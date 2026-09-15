"""Tests for clipboard copying: the tool-fallback chain (icp/cli/clipboard.py) and the
--copy-pw / --copy-otp plain-mode flow + multi-match picker (icp.cli.app)."""

import subprocess
from types import SimpleNamespace

import pytest

from icp.cli import app, clipboard
from icp.vault.host import Credential, CredentialStore

_TOTP_URI = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"


def _store(*creds):
    return CredentialStore(list(creds))


def _args(query="", copy_pw=False, copy_otp=False, copy_username=False,
          get_username=False, get_pw=False, get_otp=False):
    return SimpleNamespace(query=query, copy_pw=copy_pw, copy_otp=copy_otp,
                           copy_username=copy_username, get_username=get_username,
                           get_pw=get_pw, get_otp=get_otp,
                           show_passwords=False, plain=True)


class TestClipboardChain:
    def _patch_tools(self, monkeypatch, available, runs=None):
        """available: tool -> bool installed. runs: tool -> (returncode, raise?) map."""
        monkeypatch.setattr(clipboard.shutil, "which",
                            lambda t: "/usr/bin/" + t if available.get(t) else None)
        calls = []

        def fake_run(argv, **kwargs):
            tool = argv[0]
            calls.append((argv, kwargs.get("input")))
            behavior = (runs or {}).get(tool)
            if behavior == "fail":
                raise subprocess.CalledProcessError(1, argv)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(clipboard.subprocess, "run", fake_run)
        return calls

    def test_prefers_wl_copy(self, monkeypatch):
        calls = self._patch_tools(monkeypatch, {"wl-copy": True, "xclip": True, "xsel": True})
        used = clipboard.copy_to_clipboard("secret")
        assert used == "wl-copy"
        assert calls == [(["wl-copy"], b"secret")]

    def test_falls_back_to_xclip_when_wl_copy_missing(self, monkeypatch):
        calls = self._patch_tools(monkeypatch, {"wl-copy": False, "xclip": True, "xsel": True})
        used = clipboard.copy_to_clipboard("secret")
        assert used == "xclip"
        assert calls[0][0] == ["xclip", "-selection", "clipboard"]

    def test_falls_through_when_wl_copy_fails(self, monkeypatch):
        # wl-copy installed but unusable (e.g. no Wayland session) -> xclip must take over
        calls = self._patch_tools(monkeypatch, {"wl-copy": True, "xclip": True},
                                  runs={"wl-copy": "fail"})
        used = clipboard.copy_to_clipboard("secret")
        assert used == "xclip"
        assert [c[0][0] for c in calls] == ["wl-copy", "xclip"]

    def test_raises_when_no_tool_installed(self, monkeypatch):
        self._patch_tools(monkeypatch, {})
        with pytest.raises(clipboard.ClipboardError) as e:
            clipboard.copy_to_clipboard("secret")
        assert "none found" in str(e.value)

    def test_raises_when_all_tools_fail(self, monkeypatch):
        self._patch_tools(monkeypatch, {"wl-copy": True, "xclip": True, "xsel": True},
                          runs={"wl-copy": "fail", "xclip": "fail", "xsel": "fail"})
        with pytest.raises(clipboard.ClipboardError) as e:
            clipboard.copy_to_clipboard("secret")
        assert "wl-copy" in str(e.value) and "xsel" in str(e.value)


class TestCopyFlags:
    @pytest.fixture(autouse=True)
    def _no_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))

    @pytest.fixture
    def copied(self, monkeypatch):
        calls = []
        monkeypatch.setattr(app, "copy_to_clipboard", lambda v: calls.append(v) or "wl-copy")
        return calls

    def test_copy_pw_single_match(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c", password="hunter2"))
        assert app._show_plain(store, _args(query="example", copy_pw=True)) == 0
        assert copied == ["hunter2"]

    def test_copy_pw_multiple_matches_noninteractive_aborts(self, copied):
        store = _store(
            Credential(domain="apply.deakin.edu.au", username="a@x", password="p1"),
            Credential(domain="login.deakin.edu.au", username="b@x", password="p2"),
        )
        assert app._show_plain(store, _args(query="deakin", copy_pw=True)) == 1
        assert copied == []   # nothing copied without an explicit choice

    def test_copy_pw_multiple_matches_interactive_picker(self, copied, monkeypatch):
        monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr(app.ui, "ask", lambda _: "2")
        store = _store(
            Credential(domain="apply.deakin.edu.au", username="a@x", password="p1"),
            Credential(domain="login.deakin.edu.au", username="b@x", password="p2"),
        )
        assert app._show_plain(store, _args(query="deakin", copy_pw=True)) == 0
        assert copied == ["p2"]

    def test_copy_otp(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c",
                                  password="pw", totp=_TOTP_URI))
        assert app._show_plain(store, _args(query="example", copy_otp=True)) == 0
        from icp.totp import generate
        assert copied == [generate(_TOTP_URI)["code"]]   # same instant, same 30s window

    def test_copy_otp_without_totp_fails(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c", password="pw"))
        assert app._show_plain(store, _args(query="example", copy_otp=True)) == 1
        assert copied == []

    def test_copy_flags_without_query_rejected(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c", password="pw"))
        assert app._show_plain(store, _args(copy_pw=True)) == 1
        assert copied == []

    def test_copy_flags_no_match_fails(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c", password="pw"))
        assert app._show_plain(store, _args(query="zzz", copy_pw=True)) == 1
        assert copied == []

    def test_clipboard_error_surfaced(self, copied, monkeypatch):
        def boom(_):
            raise clipboard.ClipboardError("no working clipboard tool")
        monkeypatch.setattr(app, "copy_to_clipboard", boom)
        store = _store(Credential(domain="example.com", username="a@b.c", password="pw"))
        assert app._show_plain(store, _args(query="example", copy_pw=True)) == 1

    def test_both_flags_copy_both(self, copied):
        store = _store(Credential(domain="example.com", username="a@b.c",
                                  password="pw", totp=_TOTP_URI))
        assert app._show_plain(store, _args(query="example", copy_pw=True, copy_otp=True)) == 0
        assert copied[0] == "pw" and len(copied[1]) == 6


class TestOsc52:
    def test_osc52_sequence_format(self, tmp_path):
        import base64
        tty = tmp_path / "tty"
        used = clipboard._osc52_copy("hunter2", tty_path=str(tty))
        assert used == "osc52"
        expected = b"\x1b]52;c;" + base64.b64encode(b"hunter2") + b"\x07"
        assert tty.read_bytes() == expected

    def test_falls_back_to_osc52_when_no_tools(self, monkeypatch, tmp_path):
        monkeypatch.setattr(clipboard.shutil, "which", lambda t: None)
        monkeypatch.setattr(clipboard, "_TTY_PATH", str(tmp_path / "tty"))
        used = clipboard.copy_to_clipboard("secret")
        assert used == "osc52"

    def test_falls_back_to_osc52_when_tools_fail(self, monkeypatch, tmp_path):
        monkeypatch.setattr(clipboard.shutil, "which",
                            lambda t: "/usr/bin/" + t if t == "wl-copy" else None)

        def boom(argv, **kwargs):
            raise subprocess.CalledProcessError(1, argv)
        monkeypatch.setattr(clipboard.subprocess, "run", boom)
        monkeypatch.setattr(clipboard, "_TTY_PATH", str(tmp_path / "tty"))
        assert clipboard.copy_to_clipboard("secret") == "osc52"

    def test_error_when_osc52_impossible(self, monkeypatch):
        monkeypatch.setattr(clipboard.shutil, "which", lambda t: None)
        monkeypatch.setattr(clipboard, "_TTY_PATH", "/nonexistent/no-tty")
        with pytest.raises(clipboard.ClipboardError) as e:
            clipboard.copy_to_clipboard("secret")
        assert "OSC 52" in str(e.value)


class TestGetFlags:
    @pytest.fixture(autouse=True)
    def _no_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))

    def _store(self):
        return _store(Credential(domain="example.com", username="a@b.c",
                                 password="hunter2", totp=_TOTP_URI))

    def test_get_pw_prints_only_the_password(self, capsys, monkeypatch):
        monkeypatch.setattr(app, "copy_to_clipboard", lambda v: "wl-copy")  # must NOT run
        assert app._show_plain(self._store(), _args(query="example", get_pw=True)) == 0
        assert capsys.readouterr().out == "hunter2\n"

    def test_get_username_prints_only_the_username(self, capsys):
        assert app._show_plain(self._store(), _args(query="example", get_username=True)) == 0
        assert capsys.readouterr().out == "a@b.c\n"

    def test_get_otp_prints_only_the_code(self, capsys):
        assert app._show_plain(self._store(), _args(query="example", get_otp=True)) == 0
        from icp.totp import generate
        assert capsys.readouterr().out == generate(_TOTP_URI)["code"] + "\n"

    def test_get_otp_without_totp_fails(self, capsys):
        store = _store(Credential(domain="example.com", username="a@b.c", password="pw"))
        assert app._show_plain(store, _args(query="example", get_otp=True)) == 1
        assert capsys.readouterr().out == ""

    def test_copy_username(self, monkeypatch):
        calls = []
        monkeypatch.setattr(app, "copy_to_clipboard", lambda v: calls.append(v) or "wl-copy")
        assert app._show_plain(self._store(), _args(query="example", copy_username=True)) == 0
        assert calls == ["a@b.c"]


class TestWifiFilterAndDisplay:
    def test_airport_items_excluded_from_vault(self):
        from icp.vault.host import CredentialStore
        items = [
            {"agrp": "apple", "desc": "AirPort network password", "srvr": None,
             "acct": None, "labl": "NETGEAR66-5G", "v_Data": "wifipsk"},
            {"agrp": "apple", "desc": "", "srvr": "vpn.example.com",
             "acct": "u", "labl": "vpn.example.com (u)", "v_Data": "pw"},
            {"agrp": "com.apple.cfnetwork", "desc": "Web form password",
             "srvr": "example.com", "acct": "joe", "labl": "example.com (joe)",
             "v_Data": "pw"},
        ]
        store = CredentialStore.from_items(items)
        domains = sorted(c.domain for c in store.all())
        assert domains == ["example.com", "vpn.example.com"]   # no SSID entry

    def test_display_name(self):
        def cred(domain, title):
            return Credential(domain=domain, username="u", password="p", title=title)
        # custom name + GUID domain -> "name (guid)"
        assert cred("9F382EBC-89BF-4936-8FB4-4E8DA640FB41", "IOW duzevich").display_name \
            == "IOW duzevich (9F382EBC-89BF-4936-8FB4-4E8DA640FB41)"
        # Apple's auto label "domain (user)" -> bare domain (as before)
        assert cred("example.com", "example.com (joe)").display_name == "example.com"
        # custom name + website -> "name (website)"
        assert cred("login.microsoftonline.com", "Deakin ID").display_name \
            == "Deakin ID (login.microsoftonline.com)"
        # no title -> domain
        assert cred("example.com", "").display_name == "example.com"
        # title == domain -> domain
        assert cred("example.com", "example.com").display_name == "example.com"

    def test_airport_svce_variant_excluded_too(self):
        from icp.vault.host import CredentialStore
        items = [   # svce="AirPort", SSID in acct, no desc (older storage shape)
            {"agrp": "apple", "desc": None, "srvr": None, "svce": "AirPort",
             "acct": "ANU-Secure", "labl": None, "v_Data": "wifipsk"},
        ]
        assert len(CredentialStore.from_items(items)) == 0
