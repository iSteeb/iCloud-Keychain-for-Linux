"""Tests for the implicit-`show` argv normalization and the launcher popup path."""

from types import SimpleNamespace

import pytest

from icp.cli import app


class TestNormalizeArgv:
    def test_bare_icp_is_show(self):
        assert app._normalize_argv([]) == ["show"]

    def test_query_becomes_show_query(self):
        assert app._normalize_argv(["github"]) == ["show", "github"]
        assert app._normalize_argv(["github", "--copy-pw"]) == ["show", "github", "--copy-pw"]

    def test_explicit_commands_untouched(self):
        assert app._normalize_argv(["show", "x"]) == ["show", "x"]
        assert app._normalize_argv(["login", "-u", "a@b.c"]) == ["login", "-u", "a@b.c"]
        assert app._normalize_argv(["sync"]) == ["sync"]
        assert app._normalize_argv(["logout", "--wipe-device"]) == ["logout", "--wipe-device"]

    def test_global_flag_with_command_untouched(self):
        argv = ["--anisette", "http://x:6969", "sync"]
        assert app._normalize_argv(argv) == argv

    def test_show_flags_without_the_word_show(self):
        assert app._normalize_argv(["-s", "github"]) == ["show", "-s", "github"]
        assert app._normalize_argv(["--get-otp"]) == ["show", "--get-otp"]


class TestLauncherPopup:
    def test_window_command_prefers_terminal_env(self, monkeypatch):
        monkeypatch.setenv("TERMINAL", "kitty")
        monkeypatch.setattr(app.shutil, "which", lambda n: f"/usr/bin/{n}")
        cmd = app._tui_window_command()
        assert cmd[0] == "/usr/bin/kitty"          # $TERMINAL wins over PATH order
        assert "--class=kitty.icp" in cmd and "--title=icp" in cmd
        assert "-e" not in cmd                       # kitty runs the command bare
        assert cmd[-2:] == ["/usr/bin/icp", "show"]

    def test_window_command_ghostty_keeps_dash_e(self, monkeypatch):
        monkeypatch.delenv("TERMINAL", raising=False)
        monkeypatch.setattr(app.shutil, "which",
                            lambda n: "/usr/bin/ghostty" if n == "ghostty" else None)
        cmd = app._tui_window_command()
        assert cmd[0] == "/usr/bin/ghostty"         # PATH fallback order: ghostty first
        assert "--class=ghostty.icp" in cmd and "-e" in cmd

    def test_window_command_unknown_terminal_bare(self, monkeypatch):
        monkeypatch.setenv("TERMINAL", "alacritty -T icp")
        monkeypatch.setattr(app.shutil, "which",
                            lambda n: {"alacritty": "/usr/bin/alacritty", "icp": "/usr/bin/icp"}.get(n))
        cmd = app._tui_window_command()
        # unknown terminal: extra TERMINAL args kept, no class/title flags assumed
        assert cmd == ["/usr/bin/alacritty", "-T", "icp", "/usr/bin/icp", "show"]

    def test_window_command_none_when_no_terminal(self, monkeypatch):
        monkeypatch.delenv("TERMINAL", raising=False)
        monkeypatch.setattr(app.shutil, "which", lambda n: None)
        assert app._tui_window_command() is None

    def test_show_without_tty_spawns_window(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
        monkeypatch.setattr("sys.stdout", SimpleNamespace(isatty=lambda: False))
        monkeypatch.setattr(app, "_spawn_tui_window", lambda: 7)
        monkeypatch.setattr(app, "load_vault_tui", None, raising=False)
        from icp.vault.store import CredentialStore
        monkeypatch.setattr("icp.vault.store.load_vault", lambda: CredentialStore([]))
        args = SimpleNamespace(query=None, plain=False, show_passwords=False,
                               copy_pw=False, copy_otp=False, copy_username=False,
                               get_username=False, get_pw=False, get_otp=False)
        assert app.cmd_show(args) == 7   # returned the spawned window's code

    def test_show_with_query_never_spawns(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
        monkeypatch.setattr("sys.stdout", SimpleNamespace(isatty=lambda: False))
        called = []
        monkeypatch.setattr(app, "_spawn_tui_window", lambda: called.append(1))
        from icp.vault.store import CredentialStore
        monkeypatch.setattr("icp.vault.store.load_vault", lambda: CredentialStore([]))
        args = SimpleNamespace(query="github", plain=False, show_passwords=False,
                               copy_pw=False, copy_otp=False, copy_username=False,
                               get_username=False, get_pw=False, get_otp=False)
        app.cmd_show(args)
        assert called == []


class TestMainArgv:
    def test_main_none_uses_sys_argv(self, monkeypatch):
        """Regression: console-script main() (argv=None) once collapsed every
        invocation to bare `show`, so `icp x --get-otp` opened the TUI/popup."""
        captured = {}
        monkeypatch.setattr(app, "cmd_show",
                            lambda a: captured.update(vars(a)) or 0)
        monkeypatch.setattr("sys.argv", ["icp", "show", "github", "--get-otp"])
        assert app.main() == 0
        assert captured["query"] == "github" and captured["get_otp"] is True

    def test_sort_otp_first(self):
        from icp.vault.host import Credential, CredentialStore
        store = CredentialStore([
            Credential(domain="a.com", username="x", password="p"),
            Credential(domain="b.com", username="y", password="p",
                       totp="otpauth://totp/B:y?secret=JBSWY3DPEHPK3PXP"),
            Credential(domain="c.com", username="z", password="p"),
        ])
        order = [c.domain for c in app._sort_credentials(list(store.all()))]
        assert order == ["b.com", "a.com", "c.com"]   # OTP entry first, rest by title
