"""Command-line interface.

Interactive: the Apple ID password and 2FA code are read from the terminal and never
stored. Only the resulting tokens are persisted, encrypted.

Commands: login, show, sync, logout. `show` also folds in Hide My Email aliases.
"""
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

from . import ui
from .clipboard import ClipboardError, copy_to_clipboard
from .. import diag
from ..auth import grandslam as auth, icloud, session
from ..auth.anisette import Anisette, AnisetteError
from ..auth.device import Device
from ..auth.gsa import GSAClient, GSAError
from ..auth.session import SessionError
from ..totp import generate as totp_generate

ICLOUD_AUTH_TOKEN = "com.apple.gs.icloud.auth"


def _utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, timezone.utc)


def _twofa_prompt(kind: str) -> str:
    where = "your trusted Apple devices" if kind == "trusted" else "SMS"
    ui.step(f"A 2FA code was sent to {where}.")
    return ui.ask("6-digit code: ")


def _mint_pet(device, anisette, username: str, password: str) -> str:
    """Mint a fresh GSA PET (password-equivalent token) for escrowproxy Basic auth. Silent on an
    already-trusted device (no 2FA re-prompt). Kept fresh per phase because the PET is short-lived."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, _twofa_prompt)
    _, pet, _ = auth.extract_pet(spd)
    return pet


def _describe_bottle(b: dict) -> str:
    """Device name + serial for an escrow bottle.
    Prefers the descriptive marketing name over the bare class."""
    meta = b.get("meta") or {}
    cm = meta.get("ClientMetadata") or {}
    name = (cm.get("device_model") or cm.get("model") or cm.get("ProductType")
            or cm.get("device_name") or cm.get("deviceName"))
    return f"{name} ({meta.get('serial')})"


def _select_bottle(bottles: list[dict]) -> dict | None:
    """Let the user pick which device's escrow bottle to recover. Auto-selects a lone bottle.
    Returns the chosen `{id, otbottle, meta}` dict, or None to abort."""
    if len(bottles) == 1:
        ui.step(f"Using the only escrow bottle: {_describe_bottle(bottles[0])}")
        return bottles[0]
    ui.step("Multiple escrow bottles found. Pick the device you want to use:\n")
    for i, b in enumerate(bottles, 1):
        ui.step(f"  {i})  {_describe_bottle(b)}")
    ui.step("")
    while True:
        raw = ui.ask(f"Select 1-{len(bottles)} (blank to abort): ")
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(bottles):
            return bottles[int(raw) - 1]
        ui.err("invalid selection")


def _refresh_webservices(s: dict, device, anisette, log=None, debug=False) -> int | None:
    """Fetch account settings and cache the webservices URL map + cloudKitToken. Returns the
    endpoint count, or None on failure."""
    status, data = icloud.fetch_account_settings(s, device, anisette)
    if debug and log is not None:
        diag.dump(log, "account-settings response", data)
    if status == 401 or data.get("ErrorID") == "UNAUTHORIZED":
        raise icloud.ICloudError(
            f"iCloud credentials expired ({data.get('description') or 'unauthorized'}) - "
            "run `icp login` to re-authenticate")
    if data.get("status") not in (0, None):
        raise icloud.ICloudError(f"iCloud rejected the token: {data.get('status-message')}")
    ws = icloud.extract_webservices(data)
    if not ws:
        return None
    s["webservices"] = {k: (v.get("url") if isinstance(v, dict) else v) for k, v in ws.items()}
    tokens = data.get("tokens") or {}
    if tokens.get("cloudKitToken"):
        s.setdefault("mme", {}).setdefault("tokens", {}).update(tokens)
    return len(ws)


def _mint_tokens(record: dict, username: str, password: str, device, anisette,
                 *, twofa=_twofa_prompt, log=None, debug=False) -> None:
    """SRP login with the password, then exchange the fresh 5-min PET for a new ~7-day
    mmeAuthToken; update `record`'s token fields in place. Preserves any already-cached
    cloudKitUserId (so a re-auth need not re-run ckAppInit). Raises on failure."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa)
    dsid, pet, pet_expiry = auth.extract_pet(spd)
    if debug and log is not None:
        diag.dump(log, "GSA init response", gsa.last_init_response)
        diag.dump(log, "GSA complete response", gsa.last_complete_response)
        diag.dump(log, "Full spd", spd)
        diag.dump_token_dict(log, spd)

    app_tokens = spd.get("t") or {}
    record.update({
        "username": username,
        "dsid": dsid,
        "dsid_numeric": spd.get("DsPrsId"),  # mobileme auth uses the numeric dsid
        "pet": pet,
        "pet_expiry": pet_expiry,
        "logged_in_at": int(time.time()),
        "gsidms": spd.get("GsIdmsToken"),
        "app_tokens": {
            name: {"token": e.get("token"), "expiry": e.get("expiry"),
                   "duration": e.get("duration")}
            for name, e in app_tokens.items() if isinstance(e, dict)
        },
    })

    mme_dsid, mme_token, service_data, raw = icloud.login_mobileme(
        username, pet, dsid, device.local_user_uuid, device, anisette)
    if debug and log is not None:
        diag.dump(log, "loginDelegates response", raw if isinstance(raw, dict) else {})
    mme = record.setdefault("mme", {})
    ck_uid = mme.get("cloudKitUserId")   # keep the per-container id resolved by an earlier ckAppInit
    mme.update({
        "dsid": mme_dsid,
        "mmeAuthToken": mme_token,
        "tokens": service_data.get("tokens") or {},
        "minted_at": int(time.time()),
    })
    if ck_uid:
        mme["cloudKitUserId"] = ck_uid


def _noninteractive_twofa(kind: str) -> str:
    """2FA callback for the unattended sync path: never blocks on stdin."""
    raise GSAError(
        "Apple asked for a 2FA code during the automatic token refresh (the anisette machine "
        "identity likely changed) - run `icp login` once interactively to re-establish trust")


def _ensure_fresh_tokens(s: dict, device, anisette, *, interactive: bool) -> None:
    """Make the cloudKitToken fresh before a sync. Re-mint it from the mmeAuthToken; if that
    token has expired too, silently re-authenticate with the saved password (no manual login).
    Raises icloud.ICloudError / AnisetteError / GSAError if it cannot recover."""
    try:
        _refresh_webservices(s, device, anisette)
        return
    except icloud.ICloudError:
        # The mmeAuthToken itself expired. Recover with the stored password if we have one.
        password = s.get("password")
        username = s.get("username")
        if not password or not username:
            raise
    ui.step("iCloud token expired - re-authenticating with the saved password...")
    twofa = _twofa_prompt if interactive else _noninteractive_twofa
    _mint_tokens(s, username, password, device, anisette, twofa=twofa)
    _refresh_webservices(s, device, anisette)   # retry with the fresh mmeAuthToken


def cmd_login(args) -> int:
    """Sign in to Apple, cache the persistent tokens, then join the keychain and sync.

    A single onboarding flow: the password entered here is reused for the join's escrow
    re-authentication, so it is never prompted twice. The irreversible escrow recovery is
    still gated by an explicit y/N prompt - answer No to stop after sign-in with tokens saved.
    """
    debug_path = diag.start() if args.debug else None
    log = logging.getLogger("icp.login")

    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    try:
        anisette.headers()  # fail fast if the anisette server is down
    except AnisetteError as e:
        ui.err(str(e))
        return 2

    # Preserve the Octagon peer identity (and cached cloudKitUserId) across re-logins: keychain
    # trust membership is permanent and tied to that keypair, not to the short-lived auth tokens.
    prior = session.load() or {}

    saved_user = prior.get("username")
    username = args.username or ui.ask(
        f"Apple ID [{saved_user}]: " if saved_user else "Apple ID: ") or saved_user
    if not username:
        ui.err("no Apple ID given")
        return 2
    password = ui.secret("Password: ")

    record: dict = {}
    if prior.get("octagon", {}).get("peer_id"):
        record["octagon"] = prior["octagon"]
    if prior.get("mme", {}).get("cloudKitUserId"):
        record.setdefault("mme", {})["cloudKitUserId"] = prior["mme"]["cloudKitUserId"]
    if args.save_password:
        record["password"] = password   # in the keyring-encrypted session; enables silent refresh

    # SRP login + mint the mmeAuthToken (the one hop that needs the password).
    mme_ok = False
    try:
        _mint_tokens(record, username, password, device, anisette, log=log, debug=args.debug)
        mme_ok = True
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1
    except icloud.ICloudError as e:
        log.warning("loginDelegates failed: %s", e)
        ui.warn(f"could not mint the persistent mmeAuthToken: {e}")

    # With the fresh mmeAuthToken, fetch the iCloud service URLs (needed for join/sync).
    n_ws = None
    if mme_ok:
        try:
            n_ws = _refresh_webservices(record, device, anisette, log, args.debug)
        except (icloud.ICloudError, AnisetteError) as e:
            ui.warn(f"could not fetch iCloud service URLs: {e}")

    session.save(record)
    ui.out(f"Signed in as {username}.")

    if not (mme_ok and n_ws):
        ui.err("sign-in succeeded but iCloud service URLs are unavailable - cannot join the keychain")
        if debug_path:
            ui.out(f"Debug transcript (redacted): {debug_path}")
        return 1

    rc = _join_and_sync(record, device, anisette, username, password)
    # Fetch Hide My Email here (interactive): its web session is a separate auth surface that may
    # need its own 2FA, so handle that during login rather than surprising a later `icp sync`.
    n_aliases = len(_fetch_aliases_best_effort(interactive=True))
    if n_aliases:
        ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
    if debug_path:
        ui.out(f"Debug transcript (redacted): {debug_path}")
    return rc


def _status_fields() -> list[tuple[str, object]]:
    """The full account/session state as (label, value) rows - shown by `show`."""
    s = session.load()
    if not s:
        return [("Status", "not signed in - run: icp login")]
    rows = [("Apple ID", s.get("username")), ("DSID", s.get("dsid")),
            ("Signed in", _utc(s.get("logged_in_at", 0) * 1000).isoformat())]
    now = datetime.now(timezone.utc)
    app_tokens = s.get("app_tokens") or {}
    icloud_auth = app_tokens.get(ICLOUD_AUTH_TOKEN)
    if icloud_auth and icloud_auth.get("expiry"):
        exp = _utc(icloud_auth["expiry"])
        state = "valid" if exp > now else "EXPIRED"
        rows.append(("iCloud token", f"{state}, until {exp.date()} (~{(exp - now).days} days)"))
    rows.append(("App tokens", len(app_tokens)))
    mme = s.get("mme") or {}
    rows.append(("mmeAuthToken",
                 f"present (dsid {mme.get('dsid')}) - persistent" if mme.get("mmeAuthToken")
                 else "none - run login"))
    ws = s.get("webservices") or {}
    rows.append(("Service URLs", f"{len(ws)} cached" if ws else "none - run login"))
    octagon = s.get("octagon") or {}
    rows.append(("Octagon peer", octagon.get("peer_id") or "not yet joined"))
    rows.append(("Device ID", Device.load_or_create().device_id))
    return rows


def _status_summary() -> str:
    """One-line account state for the TUI header."""
    s = session.load()
    if not s:
        return "not signed in - run: icp login"
    from ..octagon import client as octagon
    joined = "joined" if octagon.is_joined(s) else "not joined"
    token = ""
    icloud_auth = (s.get("app_tokens") or {}).get(ICLOUD_AUTH_TOKEN) or {}
    if icloud_auth.get("expiry"):
        exp = _utc(icloud_auth["expiry"])
        valid = "valid" if exp > datetime.now(timezone.utc) else "EXPIRED"
        token = f"  |  token {valid} {exp.date()}"
    return f"{s.get('username')}  |  dsid {s.get('dsid')}  |  {joined}{token}"


def _match(c, q: str) -> bool:
    """Case-insensitive substring match (q already lowercased) across domain/title/username."""
    return (not q or q in c.domain.lower() or q in c.title.lower()
            or q in c.username.lower())


def _alias_match(a, q: str) -> bool:
    """Same idea as `_match`, over a Hide My Email alias's searchable fields."""
    return (not q or q in a.address.lower() or q in a.label.lower()
            or q in a.note.lower() or q in a.forward_to.lower())


def _fetch_aliases_best_effort(interactive: bool) -> list:
    """Hide My Email aliases for `show`, fetched via the web session (auth/webauth.py). Never
    fails `show`: no saved password skips silently, any other error warns and falls back to the
    cached aliases. On success, refreshes that cache (hme/store.py) for the native host."""
    from ..auth import webauth
    from ..hme.client import HmeClient, HmeError
    from ..hme.store import load_aliases, save_aliases

    s = session.load()
    if not s or not s.get("password"):
        return []
    try:
        sess, account_data = _ensure_web_session(s, interactive=interactive)
        session.save(s)
        base = webauth.extract_webservices(account_data).get("premiummailsettings")
        if not base:
            return load_aliases()
        aliases = HmeClient(base, sess.http).list()
        save_aliases(aliases)
        return aliases
    except (webauth.WebAuthError, HmeError) as e:
        ui.warn(f"Hide My Email unavailable: {e}")
        return load_aliases()


def cmd_show(args) -> int:
    """Browse/search stored credentials, Hide My Email aliases, and account status.

    With a TTY and no arguments, opens a full-screen browser over the vault (offline); a query,
    --plain, --show-passwords, or non-terminal stdout falls back to plain text (which also folds
    in aliases). Status to stderr, rows to stdout so the list stays pipe/grep-friendly.
    """
    use_tui = (not args.plain and not args.query and not args.show_passwords
               and not _has_credential_flags(args))
    if use_tui and not (sys.stdin.isatty() and sys.stdout.isatty()):
        # Launched without a terminal (rofi run, a keybind, a .desktop launcher):
        # open the browser in a floating terminal popup instead of dumping to
        # a null stdout. Inside the popup stdio is a tty, so the TUI runs there.
        # The vault is deliberately NOT loaded in this launcher process: the
        # popup runs its own `icp show`, so loading it here would pay the
        # Secret-Service round-trip + decrypt twice per popup - and a vault
        # error would die invisibly on a null stderr instead of showing in
        # the popup (which surfaces it on its own tty).
        return _spawn_tui_window()

    from ..vault.store import load_vault

    try:
        store = load_vault()
    except Exception as e:  # noqa: BLE001 - surface keyring/decrypt failures cleanly
        ui.err(f"could not open the vault: {e}")
        return 1

    use_tui = use_tui and sys.stdin.isatty() and sys.stdout.isatty()
    if use_tui:
        try:
            return _run_tui(store)
        except Exception as e:  # noqa: BLE001 - curses missing/unusable -> plain fallback
            ui.warn(f"TUI unavailable ({e}); showing plain output")
    return _show_plain(store, args)


def _pick_credential(creds, interactive: bool):
    """Choose one credential for the copy flags: auto-select a lone match; for several,
    prompt with a numbered list when interactive (blank or invalid aborts); non-interactive
    callers (pipes/scripts) get None so they must disambiguate via the search term."""
    if len(creds) == 1:
        return creds[0]
    if not interactive:
        return None
    ui.step("Multiple matches - pick one:\n")
    for i, c in enumerate(creds, 1):
        ui.step(f"  {i})  {c.domain}  {c.username}")
    ui.step("")
    raw = ui.ask("Copy which entry (blank to abort): ")
    if raw.isdigit() and 1 <= int(raw) <= len(creds):
        return creds[int(raw) - 1]
    return None


def _credential_flags(store, args) -> int:
    """--copy-* / --get-*: pick the one matching login, then act on it. The copy flags
    copy to the clipboard (never printing a password to the terminal; the OTP
    confirmation shows the code itself - it is short-lived and plain listings already
    display it). The get flags print ONLY the raw value on stdout, for scripting."""
    query = (args.query or "").strip()
    if not query:
        ui.err("copy/get flags need a search term: icp show <term> --copy-pw")
        return 1
    creds = [c for c in store.all() if _match(c, query.lower())]
    if not creds:
        ui.err(f"no credentials match {args.query!r}")
        return 1
    _sort_credentials(creds)
    cred = _pick_credential(creds, sys.stdin.isatty())
    if cred is None:
        ui.err("no entry selected - aborting (use a more specific search term)")
        return 1

    rc = 0
    try:
        if args.copy_username:
            if not cred.username:
                ui.err(f"{cred.title or cred.domain}: no username stored")
                rc = 1
            else:
                copy_to_clipboard(cred.username)
                ui.out(f"username for {cred.title or cred.domain} ({cred.username}) "
                       "copied to clipboard")
        if args.copy_pw:
            if not cred.password:
                ui.err(f"{cred.title or cred.domain}: no password stored")
                rc = 1
            else:
                copy_to_clipboard(cred.password)
                ui.out(f"password for {cred.title or cred.domain} ({cred.username}) "
                       "copied to clipboard")
        code = totp_generate(cred.totp) if (args.copy_otp or args.get_otp) else None
        if args.copy_otp:
            if not code:
                ui.err(f"{cred.title or cred.domain}: no verification code set up for this login")
                rc = 1
            else:
                copy_to_clipboard(code["code"])
                left = max(0, int(code["expires"] - time.time()))
                ui.out(f"code {code['code']} for {cred.username} copied to clipboard "
                       f"({left}s valid)")
        # --get-*: raw output only - nothing else on stdout, for scripts.
        if args.get_username:
            if not cred.username:
                ui.err(f"{cred.title or cred.domain}: no username stored")
                rc = 1
            else:
                ui.out(cred.username)
        if args.get_pw:
            if not cred.password:
                ui.err(f"{cred.title or cred.domain}: no password stored")
                rc = 1
            else:
                ui.out(cred.password)
        if args.get_otp:
            if not code:
                ui.err(f"{cred.title or cred.domain}: no verification code set up for this login")
                rc = 1
            else:
                ui.out(code["code"])
    except ClipboardError as e:
        ui.err(str(e))
        return 1
    return rc


def _has_credential_flags(args) -> bool:
    return bool(args.copy_pw or args.copy_otp or args.copy_username
                or args.get_username or args.get_pw or args.get_otp)


def _show_plain(store, args) -> int:
    if _has_credential_flags(args):
        return _credential_flags(store, args)

    for label, value in _status_fields():
        ui.step(f"{label:<14}{value}")

    query = (args.query or "").strip().lower()
    creds = store.all()
    if query:
        creds = [c for c in creds if _match(c, query)]
    aliases = _fetch_aliases_best_effort(sys.stdin.isatty())
    if query:
        aliases = [a for a in aliases if _alias_match(a, query)]

    if query and not creds and not aliases:
        ui.err(f"no credentials or aliases match {args.query!r}")
        return 1
    if not creds and not aliases:
        ui.step("vault is empty - run: icp login")
        return 0

    if creds:
        _sort_credentials(creds)
        dom_w = min(max(len(c.display_name) for c in creds), 40)
        user_w = min(max(len(c.username) for c in creds), 40)
        for c in creds:
            pw = c.password if args.show_passwords else "******"
            ui.out(f"{c.display_name:<{dom_w}}  {c.username:<{user_w}}  {pw}{_totp_suffix(c)}")
        ui.step(f"{len(creds)} credential(s).")

    if aliases:
        aliases.sort(key=lambda a: a.label.lower())
        label_w = min(max(len(a.label) for a in aliases), 32)
        ui.step("")
        ui.step("Hide My Email:")
        for a in aliases:
            state = "" if a.is_active else "  (inactive)"
            ui.out(f"{a.label:<{label_w}}  {a.address}{state}")
        ui.step(f"{len(aliases)} alias(es).")
    return 0


def _totp_suffix(c) -> str:
    """The trailing `123456 (12s)` column for a credential carrying a verification code."""
    code = totp_generate(c.totp)
    if not code:
        return ""
    return f"  {code['code']} ({max(0, int(code['expires'] - time.time()))}s)"


def _printable(s: str) -> str:
    """Replace non-printable bytes with a dot so untrusted values (passwords are arbitrary binary;
    some keychain items are cert/key blobs full of \\n, \\r, ESC) can't inject terminal escape
    sequences. Normal printable Unicode is preserved."""
    return "".join(ch if ch.isprintable() else "." for ch in s)


_COMMANDS = ("login", "show", "sync", "logout")


def _normalize_argv(argv):
    """`icp` == `icp show`, and `icp <query>` == `icp show <query>`: insert the
    implicit `show` subcommand unless the first token already is a command (or a
    global flag followed by one, e.g. `icp --anisette URL sync`)."""
    if not argv:
        return ["show"]
    if argv[0] in _COMMANDS:
        return list(argv)
    if argv[0].startswith("-") and any(a in _COMMANDS for a in argv):
        return list(argv)
    return ["show", *argv]


def _tui_window_command():
    """The command that opens the password browser in a floating terminal popup -
    the same Ghostty + --class pattern as the other local popups (addies, psoco);
    a Hyprland windowrule floats ghostty.icp centered."""
    ghostty = shutil.which("ghostty") or "/snap/bin/ghostty"
    icp = shutil.which("icp") or sys.argv[0]
    return [ghostty, "--class=ghostty.icp", "--title=icp", "-e", icp, "show"]


def _spawn_tui_window() -> int:
    """No terminal attached (rofi/launcher/keybind): open one with the browser.
    Inside the popup stdio is a tty, so the TUI runs there and this returns when
    the user closes it."""
    try:
        return subprocess.run(_tui_window_command()).returncode
    except OSError as e:
        ui.err(f"cannot open a terminal window for the browser: {e}")
        return 1


def _sort_credentials(creds):
    """Display order: logins with a verification code first (they're the ones you
    need right now), then by title/username."""
    creds.sort(key=lambda c: (not c.totp, c.title.lower(), c.username.lower()))
    return creds


def _psoco_flow(term: str | None = None) -> bool:
    """Psono (work password store) lookup: search, pick, show and copy the password.

    Replaces the old ~/.local/bin/psoco wrapper (invoked from rofi). `term` is
    the TUI's current search query (the `?` key passes it straight through); when
    None, the user is prompted. A single match is used immediately, several
    prompt for an index. The password is printed AND copied - over ssh the copy
    lands on the local machine's clipboard via OSC 52 (copy_to_clipboard's
    fallback), and the mechanism is echoed so remote use is verifiable. Prints
    to stdout and returns True when a search actually ran (the `?` key in
    _run_tui suspends curses around this and holds the result until Enter)."""
    psoco = shutil.which("psoco-cli") or os.path.expanduser("~/.local/bin/psoco-cli")
    if not os.path.isfile(psoco):
        ui.out(f"psoco-cli not found (looked on PATH and at {psoco})")
        return False
    term = term if term else ui.ask("psono search: ")
    if not term:
        return False

    def fields(row: str) -> tuple[str, str]:
        parts = [p.strip() for p in row.split("|")]
        name = parts[1] if len(parts) > 1 else ""
        entry_id = parts[3] if len(parts) > 3 else ""
        return name, entry_id

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([psoco, *args], capture_output=True, text=True, timeout=30)

    try:
        proc = run("search", term)
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.out(f"psoco-cli failed to run: {e}")
        return True
    if proc.returncode != 0:
        ui.out(f"psoco-cli search failed ({proc.returncode}): {proc.stderr.strip()}")
        return True
    rows = [l for l in proc.stdout.splitlines()
            if "|" in l and not re.search(r"Name|---|\+", l)]
    if not rows:
        ui.out(f"No psono results for '{term}'.")
        return True

    if len(rows) == 1:
        name, entry_id = fields(rows[0])
    else:
        ui.out("Multiple results - pick one:")
        for i, row in enumerate(rows, 1):
            ui.out(f"[{i}] {fields(row)[0]}")
        pick = ui.ask(f"Number (1-{len(rows)}): ")
        if not pick.isdigit() or not 1 <= int(pick) <= len(rows):
            ui.out("Invalid selection.")
            return True
        name, entry_id = fields(rows[int(pick) - 1])
    if not entry_id:
        ui.out(f"Could not parse an entry id for '{name}' - psoco-cli table format changed?")
        return True

    try:
        pwd = run("pwd", entry_id)
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.out(f"psoco-cli failed to run: {e}")
        return True
    if pwd.returncode != 0:
        ui.out(f"psoco-cli pwd failed ({pwd.returncode}): {pwd.stderr.strip()}")
        return True
    password = pwd.stdout.strip()
    if not password:
        ui.out(f"No password returned for '{name}'.")
        return True
    try:
        mechanism = copy_to_clipboard(password)
        ui.out(f"psono password for {name}: {password}")
        ui.out(f"(copied via {mechanism})")
    except ClipboardError as e:
        ui.out(f"psono password for {name}: {password}")
        ui.err(f"copy failed: {e}")
    return True


def _run_tui(store) -> int:
    """Full-screen password browser: one bordered panel (lazygit-style), cyan
    accents, reverse-video selection with per-column attributes, a status line
    for copy feedback, and a key-hint bar. Type to filter, up/down to move,
    Enter to reveal a password, Ctrl+P to copy it, Ctrl+U to copy the username,
    Ctrl+O to copy the current verification code and quit (the last step of a
    login workflow). Esc to clear the query (or quit when it is empty); '/'
    does the same clearing without the quit ('?' opens the psono lookup)."""
    import curses

    creds = _sort_credentials(list(store.all()))

    def draw(stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(1000)  # redraw every second so the code countdowns tick

        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)    # accent: title, borders
            curses.init_pair(2, curses.COLOR_YELLOW, -1)  # verification codes
            curses.init_pair(3, curses.COLOR_GREEN, -1)   # copy confirmations
        ACCENT = curses.color_pair(1) | curses.A_BOLD
        BORDER = curses.color_pair(1)
        CODE = curses.color_pair(2) | curses.A_BOLD
        OK = curses.color_pair(3) | curses.A_BOLD

        def put(y, x, s, attr=curses.A_NORMAL, width=None):
            # addnstr raises on the bottom-right cell and screen edges; a draw
            # glitch must never tear the whole TUI down.
            try:
                stdscr.addnstr(y, x, s,
                               width if width is not None else max(0, w - 1 - x), attr)
            except curses.error:
                pass

        query, sel, offset, revealed = "", 0, 0, set()
        flash = ["", 0.0, curses.A_NORMAL]   # message, visible-until, attribute

        def flash_copy(kind: str) -> bool:
            """Copy the selected entry's password ("password"), username ("username")
            or current verification code ("code") and show a confirmation on the
            status line. Returns True when something was actually copied."""
            if not shown:
                return False
            c = shown[sel]
            copied = False
            try:
                if kind == "password":
                    if not c.password:
                        flash[0] = "no password stored"
                    else:
                        copy_to_clipboard(c.password)
                        flash[0] = f"password for {c.title or c.domain} copied to clipboard"
                        copied = True
                elif kind == "username":
                    if not c.username:
                        flash[0] = "no username stored"
                    else:
                        copy_to_clipboard(c.username)
                        flash[0] = f"username for {c.title or c.domain} ({c.username}) copied to clipboard"
                        copied = True
                else:
                    code = totp_generate(c.totp)
                    if not code:
                        flash[0] = "no verification code for this login"
                    else:
                        copy_to_clipboard(code["code"])
                        left = max(0, int(code["expires"] - time.time()))
                        flash[0] = f"code {code['code']} copied ({left}s left)"
                        copied = True
                flash[2] = OK
            except ClipboardError as e:
                flash[0] = str(e)
                flash[2] = curses.A_BOLD
            flash[1] = time.time() + 2.5
            return copied

        while True:
            shown = [c for c in creds if _match(c, query.lower())]
            sel = max(0, min(sel, len(shown) - 1))
            h, w = stdscr.getmaxyx()

            # -- layout: name, username, password, code columns; shrink to fit --
            footer = " type to search   ↑↓ move   ⏎ reveal   ^P copy pw   ^U copy user   ^O code+quit   / clear   ? psono "
            name_w = min(max((len(c.display_name) for c in creds), default=10), 38)
            user_w = min(max((len(c.username) for c in creds), default=4), 28)
            over = (2 + name_w + 2 + user_w + 2 + 8 + 2 + 13) - (w - 2)
            if over > 0:
                name_w = max(12, name_w - over)
            user_x = 2 + name_w + 2
            pw_x = user_x + user_w + 2
            otp_x = pw_x + 8 + 2
            rows_h = max(1, h - 6)   # entry rows sit between the two ├┤ joins
            if sel < offset:
                offset = sel
            elif sel >= offset + rows_h:
                offset = sel - rows_h + 1

            # -- panel frame ---------------------------------------------
            stdscr.erase()
            put(0, 0, "┌" + "─" * (w - 2) + "┐", BORDER)
            put(h - 1, 0, "└" + "─" * (w - 2) + "┘", BORDER)
            put(2, 0, "├" + "─" * (w - 2) + "┤", BORDER)
            put(h - 4, 0, "├" + "─" * (w - 2) + "┤", BORDER)
            for y in range(1, h - 1):
                put(y, 0, "│", BORDER)
                put(y, w - 1, "│", BORDER)
            title = f" iCloud Passwords · {len(creds)} logins"
            if query:
                title += f" · {len(shown)} match{'es' if len(shown) != 1 else ''}"
            put(0, 4, title + " ", ACCENT)

            # -- search line ---------------------------------------------
            put(1, 2, "search:", BORDER)
            put(1, 10, query if query else "(type to filter)",
                curses.A_BOLD if query else curses.A_DIM)

            # -- entries --------------------------------------------------
            if not shown:
                put(3, 4, "(no matching credentials)", curses.A_DIM)
            for idx, c in enumerate(shown[offset:offset + rows_h]):
                i = offset + idx
                y = 3 + idx
                sel_attr = curses.A_REVERSE if i == sel else curses.A_NORMAL
                put(y, 1, " " * (w - 2), sel_attr)      # full-width selection strip
                put(y, 2, _printable(c.display_name)[:name_w].ljust(name_w),
                    sel_attr | (curses.A_BOLD if i == sel else curses.A_NORMAL))
                put(y, user_x, _printable(c.username)[:user_w].ljust(user_w),
                    sel_attr | curses.A_DIM)
                pw = c.password if id(c) in revealed else "••••••"
                pw_attr = curses.A_BOLD if id(c) in revealed else curses.A_DIM
                put(y, pw_x, _printable(pw)[:8], sel_attr | pw_attr)
                code = totp_generate(c.totp)
                if code:
                    left = max(0, int(code["expires"] - time.time()))
                    put(y, otp_x, f"{code['code']} ({left}s)", sel_attr | CODE)

            # -- status line + key hints ----------------------------------
            if flash[0] and time.time() < flash[1]:
                put(h - 3, 2, flash[0][:w - 4], flash[2])
            else:
                flash[0] = ""
                put(h - 3, 2, f"{len(creds)} logins · / clears the search", curses.A_DIM)
            put(h - 2, 2, footer, curses.A_DIM)
            stdscr.refresh()

            ch = stdscr.getch()
            if ch == -1:  # timeout: just redraw
                continue
            if ch == 27:  # Esc: clear the query, or quit when it is already empty.
                # (In the kitty popup Esc never arrives here - the terminal maps
                # it to close-window; use '/' to clear instead.)
                if query:
                    query, sel, offset = "", 0, 0
                else:
                    return 0
            elif ch == ord("/"):  # '/': clear the search query
                query, sel, offset = "", 0, 0
            elif ch == ord("?"):  # '?': psono lookup of the CURRENT query, TUI suspended
                curses.endwin()
                try:
                    if _psoco_flow(query or None):
                        ui.ask("\n[press Enter to return]")
                finally:
                    stdscr.keypad(True)
                    stdscr.timeout(1000)
                    curses.curs_set(0)
                    stdscr.refresh()
                continue
            elif ch == curses.KEY_UP:
                sel = max(0, sel - 1)
            elif ch == curses.KEY_DOWN:
                sel = min(len(shown) - 1, sel + 1) if shown else 0
            elif ch in (curses.KEY_ENTER, 10, 13):
                if shown:
                    revealed ^= {id(shown[sel])}
            elif ch == 16:  # Ctrl+P: copy the selected entry's password
                flash_copy("password")
            elif ch == 21:  # Ctrl+U: copy the selected entry's username
                flash_copy("username")
            elif ch == 15:  # Ctrl+O: copy the current verification code, then quit -
                # fetching a code is the last step of a login workflow, so the
                # browser closes itself once it is safely on the clipboard.
                if flash_copy("code"):
                    return 0
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                query, sel, offset = query[:-1], 0, 0
            elif 32 <= ch < 127:
                query, sel, offset = query + chr(ch), 0, 0

    try:
        curses.wrapper(draw)
    except KeyboardInterrupt:
        pass
    return 0


def _join_and_sync(s: dict, device, anisette, username: str, password: str) -> int:
    """Join the iCloud Keychain Octagon trust via escrow recovery, then sync.

    Escrow recovery is IRREVERSIBLE - escrowproxy destroys the record after 10 wrong
    passcodes. Gated: safe discovery first; an attempt is only spent after a y/N proceed
    prompt that defaults to No. The given password (entered during sign-in) is reused for
    the escrow re-authentication, so it is never prompted twice.
    """
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    # Already a trusted keychain peer (e.g. a token-refresh re-login)? Octagon membership is
    # permanent, so skip the irreversible escrow join and just sync. Gate on is_joined, not a bare
    # peer_id: aborting bottle selection persists peer_id without ever joining.
    if octagon.is_joined(s):
        ui.step("Already joined; syncing...")
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)
            n = client.sync_and_decrypt()
        except (OctagonError, CloudKitError) as e:
            ui.err(f"sync failed: {e}")
            return 1
        ui.out(f"Synced {n} credential(s) into the vault.")
        return 0

    escrow_host = (s.get("webservices") or {}).get("keychainsync")
    if not escrow_host:
        ui.err("no escrow URL cached - cannot join the keychain")
        return 1

    octagon.ensure_peer_identity(s, device)  # generate the peer identity once
    session.save(s)

    try:
        client = octagon.OctagonClient(s, device, anisette)
        session.save(s)  # persist the cloudKitUserId resolved by ckAppInit
        ui.step("Discovering escrow bottles...")
        # A PET here only lists device metadata via GETRECORDS (non-destructive, spends no
        # attempt) so the user can see WHICH device each bottle belongs to before choosing.
        list_pet = _mint_pet(device, anisette, username, password)
        bottles = client.list_recoverable_bottles(escrow_host, username, list_pet, warn=ui.warn)
    except (OctagonError, CloudKitError, GSAError, AnisetteError) as e:
        ui.err(str(e))
        return 1

    if not bottles:
        ui.err("no recoverable escrow bottle - cannot join via this path")
        return 1

    chosen = _select_bottle(bottles)
    if chosen is None:
        ui.out("Aborted before selecting a bottle - no escrow attempt spent. You're signed in "
               "but NOT joined; run `icp login` again to retry the keychain join.")
        return 0

    ui.out(f"Joining iCloud Keychain will use the passcode of: {_describe_bottle(chosen)}")
    ui.out("This is IRREVERSIBLE - a wrong passcode spends 1 of ~10 attempts, and the 10th "
           "failed attempt destroys the escrow record permanently.")
    if not ui.confirm_yn("Proceed? (y/N) "):
        ui.out("Aborted - no escrow attempt spent. You're signed in but NOT joined; "
               "run `icp login` again to retry the keychain join.")
        return 0

    # Mint a fresh PET right before the irreversible recovery so it can't expire during the
    # selection/confirmation delay above.
    try:
        pet = _mint_pet(device, anisette, username, password)
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1

    passcode = ui.secret("Device passcode / iCloud Security Code for that device: ").encode()
    if not passcode:
        ui.err("empty passcode - aborting before spending an attempt")
        return 1
    try:
        client.join_via_escrow(escrow_host, username, pet, passcode, chosen,
                               confirm_irreversible=True)
    except Exception as e:  # noqa: BLE001 - surface any failure, never crash mid-join
        ui.err(f"join failed: {e}")
        return 1
    session.save(s)  # persist the peer identity + the recovered sponsor key for later syncs

    try:
        n = client.sync_and_decrypt()
    except CloudKitError as e:
        ui.err(f"joined, but sync failed: {e}")
        return 1
    ui.out(f"Joined the keychain. Synced {n} credential(s).")
    return 0


def cmd_sync(args) -> int:
    """Fetch the keychain zones and decrypt them into the vault (requires a prior join).

    Guarded by a non-blocking file lock so the periodic background trigger and a manual run
    can never overlap (a second sync exits immediately rather than racing on the vault)."""
    import fcntl
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError
    from ..paths import sync_lock_file

    lock = open(sync_lock_file(), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        ui.err("another sync is already running")
        return 0

    try:
        s = session.load()
        if not s:
            ui.err("not signed in - run: icp login")
            return 1
        if not (s.get("octagon") or {}).get("peer_id"):
            ui.err("not joined to the keychain - run: icp login")
            return 1
        device = Device.load_or_create()
        anisette = Anisette(args.anisette)
        # The cached cloudKitToken is short-lived; re-mint it from the mmeAuthToken before every
        # sync. If the mmeAuthToken has also expired, _ensure_fresh_tokens silently re-authenticates
        # with the saved password (no manual login), unless 2FA is required or no password is saved.
        try:
            _ensure_fresh_tokens(s, device, anisette, interactive=sys.stdin.isatty())
            session.save(s)  # persist any freshly re-minted tokens
        except (icloud.ICloudError, AnisetteError, GSAError) as e:
            ui.err(f"could not refresh the iCloud token: {e}")
            return 1
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)  # persist the refreshed cloudKitToken + cloudKitUserId from ckAppInit
            n = client.sync_and_decrypt()
        except (OctagonError, CloudKitError) as e:
            ui.err(f"sync failed: {e}")
            return 1
        ui.out(f"Synced {n} credential(s) into the vault.")
        # Best-effort, never interactive: refresh the Hide My Email cache only while the web
        # session's trust is still valid, otherwise keep the cache. Its 2FA is handled at login
        # (cmd_login), so sync never prompts - see _fetch_aliases_best_effort.
        n_aliases = len(_fetch_aliases_best_effort(interactive=False))
        if n_aliases:
            ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
        return 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def _ensure_web_session(s: dict, *, interactive: bool):
    """Reach a valid idmsa web session (auth/webauth.py). Reuses a saved trust token when
    possible; otherwise signs in with the saved password and prompts for 2FA once. Returns
    (WebAuthSession, account_data)."""
    from ..auth import webauth

    wa = s.setdefault("webauth", {})
    frame_tag = wa.get("frame_tag") or f"auth-{uuid.uuid4()}"
    wa["frame_tag"] = frame_tag
    sess = webauth.WebAuthSession(frame_tag, session_data=wa.get("session_data"),
                                  cookies=wa.get("cookies"))

    account_data = None
    if sess.session_data.get("session_token"):
        try:
            account_data = sess.account_login()
            if webauth.hsa_challenge_required(account_data):
                account_data = None  # saved session is stale/untrusted -> fall through to signin
        except webauth.WebAuthError:
            account_data = None

    if account_data is None:
        username, password = s.get("username"), s.get("password")
        if not username or not password:
            raise webauth.WebAuthError(
                "no saved Apple ID password for the web session - run `icp login` "
                "with --save-password")
        sess.signin(username, password, trust_token=sess.session_data.get("trust_token"))
        if sess.needs_2fa:
            if not interactive:
                raise webauth.WebAuthError(
                    "Apple asked for a 2FA code for the web session - run `icp show` "
                    "from a terminal once to establish trust")
            sess.request_push_notification()  # the 409 no longer auto-sends this on its own
            sess.submit_2fa(_twofa_prompt("trusted"))
        account_data = sess.account_login()
        if webauth.hsa_challenge_required(account_data):
            raise webauth.WebAuthError("2FA did not clear the web-session challenge")

    wa.update(sess.export())
    return sess, account_data


def cmd_logout(args) -> int:
    session.clear()
    ui.out("Session cleared. Device identity kept (use --wipe-device to remove it).")
    if args.wipe_device:
        from ..paths import device_file
        f = device_file()
        if f.exists():
            f.unlink()
        ui.out("Device identity wiped.")
    return 0


# Shared help text: the anisette server every online command needs, with the volume
# that keeps its machine identity (and thus Apple's device trust) stable across
# container recreation.
_ANISETTE_HELP = """anisette server (required by login/sync; `show` works without it):

  Apple's sign-in needs machine data only Apple software can produce; a small local
  Docker container provides it. Start once - it survives reboots:

    docker run -d --restart=always --name anisette -p 6969:6969 \\
      --volume anisette-v3_data:/home/Alcoholic/.config/anisette-v3/lib/ \\
      dadoum/anisette-v3-server:latest

  The volume persists the provisioning identity (recreating the container without it
  may make Apple re-ask for 2FA). Using a server elsewhere: pass --anisette URL or
  set ICP_ANISETTE_URL."""


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if argv is None:
        argv = sys.argv[1:]   # never let None reach _normalize_argv (it means "bare icp")
    p = argparse.ArgumentParser(
        prog="icp",
        description="iCloud Passwords for Linux - read-only iCloud Keychain access: "
                    "sign in once, sync your passwords to an encrypted local vault, "
                    "then browse/search/copy them from the command line.",
        epilog=_ANISETTE_HELP + """

commands (bare `icp` is the same as `icp show`; launched without a terminal,
  e.g. from rofi, the browser opens in a floating Ghostty popup - Hyprland rule
  `ghostty.icp`):
  icp login [-u APPLE_ID] [--save-password] [--debug]
      Sign in (Apple ID + password + 2FA once), join the keychain via escrow
      recovery, sync. The escrow step asks a device passcode and is IRREVERSIBLE
      (~10 wrong passcodes destroy the escrow record; one correct entry is safe).
        -u, --username APPLE_ID   Apple ID (prompted if omitted)
        --save-password           keep the password in the encrypted session for
                                  silent token refresh (default: not stored; re-run
                                  `icp login` every ~2 months - password only)
        --debug                   write a redacted debug transcript

  icp show [query] [flags]
      Browse/search the encrypted local vault - fully offline. No arguments in a
      terminal opens the full-screen browser; a query or any flag below gives
      plain output. Wi-Fi passwords excluded; custom names show `Name (website)`.
        -s, --show-passwords      reveal passwords in the plain listing
        --plain                   plain text instead of the full-screen browser
        --copy-pw                 copy the matched login's password to clipboard
        --copy-otp                copy its current verification code to clipboard
        --copy-username           copy its username to clipboard
        --get-pw                  print ONLY the password (for scripts)
        --get-otp                 print ONLY the current verification code
        --get-username            print ONLY the username
      copy/get flags need a query; several matches prompt you to pick one (and
      abort cleanly in pipes). Clipboard falls back to the OSC 52 terminal
      escape when no clipboard tool exists (e.g. over SSH).

  icp sync
      Refresh the snapshot from iCloud: re-downloads and decrypts everything
      (new, changed, and deleted passwords all picked up). Needs the anisette
      server; when the ~2-month token expires, re-run `icp login`.

  icp logout [--wipe-device]
      Delete the local session. --wipe-device also forgets this device's
      identity (a future login then registers a new device and re-joins via
      escrow). Keychain trust persists at Apple until you remove the device in
      Settings > Apple ID on a real device.

full-screen browser keys (icp show):
  type to filter   up/down move   Enter reveal password   Ctrl+P copy password
  Ctrl+U copy username   Ctrl+O copy code and quit   / clear query
  ? psono (work) lookup - searches psoco-cli with whatever is already typed,
    shows the password and copies it (OSC 52 when remote)
  Esc clear query, or quit when the query is empty (kitty popups map Esc to
  close-window, so '/' is the clearer that always works)

examples:
  icp show                                full-screen browser
  icp show github                         plain list of matches
  icp show github -s                      plain list, passwords visible
  icp show github --copy-pw               copy the matched password
  icp show github --copy-otp              copy the current code
  icp show github --copy-username         copy the username
  icp show github --get-pw                print only the password (scripts)
  icp sync                                refresh from iCloud
  icp login -u steven@duz.ie              sign in as a specific Apple ID
  icp logout --wipe-device                sign out and forget this device

files:
  ~/.config/icp/                          encrypted vault, session, device identity
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--anisette", metavar="URL",
                   help="anisette server URL (default: $ICP_ANISETTE_URL or http://localhost:6969)")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser(
        "login", help="sign in, join the iCloud Keychain trust, and do the first sync",
        description=("Sign in with your Apple ID (password + 2FA code, once), then join "
                     "your keychain via escrow recovery and sync. The escrow step asks "
                     "for a device passcode and is IRREVERSIBLE: about 10 wrong "
                     "passcodes across all attempts permanently destroy the escrow "
                     "record - one correct entry is safe. Requires the anisette server "
                     "(see below)."),
        epilog=_ANISETTE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    lp.add_argument("-u", "--username", metavar="APPLE_ID",
                    help="Apple ID (prompted if omitted; remembered for next time)")
    lp.add_argument("--save-password", action="store_true",
                    help="store the password in the encrypted session for silent token "
                         "refresh (off by default; without it, re-run `icp login` when "
                         "tokens expire, roughly every 2 months - password only, no 2FA)")
    lp.add_argument("--debug", action="store_true",
                    help="write a redacted debug transcript to ~/.config/icp/debug-*.log")
    lp.set_defaults(func=cmd_login)

    sp = sub.add_parser(
        "show", help="browse/search passwords, aliases, and account status",
        description=("With no arguments and a terminal: a full-screen browser - type to "
                     "filter, up/down to move, Enter to reveal a password, Ctrl+P to "
                     "copy it, Ctrl+U to copy the username, Ctrl+O to copy the "
                     "current verification code and quit (fetching a code is the "
                     "last step of a login workflow), '/' to clear the query, "
                     "'?' for a psono (work password store) lookup, Esc to "
                     "clear/quit. With a query or any copy/get flag: plain output. "
                     "Wi-Fi (AirPort) passwords are excluded; entries named in the "
                     "Passwords app show as `Name (website)`. Works fully offline. "
                     "Multiple matches with a copy/get flag prompt you to pick one "
                     "(and abort cleanly in pipes). Clipboard copy falls back to the "
                     "OSC 52 terminal escape when no clipboard tool exists (e.g. over "
                     "SSH)."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("query", nargs="?",
                    help="filter by substring of name/website/username, or alias fields")
    sp.add_argument("-s", "--show-passwords", action="store_true",
                    help="reveal passwords in plain output")
    sp.add_argument("--plain", action="store_true",
                    help="print plain text instead of the full-screen browser")
    sp.add_argument("--copy-pw", action="store_true",
                    help="copy the matched login's password to the clipboard (needs a query)")
    sp.add_argument("--copy-otp", action="store_true",
                    help="copy the matched login's current verification code (needs a query)")
    sp.add_argument("--copy-username", action="store_true",
                    help="copy the matched login's username to the clipboard (needs a query)")
    get = sp.add_mutually_exclusive_group()
    get.add_argument("--get-username", action="store_true",
                     help="print ONLY the matched login's username (for scripting)")
    get.add_argument("--get-pw", action="store_true",
                     help="print ONLY the matched login's password (for scripting)")
    get.add_argument("--get-otp", action="store_true",
                     help="print ONLY the matched login's current verification code "
                          "(for scripting; mutually exclusive with the other --get-*)")
    sp.set_defaults(func=cmd_show)

    sub.add_parser(
        "sync", help="refresh the keychain snapshot from iCloud into the local vault",
        description=("Re-download and decrypt every keychain zone, rebuilding the vault "
                     "from scratch (new, changed, and deleted passwords all picked up). "
                     "Requires the anisette server; when the ~2-month token expires, "
                     "re-run `icp login` (password only, no 2FA).")
    ).set_defaults(func=cmd_sync)

    op = sub.add_parser(
        "logout", help="clear the stored session",
        description=("Delete the local session and vault keys from ~/.config/icp. The "
                     "keychain trust lives on at Apple until you also remove the "
                     "device in Settings > Apple ID on a real device.")
    )
    op.add_argument("--wipe-device", action="store_true",
                    help="also remove the local device identity (a fresh login then "
                         "creates a new device and re-joins via escrow)")
    op.set_defaults(func=cmd_logout)

    args = p.parse_args(_normalize_argv(argv))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.err("aborted")
        return 130
    except SessionError as e:
        ui.err(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
