"""Clipboard access for the CLI/TUI: pipe the value into the first mechanism that works.

Preference order: wl-copy (Wayland), xclip and xsel (X11), then OSC 52 - the terminal
escape sequence that sets the clipboard of whatever terminal emulator is displaying
the session, so it works over SSH on headless servers too. A secret only ever crosses
a stdin pipe or the tty escape - never a command line, a log line, or a file."""

from __future__ import annotations

import base64
import shutil
import subprocess


class ClipboardError(Exception):
    """No clipboard mechanism could be used."""


# (tool, extra argv) in preference order; all read the value from stdin.
_CANDIDATES = [
    ("wl-copy", []),
    ("xclip", ["-selection", "clipboard"]),
    ("xsel", ["--clipboard", "--input"]),
]

# OSC 52 targets the terminal itself (works over SSH); it must not go to stdout, which
# may be a pipe in scripting use - write it to the controlling terminal instead.
_TTY_PATH = "/dev/tty"


def _osc52_copy(value: str, tty_path: str | None = None) -> str:
    """Set the clipboard via the OSC 52 escape sequence (\x1b]52;c;<base64>BEL).

    Returns "osc52". Note the write succeeds even when the terminal ignores the
    sequence (support varies); there is no feedback channel to detect that."""
    path = tty_path if tty_path is not None else _TTY_PATH   # read at call time (tests patch it)
    payload = base64.b64encode(value.encode("utf-8")).decode("ascii")
    try:
        with open(path, "w") as tty:
            tty.write(f"\x1b]52;c;{payload}\x07")
            tty.flush()
    except OSError as e:
        raise ClipboardError(f"OSC 52 unavailable (cannot open {path}: {e})") from e
    return "osc52"


def copy_to_clipboard(value: str) -> str:
    """Copy `value` to the system clipboard. Returns the mechanism that accepted it
    ("wl-copy", "xclip", "xsel", or "osc52").

    A tool that is installed but unusable (e.g. wl-copy outside a Wayland session)
    counts as tried-and-failed: the next candidate is attempted; when no tool works,
    OSC 52 is sent to the terminal; only if that too is impossible is ClipboardError
    raised, naming everything that was tried."""
    tried = []
    for tool, extra_args in _CANDIDATES:
        if shutil.which(tool) is None:
            continue
        tried.append(tool)
        try:
            subprocess.run([tool, *extra_args], input=value.encode("utf-8"),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=10)
            return tool
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
    # No GUI clipboard tool available or usable (headless box, SSH session): ask the
    # terminal emulator itself via OSC 52.
    try:
        return _osc52_copy(value)
    except ClipboardError as e:
        raise ClipboardError(
            "could not copy - no working clipboard tool (tried: %s) and OSC 52 failed "
            "(%s); install wl-clipboard/xclip, or use a terminal that supports OSC 52"
            % (", ".join(tried) or "none found", e)) from e
