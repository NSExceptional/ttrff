#!/usr/bin/env python3
"""Drive the game through winctl 0.3's CLI, using the BACKGROUND input backend.

WHY THE CLI AND NOT THE PYTHON PACKAGE: winctl was rewritten in Deno/TypeScript, and its Python
package is now kept only as a reference oracle. The input backends that matter live in the CLI.
The one that matters here is `background`, which posts window messages instead of synthesising
device input -- so it never takes focus and never moves the cursor, and the machine stays usable
while the bot plays. Panda3D reads its message pump, so a posted key held for a few frames walks
the toon exactly like a real one.

The old path used SendInput, which foregrounds the target on EVERY key event. That made the
machine unusable while the bot ran and meant anything the user clicked stole the keys mid-stride.

A key press is one invocation: `winctl key <sel> w --hold 600` posts the down, holds, and posts
the up. That is also a safety improvement -- the press and release are atomic inside winctl, so a
crash here can no longer leave a key stuck down in the game.
"""
import json
import os
import subprocess

WINCTL = os.environ.get(
    "WINCTL_EXE", os.path.join(os.path.expanduser("~"), "Developer", "winctl", "winctl.exe"))
SEL = os.environ.get("TTRFF_SEL", "class=WinGraphicsWindow0")
INPUT_MODE = os.environ.get("WINCTL_INPUT", "background")


class WinctlError(RuntimeError):
    pass


def _run(args, timeout=30, want_json=True):
    """Invoke winctl. Returns parsed JSON (or raw text). Raises WinctlError on a non-zero exit."""
    cmd = [WINCTL] + (["--json"] if want_json else []) + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise WinctlError("winctl not found at %s (set WINCTL_EXE)" % WINCTL)
    except subprocess.TimeoutExpired:
        raise WinctlError("winctl timed out: %s" % " ".join(args))
    out = (p.stdout or "").strip()
    if not want_json:
        if p.returncode != 0:
            raise WinctlError("winctl exit %d: %s" % (p.returncode, (p.stderr or out)[:300]))
        return out
    try:
        data = json.loads(out) if out else None
    except ValueError:
        data = None
    if p.returncode != 0:
        msg = ""
        if isinstance(data, dict):
            msg = (data.get("error") or {}).get("message") or ""
        raise WinctlError("winctl exit %d: %s" % (p.returncode, msg or (p.stderr or out)[:300]))
    return data


def list_windows(cls=None, all_=False):
    args = ["list"]
    if cls:
        args += ["--class", cls]
    if all_:
        args += ["--all"]
    return _run(args) or []


def game_window(sel=SEL):
    """The live game window dict, or None. Selector-based, so it matches what the verbs will hit."""
    cls = sel.split("=", 1)[1] if sel.startswith("class=") else "WinGraphicsWindow0"
    ws = list_windows(cls=cls)
    return ws[0] if ws else None


def key(name, hold_ms=None, sel=SEL, input_mode=None, mods=None):
    """Press a key. With hold_ms the key is held down that long before release -- which is how a
    message-pump game is walked without focus (a tap is too short to survive a frame poll)."""
    args = ["key", sel, name, "--input", input_mode or INPUT_MODE]
    if hold_ms:
        args += ["--hold", str(int(hold_ms))]
    if mods:
        args += ["--mods", ",".join(mods)]
    # +5s of slack over the hold so the subprocess timeout never fires before winctl finishes
    return _run(args, timeout=5 + (hold_ms or 0) / 1000.0 + 20)


def click(fx, fy, sel=SEL, input_mode=None, button="left", double=False):
    """Click at a fraction of the client area. Fractions need a '.', so they are formatted as such."""
    args = ["click", sel, "%.4f" % float(fx), "%.4f" % float(fy),
            "--input", input_mode or INPUT_MODE, "--button", button]
    if double:
        args += ["--double"]
    return _run(args)


def shot(path, sel=SEL, backend=None):
    """Capture the client area to `path` and return it as a PIL image."""
    args = ["shot", sel, path]
    if backend:
        args += ["--backend", backend]
    _run(args)
    from PIL import Image
    return Image.open(path).convert("RGB")


def available():
    return os.path.exists(WINCTL)
