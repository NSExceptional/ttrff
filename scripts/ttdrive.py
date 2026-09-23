#!/usr/bin/env python3
"""ttdrive - drive the Windows TTR client from wherever it is into the game, unattended.

The Windows counterpart of `tt-to-playground` (macOS), built on `winctl` instead of the macOS
`winctl`. Out-of-process only: window management, capture and synthetic input. It never attaches
to, injects into, or reads memory from the engine -- that is the injector's job, kept separate.

Same shape as the macOS driver, because that shape was earned:
  * classify the current screen into exactly ONE token, cheap signals first
  * never exit empty -- an unexpected error yields a safe token and the caller keeps polling
  * re-read state every tick and resume from whatever is on screen, rather than running a fixed
    script; loads are slow and screens flap
  * confirm a terminal state twice before declaring success

Because it resumes from any state, the post-crash path and the cold-start path are the same code:
the crash dialog is just one more state. `recover` is an alias for `enter` and exists only so the
post-crash entry point has an obvious name.

States:
    dead        nothing running                  -> launch the launcher
    crashdialog "Gadzooks!" crash prompt         -> press Yes (UI Automation)
    launcher    launcher up, no engine           -> press GO (UI Automation, geometry fallback)
    loading     engine up, window black/absent   -> wait
    title       "PRESS ANY KEY TO ENTER"         -> tap a key
    toonselect  toon picker                      -> click the toon slot
    ingame      3D scene                         -> done
    unknown     unclassifiable                   -> wait (safe fallback)

Run it with the Python that has `winctl` installed:
    <winctl-venv>/python.exe scripts/ttdrive.py enter

Usage:
    ttdrive.py state            print the current token and exit
    ttdrive.py enter            drive to `ingame`
    ttdrive.py recover          alias for enter (post-crash entry point)
"""
import argparse
import os
import subprocess
import sys
import time

try:
    from winctl import capture, inputs, uia, windows
except ImportError:
    sys.exit("ttdrive: needs `winctl` importable. Run it with the winctl venv's python, e.g.\n"
             "  C:\\Users\\<you>\\Developer\\winctl\\.venv\\Scripts\\python.exe scripts/ttdrive.py enter")

# ---- constants -------------------------------------------------------------
ENGINE_CLASS = "WinGraphicsWindow0"          # Panda3D's window class; stabler than the title,
                                             # which the launcher also starts with
LAUNCHER_PROC = "Launcher.exe"
LAUNCHER_TITLE = "Toontown Rewritten Launcher"
CRASH_TITLE = "Gadzooks!"                    # the post-crash "log in again?" dialog
LAUNCHER_EXE = os.environ.get(
    "TTRFF_LAUNCHER", r"C:\Program Files (x86)\Toontown\Launcher.exe")

# Toon slot to play, as a fraction of the client area. The picker is a 3x2 grid; this is the
# bottom-right slot. Fractions, not pixels, so it survives a resize (measured 0.775,0.725 at
# 1280x768; the macOS driver uses 0.77,0.70 for the same slot).
TOON_SLOT = (float(os.environ.get("TTRFF_TOON_X", "0.775")),
             float(os.environ.get("TTRFF_TOON_Y", "0.725")))

# Centres of all six picker slots, used to RECOGNISE the picker: on the toon picker these sit on
# saturated warm cards, on the title screen they are all background blue.
SLOT_POINTS = [(0.248, 0.306), (0.504, 0.354), (0.762, 0.328),
               (0.240, 0.736), (0.504, 0.755), (0.775, 0.725)]

GO_BUTTON_FRAC = (0.873, 0.560)              # launcher GO, geometry fallback if UIA misses
POLL = 2.0
DEFAULT_TIMEOUT = float(os.environ.get("TTRFF_DRIVE_TIMEOUT", "300"))


def log(msg):
    print("[ttdrive] %s" % msg, flush=True)


# ---- window resolution -----------------------------------------------------
def _win(**kw):
    try:
        return windows.list_windows(**kw)
    except Exception:
        return []


def engine_window():
    for w in _win(cls=ENGINE_CLASS):
        return w
    return None


def launcher_window():
    for w in _win(process=LAUNCHER_PROC):
        if w.get("title") == LAUNCHER_TITLE and w.get("visible"):
            return w
    return None


def launcher_alive():
    """True if the launcher PROCESS exists, even with no visible window.

    Needed because after GO the launcher HIDES its main window while the engine starts. During
    that gap there is no launcher window and no engine window, and classifying that as `dead`
    makes the driver spuriously launch a SECOND launcher -- observed exactly that. Listing with
    all=True sees the process's hidden/IME windows, which is enough to prove it is alive without
    adding a psutil dependency.
    """
    return bool(_win(process=LAUNCHER_PROC, all=True))


def crash_dialog():
    """The visible crash prompt, if any.

    MUST check `visible`. Qt HIDES this dialog after it is dismissed instead of destroying it, so
    the window handle lives on for the rest of the launcher's life. Matching on title alone (or
    listing with all=True) finds that corpse and pins the classifier to `crashdialog` forever --
    observed exactly that, looping until timeout on an already-dismissed dialog.
    """
    for w in _win(process=LAUNCHER_PROC):
        if w.get("title") == CRASH_TITLE and w.get("visible"):
            return w
    return None


# ---- screen classification -------------------------------------------------
def _metrics(hwnd):
    """(mean luma, distinct-colour count, per-slot 'is warm' flags) from one capture."""
    im = capture.capture_printwindow(hwnd)
    # tobytes() rather than getdata(): getdata() is deprecated in Pillow >= 12 and warns on
    # every call, which would spam a polling loop.
    px = im.convert("L").resize((64, 40)).tobytes()
    luma = sum(px) / float(len(px))
    raw = im.convert("RGB").resize((32, 20)).tobytes()
    variety = len({raw[i:i + 3] for i in range(0, len(raw), 3)})
    rgb = im.convert("RGB")
    w, h = rgb.size
    warm = []
    for fx, fy in SLOT_POINTS:
        x = min(max(int(fx * w), 0), w - 1)
        y = min(max(int(fy * h), 0), h - 1)
        r, g_, b = rgb.getpixel((x, y))
        warm.append(r > b + 25)     # cards are warm (yellow/red/orange); background is blue
    return luma, variety, warm


def classify():
    """Current screen as exactly one token. Never raises; never returns empty."""
    try:
        if crash_dialog():
            return "crashdialog"
        ew = engine_window()
        if ew is None:
            if launcher_window():
                return "launcher"
            # launcher process alive but no window = it hid itself and is starting the engine
            return "loading" if launcher_alive() else "dead"
        if ew.get("minimized") or not ew.get("clientW"):
            return "loading"
        luma, variety, warm = _metrics(ew["hwnd"])
        if luma < 12:
            return "loading"
        if variety > 300:
            return "ingame"
        if sum(warm) >= 4:
            return "toonselect"
        return "title"
    except Exception as e:
        log("classify failed (%r) -- treating as unknown" % (e,))
        return "unknown"


# ---- actions ---------------------------------------------------------------
def press_yes(dlg):
    """Post-crash dialog. A real Qt dialog with QPushButtons, so UIA can invoke Yes directly --
    no mouse, no geometry. Verified: uia.press resolves it and reports method 'invoke'."""
    try:
        res = uia.press(dlg["hwnd"], "name=Yes")
        log("crash dialog: pressed Yes via %s" % res.get("method", "uia"))
        return True
    except Exception as e:
        log("crash dialog: UIA press failed (%r); falling back to geometry" % (e,))
    try:
        inputs.click(dlg["hwnd"], 0.681, 0.803)
        log("crash dialog: clicked Yes by geometry")
        return True
    except Exception as e:
        log("crash dialog: geometry click failed (%r)" % (e,))
        return False


def press_go(lw):
    """Launcher GO. The button is a custom-painted Qt widget that UIA reports with role 'image'
    (class GoButton), so an Invoke pattern is not trustworthy -- locate it via UIA, then click its
    centre for real. Falls back to the measured fraction if UIA can't see it."""
    try:
        els, _ = uia.describe(lw["hwnd"], actionable=True)
        for el in els:
            if (el.get("class") or "") == "GoButton":
                inputs.click(lw["hwnd"], el["fx"], el["fy"])
                log("launcher: clicked GO (UIA-located at %.3f,%.3f)" % (el["fx"], el["fy"]))
                return True
        log("launcher: no GoButton in the UIA tree; using geometry")
    except Exception as e:
        log("launcher: UIA lookup failed (%r)" % (e,))
    try:
        inputs.click(lw["hwnd"], *GO_BUTTON_FRAC)
        log("launcher: clicked GO by geometry")
        return True
    except Exception as e:
        log("launcher: GO click failed (%r)" % (e,))
        return False


def open_launcher():
    log("launching %s" % LAUNCHER_EXE)
    try:
        subprocess.Popen([LAUNCHER_EXE], cwd=os.path.dirname(LAUNCHER_EXE),
                         close_fds=True)
        return True
    except Exception as e:
        log("could not launch: %r" % (e,))
        return False


# ---- driver ----------------------------------------------------------------
def enter(timeout=DEFAULT_TIMEOUT):
    """Drive from any state to `ingame`. Returns True on success."""
    start = time.time()
    last, repeats = None, 0
    while True:
        if time.time() - start > timeout:
            log("TIMEOUT after %.0fs (last state: %s)" % (timeout, last))
            return False
        s = classify()
        repeats = repeats + 1 if s == last else 0
        last = s
        log("state=%s (%ds elapsed)" % (s, int(time.time() - start)))

        if s == "ingame":
            # confirm: a fading picker can momentarily look like a loaded scene
            time.sleep(1.3)
            if classify() != "ingame":
                log("ingame was transient; re-evaluating")
                continue
            log("in game")
            return True

        if s == "crashdialog":
            press_yes(crash_dialog() or {})
        elif s == "dead":
            open_launcher()
            time.sleep(6)
        elif s == "launcher":
            lw = launcher_window()
            if lw:
                press_go(lw)
                time.sleep(5)
        elif s == "title":
            ew = engine_window()
            if ew:
                inputs.key(ew["hwnd"], "return")
                log("title: tapped return")
        elif s == "toonselect":
            ew = engine_window()
            if ew:
                inputs.click(ew["hwnd"], *TOON_SLOT)
                log("toonselect: clicked slot at %.3f,%.3f" % TOON_SLOT)
                time.sleep(4)
        # `loading` and `unknown` just wait

        time.sleep(POLL)


def main():
    ap = argparse.ArgumentParser(description="drive the Windows TTR client into the game")
    ap.add_argument("verb", choices=["state", "enter", "recover"])
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    a = ap.parse_args()
    if a.verb == "state":
        print(classify())
        return 0
    return 0 if enter(a.timeout) else 1


if __name__ == "__main__":
    sys.exit(main())
