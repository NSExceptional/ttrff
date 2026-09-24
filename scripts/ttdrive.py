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
    modal       a DirectGUI dialog is up          -> click cancel (red X), else ok (green check)
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
    """(mean luma, distinct-colour count, per-slot 'is warm' flags, blue-dominant fraction)."""
    im = capture.capture_printwindow(hwnd)
    # tobytes() rather than getdata(): getdata() is deprecated in Pillow >= 12 and warns on
    # every call, which would spam a polling loop.
    px = im.convert("L").resize((64, 40)).tobytes()
    luma = sum(px) / float(len(px))
    raw = im.convert("RGB").resize((32, 20)).tobytes()
    variety = len({raw[i:i + 3] for i in range(0, len(raw), 3)})
    # Blue dominance separates the 2D menus from a 3D scene. Colour variety ALONE is not enough:
    # the title screen's animated fireworks push it past any useful threshold, and that screen was
    # misclassified as `ingame` -- which matters, because the driver then taps keys at a screen
    # whose buttons include QUIT. The menus are overwhelmingly the same blue; a rendered world is
    # grass/pavement/sky and much less blue-dominant.
    small = im.convert("RGB").resize((64, 40))
    sb = small.tobytes()
    n = len(sb) // 3
    blue = sum(1 for i in range(0, len(sb), 3) if sb[i + 2] > sb[i] + 20) / float(n)
    rgb = im.convert("RGB")
    w, h = rgb.size
    warm = []
    for fx, fy in SLOT_POINTS:
        x = min(max(int(fx * w), 0), w - 1)
        y = min(max(int(fy * h), 0), h - 1)
        r, g_, b = rgb.getpixel((x, y))
        warm.append(r > b + 25)     # cards are warm (yellow/red/orange); background is blue
    # TTR's DirectGUI dialogs are a pale cream/yellow rounded panel in the middle of the screen.
    # Sampling the central band for that colour finds one without OCR.
    panel = 0.0
    x0, x1 = int(0.34 * w), int(0.67 * w)
    y0, y1 = int(0.36 * h), int(0.62 * h)
    seen = 0
    for yy in range(y0, y1, max(1, (y1 - y0) // 24)):
        for xx in range(x0, x1, max(1, (x1 - x0) // 24)):
            r, g_, b = rgb.getpixel((xx, yy))
            seen += 1
            if r > 195 and g_ > 195 and b < r - 22:
                panel += 1
    panel = panel / float(seen or 1)
    return luma, variety, warm, blue, panel


def dialog_buttons(hwnd):
    """Locate a dialog's buttons by COLOUR, so no OCR is needed.

    TTR colour-codes them: a red X is cancel/no, a green check is ok/yes. That distinction is what
    makes a generic dismissal safe -- on the title screen's "Are you ready to leave Toontown?" the
    red X is the one you want, and blindly tapping return there hits OK and quits the game.
    Returns {"cancel": (fx, fy) | None, "ok": (fx, fy) | None}.
    """
    im = capture.capture_printwindow(hwnd).convert("RGB")
    w, h = im.size
    # Search the BUTTON ROW only (buttons sit low in the panel). Searching the whole panel picked
    # up its green border as an "ok" button, and red from the artwork behind it as a "cancel".
    x0, x1 = int(0.34 * w), int(0.67 * w)
    y0, y1 = int(0.55 * h), int(0.68 * h)
    red, blue = [], []
    for yy in range(y0, y1):
        for xx in range(x0, x1):
            r, g_, b = im.getpixel((xx, yy))
            if r > 140 and g_ < 95 and b < 95:
                red.append((xx, yy))          # red X = cancel / no
            elif b > 130 and b > r + 45 and b > g_ + 25:
                blue.append((xx, yy))         # blue check = ok / yes

    def centroid(pts):
        if len(pts) < 12:
            return None
        return (sum(p[0] for p in pts) / float(len(pts)) / w,
                sum(p[1] for p in pts) / float(len(pts)) / h)

    # Verified against real captures: on the quit confirm this yields ok=0.466,0.615 and
    # cancel=0.533,0.617; on non-dialog screens it finds no red at all.
    return {"cancel": centroid(red), "ok": centroid(blue)}


# The picker is a 3x2 grid of cards; these are their centres as client-area fractions.
SLOT_GRID = [(0.25, 0.31), (0.50, 0.31), (0.76, 0.31),
             (0.25, 0.73), (0.50, 0.73), (0.76, 0.73)]


def find_occupied_slot(hwnd):
    """Fraction coords of the picker card that actually HOLDS a toon, or None.

    Clicking a fixed fraction landed on an empty card and dropped the driver into Make-a-Toon --
    twice -- which is disruptive and has to be backed out of by hand. Position is the wrong thing
    to trust: which cards are empty depends on the account, and an empty card looks nothing like an
    occupied one. An occupied card renders a 3D toon head, so it carries many distinct colours; an
    empty card is a flat pastel rectangle with "MAKE A TOON" on it, so it carries a handful.
    Counting quantised colours separates them by a wide margin.

    Returns None rather than a guess when no card clearly wins, so the caller can refuse to click.
    """
    im = capture.capture_printwindow(hwnd).convert("RGB")
    w, h = im.size
    scores = []
    for fx, fy in SLOT_GRID:
        cx, cy = int(fx * w), int(fy * h)
        x0, x1 = max(cx - int(0.075 * w), 0), min(cx + int(0.075 * w), w)
        y0, y1 = max(cy - int(0.10 * h), 0), min(cy + int(0.10 * h), h)
        seen = set()
        for yy in range(y0, y1, 3):
            for xx in range(x0, x1, 3):
                r, g, b = im.getpixel((xx, yy))
                seen.add((r >> 4, g >> 4, b >> 4))     # quantise; exact shades are noise
        scores.append(((fx, fy), len(seen)))
    scores.sort(key=lambda kv: -kv[1])
    (best, top), (_, second) = scores[0], scores[1]
    log("toonselect: slot colour variety %s" % [(("%.2f,%.2f" % s[0]), s[1]) for s in scores])
    if top < 1.5 * max(second, 1):
        return None
    return best


def click_fresh(hwnd, fx, fy, park=(0.20, 0.30)):
    """Click a DirectGUI control, parking the cursor elsewhere first.

    Panda3D's DirectGUI arms a button on mouse-ENTER. SendInput moves the cursor and clicks in one
    go, so if the cursor is ALREADY on the control (e.g. from a previous click at the same spot) no
    enter fires and the click does nothing -- silently, forever. Observed repeatedly: the first
    click would only reveal a button's hover label, and further clicks at the same point were
    ignored. Parking the cursor away first guarantees a fresh enter.
    """
    inputs.click(hwnd, float(park[0]), float(park[1]))
    time.sleep(0.6)
    return inputs.click(hwnd, float(fx), float(fy))


def dismiss_modal(ew):
    """Dismiss a dialog, preferring the NON-destructive button.

    Prefer cancel (red X) when present -- the common blocking modal is the quit confirm, and OK
    there leaves the game. Fall back to ok (green check) for one-button dialogs like a disconnect
    notice, which can only be acknowledged.
    """
    b = dialog_buttons(ew["hwnd"])
    for which in ("cancel", "ok"):
        if b.get(which):
            fx, fy = b[which]
            click_fresh(ew["hwnd"], fx, fy)
            log("modal: clicked %s at %.3f,%.3f" % (which, fx, fy))
            return True
    log("modal: no button located; leaving it alone rather than guessing")
    return False


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
        luma, variety, warm, blue, panel = _metrics(ew["hwnd"])
        if luma < 12:
            return "loading"
        # modal is checked BEFORE title/ingame on purpose: the title screen's quit confirm sits on
        # top of the title art, and the `title` action taps return -- which would press OK and quit.
        if panel > 0.45:
            return "modal"
        # toonselect needs BOTH warm slot cards AND a blue background. Warm slots alone matched a
        # tan tunnel arch in-game, and the driver then clicked the toon-slot fraction forever
        # (250s timeout) at a screen that has no slots. The picker is warm cards ON blue.
        if sum(warm) >= 4 and blue > 0.30:
            return "toonselect"
        if variety > 300 and blue < 0.55:
            return "ingame"
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
        elif s == "modal":
            ew = engine_window()
            if ew:
                dismiss_modal(ew)
                time.sleep(1.5)
        elif s == "title":
            ew = engine_window()
            if ew:
                inputs.key(ew["hwnd"], "return")
                log("title: tapped return")
        elif s == "toonselect":
            ew = engine_window()
            if ew:
                slot = find_occupied_slot(ew["hwnd"])
                if slot is None:
                    # Refuse to guess: a wrong click here enters Make-a-Toon, which is far worse
                    # than waiting a tick for the picker to finish animating in.
                    log("toonselect: no card clearly holds a toon yet -- waiting")
                    time.sleep(1.0)
                    continue
                click_fresh(ew["hwnd"], slot[0], slot[1])
                log("toonselect: clicked occupied slot at %.3f,%.3f" % slot)
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
