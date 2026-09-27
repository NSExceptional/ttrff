#!/usr/bin/env python3
"""Select the real toon at the picker, by NAME, read from the client's memory.

WHY THIS EXISTS: picking the slot by screen position has now failed four times, each time dropping
into Make-a-Toon, which is disruptive and has to be backed out of by hand. Every approach that
guessed from pixels failed for a different reason -- a fixed fraction (the occupied slot is not
always bottom-right), colour variety at fixed grid centres (measured the wrong thing), and waiting
for the picker to stop animating (it was already still). Position was simply the wrong signal.

The scene graph settles it. Each picker slot is a DirectGUI button, and the occupied one's node is
NAMED AFTER THE TOON -- `Mr. Beanwhip` -- while empty slots have an empty name and every other
widget is `vlt<hash>-pg<id>`. So the toon is found by name and clicked at its own drawn centre.

CLICKING: Panda places the cursor, we only press the button. `base.win.movePointer(0, px, py)` is
Panda's own API and takes window-relative pixels, so the cursor ends up exactly where the engine
thinks it does -- no screen mapping, DPI or aspect-ratio arithmetic on our side to get wrong. Since
Panda's MouseWatcher reads the real cursor (../winctl/bugs.md #1), a plain BACKGROUND click then
lands on the right widget without stealing focus. Converting fractions to screen pixels ourselves
and clicking there is what kept hitting the wrong slot.

Usage:
    python scripts/pick_toon.py            pick the toon, backing out of Make-a-Toon if needed
    python scripts/pick_toon.py --list     just show what is on screen
"""
import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "frida"))
sys.path.insert(0, HERE)
import worldstate as WS                 # noqa: E402
import winctl_cli as W                  # noqa: E402

# Every ordinary widget is named `vlt<hash>-pg<id>`; anything else is a name the game chose.
GENERIC = re.compile(r"^vlt[0-9a-f]+-pg\d+$")
CANCEL_X = (0.045, 0.925)               # Make-a-Toon's cancel, stable across its pages


def click_at(ex, fx, fy, settle=0.35):
    """Point via Panda, then click. Returns False if the pointer could not be placed."""
    r = ex.point({"fx": float(fx), "fy": float(fy)})
    if not r.get("ok") or not (r.get("r") or {}).get("moved"):
        return False
    time.sleep(settle)                     # let DirectGUI register the mouse-ENTER before pressing
    W.click(fx, fy, input_mode="background")
    return True


def buttons(ex):
    """[{name, fx, fy}] for every visible DirectGUI button."""
    win = W.game_window()
    if not win or not win.get("clientH"):
        return []
    aspect = float(win["clientW"]) / float(win["clientH"])
    r = ex.buttons()
    if not r.get("ok"):
        return []
    out = []
    for b in (r.get("r") or {}).get("buttons") or []:
        if b.get("x") is None or b.get("z") is None:
            continue
        out.append({"name": b.get("name") or "",
                    "fx": 0.5 + b["x"] / (2.0 * aspect),
                    "fy": 0.5 - b["z"] / 2.0})
    return out


def find_toon(btns):
    """The picker button named after a toon, or None."""
    for b in btns:
        n = (b["name"] or "").strip()
        if n and not GENERIC.match(n):
            return b
    return None


def in_make_a_toon(btns):
    """Make-a-Toon shows a cancel X bottom-left and no toon-named slot."""
    if find_toon(btns):
        return False
    return any(abs(b["fx"] - CANCEL_X[0]) < 0.05 and abs(b["fy"] - CANCEL_X[1]) < 0.05
               for b in btns)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="show the visible buttons and exit")
    ap.add_argument("--timeout", type=float, default=90.0)
    a = ap.parse_args()

    session, ex = WS.attach()
    try:
        if a.list:
            for b in buttons(ex):
                print("  %-28r %.3f,%.3f" % (b["name"][:28], b["fx"], b["fy"]))
            return 0

        deadline = time.time() + a.timeout
        while time.time() < deadline:
            st = ex.state({})
            if st.get("ok") and (st.get("r") or {}).get("me"):
                print("[pick] already in world")
                return 0

            btns = buttons(ex)
            if in_make_a_toon(btns):
                print("[pick] in Make-a-Toon -- backing out", flush=True)
                if not click_at(ex, CANCEL_X[0], CANCEL_X[1]):
                    W.click(CANCEL_X[0], CANCEL_X[1], input_mode="raw")   # fallback
                time.sleep(2.5)
                continue

            toon = find_toon(btns)
            if toon:
                print("[pick] found toon %r at %.3f,%.3f" % (toon["name"], toon["fx"], toon["fy"]),
                      flush=True)
                click_at(ex, 0.30, 0.25, settle=0.3)       # park: DirectGUI arms on mouse-ENTER
                if not click_at(ex, toon["fx"], toon["fy"]):
                    W.click(toon["fx"], toon["fy"], input_mode="raw")     # fallback
                time.sleep(3.0)
                continue

            time.sleep(1.5)
        print("[pick] timed out", file=sys.stderr)
        return 1
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
