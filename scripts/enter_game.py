#!/usr/bin/env python3
"""Drive the client back into the world from wherever it is -- reading the game, not the screen.

This is the memory-driven counterpart to `ttdrive.py`. ttdrive classifies the screen from PIXELS
and clicks fixed fractions, which works but is brittle; this asks the engine directly. Every
decision below comes from the client's own memory, and nothing is inferred from a screenshot.

HOW EACH STATE IS RECOGNISED

    in world        `base.cr.doId2do` contains the local toon (the object exposing `tunnelOut`)
    toon picker     a DirectGUI button whose NODE IS NAMED AFTER THE TOON ("Mr. Beanwhip").
                    Empty slots have an empty name; every other widget is `vlt<hash>-pg<id>`.
    Make-a-Toon     no toon-named button, but a cancel X bottom-left and several others
    a dialog        exactly one non-HUD button -- e.g. "Your Toon got sleepy and went to bed",
                    whose OK sits alone at 0.500,0.617
    title screen    no DirectGUI buttons at all; it wants any keypress

WHY NOT PIXELS: picking the toon by screen position failed four separate times, each time dropping
into Make-a-Toon. A fixed fraction was wrong (the occupied slot is not always bottom-right), colour
variety at fixed grid centres measured the wrong thing, and waiting for the picker to stop
animating did not help because it was already still. Position was never the right signal.

HOW IT CLICKS: `base.win.movePointer(0, px, py)` -- Panda's OWN api, in window-relative pixels --
puts the cursor exactly where the engine thinks it is, with no screen mapping, DPI or aspect
arithmetic on our side to get wrong. Panda's MouseWatcher reads the real cursor rather than a
posted message's coordinates (see ../winctl/bugs.md #1), so a plain BACKGROUND click then lands on
the right widget WITHOUT stealing focus or moving anything the user is doing.

Usage:
    python scripts/enter_game.py           drive to in-world from any of the above
    python scripts/enter_game.py --list    print what is on screen right now, change nothing
    python scripts/enter_game.py --once    take a single step and report
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
    """Point via Panda, then press. False if the pointer could not be placed."""
    r = ex.point({"fx": float(fx), "fy": float(fy)})
    if not r.get("ok") or not (r.get("r") or {}).get("moved"):
        return False
    time.sleep(settle)                  # let DirectGUI see the mouse-ENTER before the press
    W.click(fx, fy, input_mode="background")
    return True


def buttons(ex):
    """[{name, fx, fy}] for every visible DirectGUI button, from the scene graph."""
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


def is_cancel(b):
    return abs(b["fx"] - CANCEL_X[0]) < 0.05 and abs(b["fy"] - CANCEL_X[1]) < 0.05


def in_world(ex):
    st = ex.state({})
    return bool(st.get("ok") and (st.get("r") or {}).get("me"))


def classify(ex):
    """(state, detail) for the current screen. Never raises; never guesses from pixels."""
    if in_world(ex):
        return "ingame", None
    btns = buttons(ex)
    toon = find_toon(btns)
    if toon:
        return "picker", toon
    if any(is_cancel(b) for b in btns) and len(btns) >= 3:
        return "makeatoon", next(b for b in btns if is_cancel(b))
    if len(btns) == 1:
        return "dialog", btns[0]
    if not btns:
        return "title", None
    return "unknown", None


def step(ex, verbose=True):
    """Take one action toward being in the world. Returns the state it acted on."""
    state, detail = classify(ex)
    if verbose:
        where = "" if not detail else " (%r at %.3f,%.3f)" % (detail["name"][:24], detail["fx"], detail["fy"])
        print("[enter] %s%s" % (state, where), flush=True)

    if state == "ingame":
        return state
    if state == "picker":
        click_at(ex, 0.30, 0.25, settle=0.3)        # park elsewhere: DirectGUI arms on ENTER
        if not click_at(ex, detail["fx"], detail["fy"]):
            W.click(detail["fx"], detail["fy"], input_mode="raw")
        time.sleep(3.0)
    elif state == "makeatoon":
        if not click_at(ex, detail["fx"], detail["fy"]):
            W.click(detail["fx"], detail["fy"], input_mode="raw")
        time.sleep(2.5)
    elif state == "dialog":
        if not click_at(ex, detail["fx"], detail["fy"]):
            W.click(detail["fx"], detail["fy"], input_mode="raw")
        time.sleep(2.0)
    elif state == "title":
        W.key("enter", hold_ms=60)                  # title wants any key; background is enough
        time.sleep(1.5)
    else:
        time.sleep(1.5)
    return state


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="print the visible buttons and exit")
    ap.add_argument("--once", action="store_true", help="take a single step and exit")
    ap.add_argument("--timeout", type=float, default=180.0)
    a = ap.parse_args()

    session, ex = WS.attach()
    try:
        if a.list:
            state, detail = classify(ex)
            print("state: %s" % state)
            for b in buttons(ex):
                print("  %-28r %.3f,%.3f" % (b["name"][:28], b["fx"], b["fy"]))
            return 0

        deadline = time.time() + a.timeout
        while time.time() < deadline:
            if step(ex) == "ingame":
                print("[enter] in world", flush=True)
                return 0
            if a.once:
                return 0
        print("[enter] timed out", file=sys.stderr)
        return 1
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
