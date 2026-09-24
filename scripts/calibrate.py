#!/usr/bin/env python3
"""Measure the toon's movement model: degrees turned and units walked per key-hold duration.

The steering constants were originally guessed, which is why the bot overshot every target -- it
held a turn key for a whole tick regardless of the correction needed. This measures the real
numbers by holding a key for a set time and reading position/heading out of the client's own
memory before and after. No pixels, no guessing.

It reports, for each axis, a least-squares fit of

    amount = rate * seconds + overhead

Overhead absorbs key latency and the engine's acceleration ramp, which is why short holds are not
simply proportional. Feed the results into TURN_RATE / WALK_SPEED in scripts/beanbot.py.

Run it standing in open space: turns are harmless, but a walk measurement that ends against a wall
reads low. The spread column shows when that happened -- a large spread means re-run it somewhere
clearer, and the median is reported alongside the mean for that reason.

Usage:  python scripts/calibrate.py [--repeats 3] [--turn-only | --walk-only]
"""
import argparse
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "frida"))
import worldstate as WS                 # noqa: E402

TURN_DURATIONS = [0.05, 0.08, 0.12, 0.18, 0.25, 0.35, 0.50]
# 1.8s was dropped: at ~21 units/s that is 38 units, far enough that the toon reliably ran
# into scenery before the hold ended, which reads as a LOW speed and drags the fit down.
WALK_DURATIONS = [0.15, 0.30, 0.50, 0.80, 1.20]
SETTLE = 0.30          # let the animation stop before reading the final pose


def norm180(d):
    return (d + 180.0) % 360.0 - 180.0


def pose(ex):
    r = ex.state({})
    if not r.get("ok"):
        return None
    st = r.get("r") or {}
    if st.get("err") or not st.get("me"):
        return None
    return st["me"]


def median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def fit(pts):
    """least squares amount = rate*seconds + overhead"""
    n = len(pts)
    sx = sum(p[0] for p in pts)
    sy = sum(p[1] for p in pts)
    sxx = sum(p[0] * p[0] for p in pts)
    sxy = sum(p[0] * p[1] for p in pts)
    den = n * sxx - sx * sx
    if abs(den) < 1e-9:
        return None
    rate = (n * sxy - sx * sy) / den
    return rate, (sy - rate * sx) / n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--turn-only", action="store_true")
    ap.add_argument("--walk-only", action="store_true")
    a = ap.parse_args()

    from winctl import inputs, windows
    ws = windows.list_windows(cls="WinGraphicsWindow0")
    if not ws:
        raise SystemExit("calibrate: no game window")
    hwnd = ws[0]["hwnd"]

    session, ex = WS.attach()
    turn_pts, walk_pts = [], []
    try:
        if pose(ex) is None:
            raise SystemExit("calibrate: toon not in world")

        if not a.walk_only:
            print("== turn ==")
            for key, label, sign in (("d", "right", -1.0), ("a", "left", +1.0)):
                for dur in TURN_DURATIONS:
                    vals = []
                    for _ in range(a.repeats):
                        p0 = pose(ex)
                        if p0 is None:
                            continue
                        inputs.key_hold(hwnd, key, True)
                        time.sleep(dur)
                        inputs.key_hold(hwnd, key, False)
                        time.sleep(SETTLE)
                        p1 = pose(ex)
                        if p1 is None:
                            continue
                        vals.append(norm180(p1["h"] - p0["h"]) * sign)
                    if vals:
                        turn_pts.append((dur, median(vals)))
                        print("  %-5s hold %.2fs -> %6.1f deg  (median %6.1f, spread %4.1f, n=%d)"
                              % (label, dur, sum(vals) / len(vals), median(vals),
                                 max(vals) - min(vals), len(vals)), flush=True)

        if not a.turn_only:
            print("== walk ==")
            for dur in WALK_DURATIONS:
                vals = []
                for _ in range(a.repeats):
                    p0 = pose(ex)
                    if p0 is None:
                        continue
                    inputs.key_hold(hwnd, "w", True)
                    time.sleep(dur)
                    inputs.key_hold(hwnd, "w", False)
                    time.sleep(SETTLE)
                    p1 = pose(ex)
                    if p1 is None:
                        continue
                    vals.append(math.hypot(p1["x"] - p0["x"], p1["y"] - p0["y"]))
                    # turn 180 and walk back, so a long run does not march out of the open area
                    inputs.key_hold(hwnd, "a", True)
                    time.sleep(1.92)
                    inputs.key_hold(hwnd, "a", False)
                    time.sleep(0.2)
                if vals:
                    walk_pts.append((dur, median(vals)))
                    print("  hold %.2fs -> %6.1f units  (median %6.1f, spread %4.1f, n=%d)"
                          % (dur, sum(vals) / len(vals), median(vals),
                             max(vals) - min(vals), len(vals)), flush=True)
    finally:
        for k in ("w", "a", "s", "d"):
            try:
                inputs.key_hold(hwnd, k, False)
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass

    print()
    if len(turn_pts) >= 2:
        f = fit(turn_pts)
        if f:
            print("TURN_RATE = %.1f      # deg/s   (overhead %+.1f deg)" % (f[0], f[1]))
            print("  to turn N degrees, hold (N - %.1f) / %.1f seconds" % (f[1], f[0]))
    if len(walk_pts) >= 2:
        f = fit(walk_pts)
        if f:
            print("WALK_SPEED = %.1f     # units/s (overhead %+.1f units)" % (f[0], f[1]))
            print("  to cover N units, hold (N - %.1f) / %.1f seconds" % (f[1], f[0]))
            for d in (10, 25, 50, 100, 200):
                print("   %3d units -> %.2fs" % (d, max((d - f[1]) / f[0], 0.0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
