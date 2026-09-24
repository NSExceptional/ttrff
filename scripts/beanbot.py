#!/usr/bin/env python3
"""Auto-walk to Cartoonival bean/coin bags, steered by a Jev decision model (classifier.dev).

Reads the world from the client's OWN MEMORY via `frida/worldstate.py` -- the toon's position and
heading, and the position of every pickup -- converts that into toon-relative bearings, and asks
classifier.dev's System One endpoint which way to move. The answer is executed as a timed key hold.

WHAT IT CHASES
    Only the pickups carrying a `value`: both the jellybean bags and the Cartoonival coin bags are
    that kind, and both are wanted. The valueless kind is ice cream (a laff restore), which a toon
    at full health walks straight through without collecting -- chasing it looks exactly like a
    navigation failure and wastes the whole run. --include-treasures opts back in.

COLLECTION COOLDOWN
    Bags are rate limited: past some number in a window, walking through one only plays a sound and
    the bag stays put. That is temporary, so a bag that fails to collect goes on a SHORT retry
    timer (--retry-after, 5s) rather than the long blacklist used for genuinely unreachable ones.

CONTROL LAW: align, then advance
    Every action is a discrete pulse -- press a key, hold it for a MEASURED duration, release.
    Turns happen in place (a/d alone), never while walking, so a turn and a translation can never
    confound each other. The loop re-reads the world after each pulse, so any residual error is
    corrected on the next tick rather than accumulating.

DURATIONS ARE MEASURED, NOT GUESSED
    `scripts/calibrate.py` holds a key for a set time and reads the heading delta out of
    memory. On this client it fits, over both directions and 7 durations:

        degrees = 93.6 * seconds + 0.7        (repeat spread < 1 deg, left/right within 1%)

    The first version of this bot held the turn key for a whole 500 ms tick regardless of the
    correction needed -- i.e. ~47 degrees every time -- which made it zig-zag violently past every
    target. Re-run the calibration if the client's turn rate ever changes, and update TURN_RATE.

WHAT JEV IS AND IS NOT DOING
    Mapping a bearing to a turn is arithmetic, and `local_decide()` does exactly that as the
    fallback whenever the network is slow or down. Jev's value is the judgement around it: which
    treasure to commit to, when to abandon one that is not getting closer, when to reverse. Its
    accuracy depends on the criteria carrying EXPLICIT NUMERIC BANDS -- measured at 10/10 against
    arithmetic with bands, 5/10 with vague wording. Do not soften them.

WHAT IS NOT AVAILABLE
    There are no obstacle positions. Walls, buildings and trees are scene-graph collision geometry,
    not distributed objects, so they never appear in `base.cr.doId2do`. Instead the bot measures
    whether the distance to its target is actually falling and reports `blocked` -- the signal that
    matters anyway, and what lets Jev decide to turn off and try another line.

SAFETY
    Keys are held during a pulse, so every exit path must release them: the `finally`, an atexit
    hook and the signal handler all call `Keys.release_all`. Stop it with the stop file rather than
    Ctrl+C -- per AGENTS.md the stop file is the only reliable stop on Windows:
        echo . > %TEMP%\\beanbot-stop

Usage:
    python scripts/beanbot.py --dry-run          decide + print, never touch the keyboard
    python scripts/beanbot.py                    drive for real
    python scripts/beanbot.py --local            no network; arithmetic steering only
"""
import argparse
import atexit
import json
import math
import os
import signal
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "frida"))
import worldstate as WS                 # noqa: E402  -- the read-only memory reader

API = "https://classifier.dev/v1/systemone"
MODEL = "jev-latest"                    # bare 'jev' is rejected: unpriced_model

# --- measured by scripts/calibrate.py against this client -----------------------------------
TURN_RATE = 93.6        # degrees per second of held a/d   (fit spread < 1 deg, L/R within 1%)
TURN_OVERHEAD = 0.7     # fixed degrees per pulse (key latency + accel ramp); small but real
WALK_SPEED = 21.0       # units per second of held w
WALK_OVERHEAD = 0.1     # fixed units per pulse


def hold_for(degrees):
    """Seconds to hold a turn key to rotate `degrees`. Inverse of the measured fit."""
    return max((degrees - TURN_OVERHEAD) / TURN_RATE, 0.02)


def walk_for(units):
    """Seconds to hold `w` to cover `units`. Inverse of the measured fit."""
    return max((units - WALK_OVERHEAD) / WALK_SPEED, 0.05)


# Discrete actions: (key, seconds). Turns are in place -- no w+a / w+d -- so a turn never also
# translates. Magnitudes exist so Jev can express intent; the exact amount is whatever the
# measurement says that magnitude costs.
#
# Forward comes in three lengths because a fixed short burst wastes decisions: crossing 150 units
# of open playground in 0.6s hops is ~12 network round-trips to repeatedly answer "still straight
# ahead". A long leg covers it in one. Overshoot is not a risk even when the long leg is chosen
# wrongly, because the duration is clamped at run time to the distance actually remaining.
ACTIONS = {
    "turn_left_slight":  ("a", hold_for(10)),
    "turn_left":         ("a", hold_for(30)),
    "turn_left_far":     ("a", hold_for(90)),
    "turn_right_slight": ("d", hold_for(10)),
    "turn_right":        ("d", hold_for(30)),
    "turn_right_far":    ("d", hold_for(90)),
    "forward_short":     ("w", walk_for(8)),
    "forward":           ("w", walk_for(25)),
    "forward_far":       ("w", walk_for(90)),
    "back":              ("s", 0.50),
}

# Bands are chosen so each magnitude lands inside the band it is meant to clear: slight turns
# ~10 deg, medium ~30, far ~90; forward legs cover ~8 / ~25 / ~90 units.
CRITERIA = {
    "forward_short":     "bearing is between -8 and +8 degrees and the target is closer than 15 units, so close in carefully",
    "forward":           "bearing is between -8 and +8 degrees and the target is 15 to 60 units away",
    "forward_far":       "bearing is between -8 and +8 degrees and the target is more than 60 units away, so commit to a long run",
    "turn_left_slight":  "the target bearing is between -20 and -8 degrees (slightly left)",
    "turn_left":         "the target bearing is between -60 and -20 degrees (clearly left)",
    "turn_left_far":     "the target bearing is less than -60 degrees (far to the left or behind on the left)",
    "turn_right_slight": "the target bearing is between +8 and +20 degrees (slightly right)",
    "turn_right":        "the target bearing is between +20 and +60 degrees (clearly right)",
    "turn_right_far":    "the target bearing is greater than +60 degrees (far to the right or behind on the right)",
    "back":              "the distance has stopped falling for several seconds, so we are walking into something and must reverse",
}
INSTRUCTIONS = (
    "Steering a character toward treasure in a 3D game. Bearing is degrees relative to the way the "
    "character faces: negative is to the left, positive is to the right, 0 is dead ahead. Turns "
    "happen in place, then the character walks. NEVER choose a forward action unless the bearing "
    "is already within 8 degrees of straight ahead -- turn to face the target first. Prefer the "
    "target already being chased unless another is much closer. Pick the single best next action."
)


def norm180(deg):
    """Fold any angle into [-180, 180). Headings come out of Panda unbounded (404.47 is real)."""
    return (deg + 180.0) % 360.0 - 180.0


def bearing_to(me, t):
    """(bearing_degrees, ground_distance, height_difference) of `t` in the toon's own frame.

    Panda3D is Z-up with +Y forward, and heading rotates counter-clockwise seen from above, so the
    facing vector is (-sin H, cos H) and a target direction d has heading atan2(-dx, dy). A
    POSITIVE difference therefore means the target is to the LEFT; the sign is flipped on the way
    out because the criteria (and every human reading the log) treat positive as RIGHT.

    Height is returned separately and deliberately. Treasures in this zone span z=-10 to z=+46
    while the toon stands at z=11, so ground distance ALONE will happily report a treasure one
    unit away that is really on a rooftop -- the bot then stands under it forever. Steering is a
    horizontal problem, so the bearing ignores z; reachability is not, so the caller gets dz.
    """
    dx = t["x"] - me["x"]
    dy = t["y"] - me["y"]
    dz = t["z"] - me["z"] if t.get("z") is not None and me.get("z") is not None else 0.0
    return -norm180(math.degrees(math.atan2(-dx, dy)) - me["h"]), math.hypot(dx, dy), dz


def local_decide(bearing, distance, blocked):
    """The arithmetic controller: ground truth, and the fallback when the network is unavailable."""
    if blocked:
        return "back", 1.0
    b = bearing
    if b < -60:
        return "turn_left_far", 1.0
    if b < -20:
        return "turn_left", 1.0
    if b < -8:
        return "turn_left_slight", 1.0
    if b <= 8:
        if distance > 60:
            return "forward_far", 1.0
        return ("forward", 1.0) if distance > 15 else ("forward_short", 1.0)
    if b <= 20:
        return "turn_right_slight", 1.0
    if b <= 60:
        return "turn_right", 1.0
    return "turn_right_far", 1.0


def jev_decide(state, timeout):
    """Ask Jev. Returns (action, confidence) or raises."""
    body = {"state": state, "model": MODEL,
            "questions": {"move": {"type": "choice",
                                   "instructions": INSTRUCTIONS,
                                   "criteria": CRITERIA}}}
    req = urllib.request.Request(
        API, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer placeholder"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read())
    m = (out.get("answers") or out)["move"]
    return m["choice"], m.get("confidence", 0.0)


def screen_buttons(ex, hwnd):
    """Every visible DirectGUI button as {fx, fy, text, rgb}, read from the client's memory.

    This replaced a screen-wide colour hunt, which was the wrong tool. Searching pixels for "a red
    disc" repeatedly matched the gag/pie HUD icon, the red toon-picker cards, a maroon floor and
    even a single confetti flake, and each fix needed another gate (fill, size, isolation, glyph).
    The scene graph simply *knows* where the buttons are: `**/+PGButton` under aspect2d lists them
    with exact positions. Colour is still used, but only as a one-pixel-ish sample AT a known
    button, which is a completely different proposition from finding one in a 1280x768 haystack.

    Labels come back for text buttons and are None for the icon-only ones (the close X, the OK
    check), which is why colour is still needed to tell cancel from confirm.
    """
    from winctl import capture, windows
    r = ex.buttons()
    if not r.get("ok"):
        return []
    bs = (r.get("r") or {}).get("buttons") or []
    if not bs:
        return []
    w = windows.list_windows(cls="WinGraphicsWindow0")
    if not w or not w[0].get("clientH"):
        return []
    aspect = float(w[0]["clientW"]) / float(w[0]["clientH"])
    im = capture.capture_printwindow(hwnd).convert("RGB")
    iw, ih = im.size
    out = []
    for b in bs:
        if b.get("x") is None or b.get("z") is None:
            continue
        fx = 0.5 + b["x"] / (2.0 * aspect)
        fy = 0.5 - b["z"] / 2.0
        px, py = int(fx * iw), int(fy * ih)
        if not (0 <= px < iw and 0 <= py < ih):
            continue
        # median-ish sample over a small patch so one antialiased pixel cannot decide it
        rs = gs = bs_ = n = 0
        for dy in range(-6, 7, 3):
            for dx in range(-6, 7, 3):
                xx, yy = px + dx, py + dy
                if 0 <= xx < iw and 0 <= yy < ih:
                    pr, pg, pb = im.getpixel((xx, yy))
                    rs += pr; gs += pg; bs_ += pb; n += 1
        if not n:
            continue
        out.append({"fx": fx, "fy": fy, "text": b.get("text"), "name": b.get("name"),
                    "rgb": (rs // n, gs // n, bs_ // n)})
    return out


def classify_button(btn):
    """'cancel' (red X), 'ok' (green/blue check), or None -- from the colour at its own position."""
    r, g, b = btn["rgb"]
    txt = (btn.get("text") or "").strip().lower()
    if txt in ("cancel", "no", "quit", "close", "back"):
        return "cancel"
    if txt in ("ok", "yes", "done", "continue"):
        return "ok"
    if r > 140 and r > 1.5 * max(g, b, 1):
        return "cancel"
    if g > 120 and g > 1.3 * max(r, b, 1):
        return "ok"
    if b > 120 and b > 1.25 * max(r, g, 1):
        return "ok"
    return None


def unwedge(ex, hwnd, hud_names=frozenset()):
    """Clear a UI panel that is swallowing movement keys. True if something was dismissed.

    Buttons come from memory, so the only question is WHICH to press. Prefer a cancel/close control
    over a confirm one: on the title screen's "Are you ready to leave Toontown?" the red X is the
    safe answer and OK quits the game outright.

    Escape is not tried -- verified against the live token shop, which ignored it completely.
    """
    from winctl import inputs
    btns = screen_buttons(ex, hwnd)
    if not btns:
        return False
    # Ignore the permanent HUD. The chat bubble, gag, laff and book icons are DirectGUI buttons too
    # and the green chat icon classifies as a confirm control, so without this the bot would press
    # it, achieve nothing, and report that it had cleared a panel -- which also suppresses the wall
    # recovery. A panel's buttons are by definition the ones that were not there a moment ago.
    fresh = [b for b in btns if b.get("name") not in hud_names]
    if not fresh:
        return False
    ranked = []
    for b in fresh:
        kind = classify_button(b)
        if kind:
            ranked.append((0 if kind == "cancel" else 1, b, kind))
    if not ranked:
        return False
    ranked.sort(key=lambda t: t[0])
    _, btn, kind = ranked[0]
    inputs.click(hwnd, 0.20, 0.30)       # park: DirectGUI arms on mouse-ENTER
    time.sleep(0.4)
    inputs.click(hwnd, float(btn["fx"]), float(btn["fy"]))
    print("[bot] pressed %s button at %.3f,%.3f (label=%r rgb=%s)"
          % (kind, btn["fx"], btn["fy"], btn.get("text"), btn["rgb"]), flush=True)
    return True


class Keys(object):
    """Owns every held key, so there is exactly one place that can leave one stuck down."""

    def __init__(self, hwnd, dry=False):
        self.hwnd = hwnd
        self.dry = dry
        self.held = set()
        self._inputs = None
        if not dry:
            from winctl import inputs
            self._inputs = inputs

    def pulse(self, key, seconds):
        """Press, hold for `seconds`, release. The release runs even if the sleep is interrupted."""
        if self.dry:
            time.sleep(min(seconds, 0.05))
            return
        try:
            self._inputs.key_hold(self.hwnd, key, True)
            self.held.add(key)
            time.sleep(seconds)
        finally:
            try:
                self._inputs.key_hold(self.hwnd, key, False)
            except Exception:
                pass
            self.held.discard(key)

    def release_all(self):
        if self.dry:
            self.held.clear()
            return
        for k in list(self.held) + ["w", "a", "s", "d"]:
            try:
                self._inputs.key_hold(self.hwnd, k, False)
            except Exception:
                pass
        self.held.clear()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="decide and print; never press a key")
    ap.add_argument("--local", action="store_true", help="arithmetic only; never call the network")
    ap.add_argument("--timeout", type=float, default=2.0, help="per-decision network timeout (s)")
    ap.add_argument("--stall-after", type=float, default=4.0,
                    help="seconds of no progress before reporting blocked")
    ap.add_argument("--give-up", type=float, default=45.0,
                    help="seconds to chase one treasure before blacklisting it")
    ap.add_argument("--blacklist-for", type=float, default=120.0,
                    help="seconds an abandoned treasure stays ignored")
    ap.add_argument("--max-height", type=float, default=12.0,
                    help="ignore treasures more than this far above/below the toon (another level)")
    ap.add_argument("--max-backs", type=int, default=3,
                    help="consecutive reverses before sidestepping instead")
    ap.add_argument("--touch", type=float, default=3.0,
                    help="distance counted as having touched a treasure")
    ap.add_argument("--max-walk-bearing", type=float, default=25.0,
                    help="never walk forward when the bearing is worse than this; realign instead")
    ap.add_argument("--include-treasures", action="store_true",
                    help="also chase the valueless treasures (ice cream); off by default")
    ap.add_argument("--retry-after", type=float, default=5.0,
                    help="seconds before re-approaching a bag that did not collect (cooldown)")
    ap.add_argument("--frozen-pulses", type=int, default=3,
                    help="pulses with zero movement before assuming a UI panel is blocking input")
    ap.add_argument("--stopfile", default=os.path.join(os.environ.get("TEMP", "/tmp"), "beanbot-stop"))
    ap.add_argument("--max-seconds", type=float, default=0.0, help="stop after N seconds (0 = forever)")
    a = ap.parse_args()

    if os.path.exists(a.stopfile):
        os.remove(a.stopfile)
    print("[bot] turn model: %.1f deg/s (+%.1f); stop with:  echo . > %s"
          % (TURN_RATE, TURN_OVERHEAD, a.stopfile), file=sys.stderr)

    hwnd = None
    if not a.dry_run:
        from winctl import windows
        ws = windows.list_windows(cls="WinGraphicsWindow0")
        if not ws:
            raise SystemExit("beanbot: no game window (class WinGraphicsWindow0)")
        hwnd = ws[0]["hwnd"]

    session, ex = WS.attach()
    keys = Keys(hwnd, dry=a.dry_run)
    atexit.register(keys.release_all)

    stop = {"now": False}

    def _sig(_s, _f):
        stop["now"] = True
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _sig)
        except Exception:
            pass

    t_start = time.time()
    committed = None          # (x, y) of the target being chased, for hysteresis
    t_commit = time.time()    # when we committed to it, for the give-up timer
    best_dist = None
    last_progress = time.time()
    blacklist = []            # [(x, y, ignore_until)] -- treasures we could not reach
    backs = 0                 # consecutive reverses, to break the back-forever spiral
    hud_names = set()         # DirectGUI buttons present while moving freely = the permanent HUD
    hud_at = 0.0              # when that baseline was last refreshed
    closest = 1e9             # closest approach to the committed target, for fly-through detection
    last_pose = None          # (x, y, h) last tick, to notice a UI panel eating input
    frozen = 0                # consecutive pulses with no movement at all
    picked = 0

    try:
        while not stop["now"]:
            if os.path.exists(a.stopfile):
                print("[bot] stop file present -- stopping", file=sys.stderr)
                break
            if a.max_seconds and (time.time() - t_start) > a.max_seconds:
                print("[bot] max-seconds reached", file=sys.stderr)
                break

            raw = ex.state({})
            if not raw.get("ok"):
                print("[bot] state failed: %s" % raw.get("e"), file=sys.stderr)
                time.sleep(1.0)
                continue
            st = raw.get("r") or {}
            if st.get("err"):
                print("[bot] %s" % st["err"], file=sys.stderr)
                time.sleep(1.0)
                continue

            me = st["me"]

            # WEDGED: a DirectGUI panel (the Cartoonival token shop, the cattlelog) swallows WASD
            # completely, so the toon freezes with position AND heading identical across pulses --
            # observed live as twelve consecutive 90-degree turn commands with the bearing pinned
            # at -106. Heading alone is not enough to detect it, since a turn leaves position
            # unchanged by design; it is the pair being frozen that means input is going nowhere.
            # Escape does NOT close these panels (verified against the live shop); the red X does.
            pose_now = (round(me["x"], 1), round(me["y"], 1), round(me["h"], 1))
            frozen = frozen + 1 if pose_now == last_pose else 0
            last_pose = pose_now
            # Refresh the HUD baseline only while the toon is demonstrably moving, because that is
            # the one moment we know nothing is blocking input and therefore that every button on
            # screen is permanent furniture.
            if frozen == 0 and not a.dry_run and time.time() - hud_at > 30.0:
                try:
                    seen = {b.get("name") for b in screen_buttons(ex, hwnd) if b.get("name")}
                    if seen:
                        hud_names = seen
                        hud_at = time.time()
                except Exception:
                    pass
            if frozen >= a.frozen_pulses:
                print("[bot] no movement for %d pulses -- looking for a blocking UI panel" % frozen,
                      flush=True)
                frozen = 0
                if not a.dry_run and unwedge(ex, hwnd, hud_names):
                    # A real panel was in the way and is now gone; give it a clean slate.
                    print("[bot] closed a panel", flush=True)
                    best_dist = None
                    last_progress = time.time()
                    time.sleep(0.5)
                    continue
                # No panel: the toon is against scenery. Fall THROUGH deliberately rather than
                # resetting the clock -- an earlier version reset last_progress here every time,
                # which meant `stalled` never grew, `blocked` never latched, and the sidestep
                # recovery could never fire. The toon pushed into the same fence indefinitely.

            tg = []
            for t in st.get("targets", []):
                # BAGS ONLY by default. Both the jellybean bags and the Cartoonival coin bags are
                # the valued kind and both are wanted; the valueless kind is ice cream, which a
                # toon at full laff walks straight through -- chasing it is pure wasted time.
                if t["kind"] != "bag" and not a.include_treasures:
                    continue
                b, d, dz = bearing_to(me, t)
                if abs(dz) > a.max_height:
                    continue              # another level: walking its ground position never touches it
                tg.append({"bearing": round(b, 1), "distance": round(d, 1), "dz": round(dz, 1),
                           "kind": t["kind"], "value": t.get("value"), "x": t["x"], "y": t["y"]})
            if not tg:
                print("[bot] no reachable treasures in this zone -- waiting", file=sys.stderr)
                time.sleep(2.0)
                continue

            # rank by true 3D separation, so a treasure overhead is not mistaken for an adjacent one
            tg.sort(key=lambda t: math.hypot(t["distance"], t["dz"]))

            # COLLECTION IS DETECTED BY DISAPPEARANCE, not by proximity. A treasure is picked up by
            # touching its collision sphere, and being within a few units of one does not mean it
            # is gone -- an earlier version counted proximity as success and re-counted the same
            # bag every tick forever. When the object leaves doId2do, it is genuinely collected
            # (by us or by another player); either way it is no longer a target.
            cur = None
            if committed is not None:
                for t in tg:
                    if abs(t["x"] - committed[0]) < 1.0 and abs(t["y"] - committed[1]) < 1.0:
                        cur = t
                        break
                if cur is None:
                    picked += 1
                    print("[bot] COLLECTED -- %d so far" % picked, flush=True)
                    committed = None

            # Drop targets we have already failed to reach (unreachable ledges, blocked routes).
            now = time.time()
            live = [t for t in tg
                    if not any(abs(t["x"] - bx) < 1.0 and abs(t["y"] - by) < 1.0 and now < until
                               for bx, by, until in blacklist)]
            if not live:
                print("[bot] every treasure is blacklisted or gone -- waiting", file=sys.stderr)
                time.sleep(2.0)
                continue

            if cur is None or live[0]["distance"] < cur["distance"] * 0.6:
                cur = live[0]
                committed = (cur["x"], cur["y"])
                t_commit = now
                best_dist = None
                closest = cur["distance"]
                last_progress = now

            # WALKED THROUGH IT AND IT IS STILL THERE -> it is not collectible right now, so stop
            # orbiting it. Ice-cream treasures restore laff and are simply ignored by a toon at
            # full health (this one is 16/16), which looks exactly like a navigation failure: the
            # bot reaches d=0, passes through, turns around and repeats forever. Detecting the
            # fly-through needs no knowledge of WHY -- only that contact did not consume it.
            closest = min(closest, cur["distance"])
            if closest <= a.touch and cur["distance"] > a.touch * 3.0:
                # Walked through it and it is still there. For a BAG this is almost always the
                # collection cooldown -- you may only take so many in a window, and a bag taken
                # during it just plays a sound and stays put. That is temporary, so back off for a
                # few seconds and come again rather than writing the bag off for two minutes.
                # (For ice cream it is permanent-ish, hence the longer wait when chasing those.)
                wait = a.retry_after if cur["kind"] == "bag" else a.blacklist_for
                print("[bot] passed through %s at d=%.1f and it remains (cooldown?) -- retrying in "
                      "%.0fs" % (cur["kind"], closest, wait), flush=True)
                blacklist.append((cur["x"], cur["y"], now + wait))
                committed = None
                continue

            # Give up on one we cannot get to, so a bag on a ledge cannot trap the bot forever.
            if now - t_commit > a.give_up:
                print("[bot] giving up on %s at d=%.0f after %.0fs -- blacklisting for %.0fs"
                      % (cur["kind"], cur["distance"], now - t_commit, a.blacklist_for), flush=True)
                blacklist.append((cur["x"], cur["y"], now + a.blacklist_for))
                committed = None
                continue

            if best_dist is None or cur["distance"] < best_dist - 0.5:
                best_dist = cur["distance"]
                last_progress = time.time()
            stalled = time.time() - last_progress
            blocked = stalled >= a.stall_after

            payload = {
                "target": {"bearing": cur["bearing"], "distance": cur["distance"],
                           "height_difference": cur["dz"],
                           "kind": cur["kind"], "value": cur["value"]},
                "others": [{"bearing": t["bearing"], "distance": t["distance"], "kind": t["kind"]}
                           for t in tg[1:4]],
                "seconds_without_progress": round(stalled, 1),
                "progress": "blocked" if blocked else "closing",
            }

            if a.local:
                act, conf = local_decide(cur["bearing"], cur["distance"], blocked)
                via = "local"
            else:
                try:
                    act, conf = jev_decide(payload, a.timeout)
                    via = "jev"
                except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                        KeyError, ValueError) as e:
                    act, conf = local_decide(cur["bearing"], cur["distance"], blocked)
                    via = "local(%s)" % type(e).__name__
            if act not in ACTIONS:
                act, conf = local_decide(cur["bearing"], cur["distance"], blocked)
                via = "local(bad)"

            # Reversing is an ESCAPE, not a state. Backing up always increases the distance, so the
            # stall check stays latched and the toon reverses out of the zone -- observed live,
            # d=17 -> 65 and still going. After a few in a row, sidestep instead: turn 90 degrees
            # and commit to a short walk, which is what actually gets around a wall.
            backs = backs + 1 if act == "back" else 0
            if backs >= a.max_backs:
                print("[bot] %d reverses in a row is not working -- sidestepping" % backs, flush=True)
                keys.pulse("a", hold_for(90))
                keys.pulse("w", 1.0)
                backs = 0
                best_dist = None
                last_progress = time.time()
                continue

            key, dur = ACTIONS[act]
            # GUARD RAIL: never take a long blind walk while misaligned. Jev was observed choosing
            # forward_far at bearings of -96 and -144 degrees -- a 4 second run in almost the
            # opposite direction, the single worst outcome available. Offering a long leg is only
            # safe if a wrong pick degrades gracefully, so alignment decides how far we may commit.
            if key == "w" and abs(cur["bearing"]) > a.max_walk_bearing:
                act, conf = local_decide(cur["bearing"], cur["distance"], blocked)
                via += "+align"
                key, dur = ACTIONS[act]
            elif key == "w" and abs(cur["bearing"]) > 8.0:
                dur = min(dur, ACTIONS["forward"][1])      # slightly off: medium leg at most
            elif key in ("a", "d") and abs(cur["bearing"]) <= 8.0 and not blocked:
                # SYMMETRIC COUNTERPART of the align guard: when already facing the target, a turn
                # can only take us off it. This is exactly where Jev is weakest -- the smoke test
                # measured 0.39-0.50 confidence inside the forward band against 0.99 on
                # unambiguous turns -- and it was seen picking turn_left at +8 degrees, swinging
                # back out to +36. The toon then spun on the spot at a fixed distance of 183
                # forever, because it never once committed to walking.
                act, conf = local_decide(cur["bearing"], cur["distance"], blocked)
                via += "+lock"
                key, dur = ACTIONS[act]
            # Never walk past the target: clamp a forward leg to the ground it actually has to
            # cover. This is what makes the long leg safe to offer -- if Jev picks forward_far at
            # 20 units, it simply becomes a 1s walk instead of a 4s run into the scenery beyond.
            if key == "w":
                dur = min(dur, walk_for(max(cur["distance"] - a.touch * 0.5, 1.0)))
            print("[bot] %-17s conf=%.2f via=%-6s | %s d=%.0f dz=%+.1f brg=%+.0f val=%s | %s %.2fs stalled=%.1fs"
                  % (act, conf, via, cur["kind"], cur["distance"], cur["dz"], cur["bearing"],
                     cur["value"], key, dur, stalled), flush=True)
            keys.pulse(key, dur)
    finally:
        keys.release_all()
        try:
            session.detach()
        except Exception:
            pass
        print("[bot] stopped; keys released; %d treasures reached" % picked, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
