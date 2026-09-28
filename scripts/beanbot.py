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

INPUT: BACKGROUND FOR MOVEMENT, RAW ONLY FOR PANELS
    Movement goes through winctl 0.3's `background` backend, which posts window messages: it never
    takes focus and never moves the cursor, so the machine stays usable while the bot plays.
    Measured against the raw backend on this client and identical -- a 500 ms turn gives -47.4 vs
    -47.1 degrees, a 700 ms walk 14.6 vs 14.4 units.

    CLICKS are the exception and must use `raw`. Panda3D's MouseWatcher reads the real cursor
    position from the device rather than the coordinates carried in the posted message, so a
    background click is delivered but lands wherever the user's pointer happens to be -- which is
    how three separate attempts at the toon picker ended up in Make-a-Toon. Clicks are only used
    to dismiss a panel, so the brief focus blip is rare. `--inject` would remove even that, but
    needs the 64-bit winctl-hook DLL built.

SAFETY
    A key press is one winctl invocation that holds and releases, so an exception cannot strand a
    key down. `release_all` additionally taps w/a/s/d, since a tap ends in a key-up regardless of
    prior state. Stop it with the stop file rather than Ctrl+C -- per AGENTS.md the stop file is
    the only reliable stop on Windows:
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
sys.path.insert(0, HERE)
import winctl_cli as W                  # noqa: E402  -- winctl 0.3 CLI, background input

SHOTDIR = os.environ.get("TEMP", "/tmp")

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
    "back":              "clear_ahead is under 3 units, or the distance has stopped falling for several seconds, so we are up against something and must reverse",
}
INSTRUCTIONS = (
    "Steering a character toward treasure in a 3D game. Bearing is degrees relative to the way the "
    "character faces: negative is to the left, positive is to the right, 0 is dead ahead. Turns "
    "happen in place, then the character walks. NEVER choose a forward action unless the bearing "
    "is already within 8 degrees of straight ahead -- turn to face the target first. clear_ahead, "
    "clear_left and clear_right are the measured free distance in units before hitting a wall in "
    "that direction; under about 4 means blocked, so never walk forward on a small clear_ahead -- "
    "turn toward whichever side has more clearance. Prefer the target already being chased unless "
    "another is much closer. Pick the single best next action."
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


MAX_OBSTACLE_R = 15.0       # ignore colliders larger than this: zone-scale volumes, not
                            # things you steer around
BLOCKED_CLEARANCE = 4.0     # measured: at 1.4 the toon is stopped dead, at 3.1 it creeps,
                            # at 13+ it walks a full 10.5-unit leg
MOVED_ENOUGH = 1.5          # units of real movement that prove a gap is passable after all
DETOUR_CLEAR = 20.0         # clearance that counts as a way out
DETOUR_EXIT = 15.0          # clearance toward the target that ends a detour
MAX_WHISKER = 60.0          # units; beyond this, nothing is "in the way" for steering purposes


def fetch_obstacles(ex):
    """Static collision geometry as [{x, y, z, r}] in world space, or [] if unavailable.

    Walls, buildings, trees and picnic tables are CollisionNodes under `render` -- they are not
    distributed objects, which is why the bot was blind to them. getTightBounds() is useless for
    them (0 of 958 returned anything: it covers DRAWN geometry and collision solids are not drawn),
    so position comes from the node plus its bounding volume's centre and radius.

    CAVEAT: the centre is a LOCAL offset, added here without applying the node's rotation. 685 of
    763 nodes have a non-trivial offset so ignoring it is clearly worse -- it moved the count of
    obstacles within 60 units from 28 to 40 -- but a rotated parent would place it imprecisely.
    Offsets run 0-5 units against radii of 2-12, so the error is small relative to what it decides.
    """
    try:
        r = ex.collision({"static_only": True})
        if not r.get("ok"):
            return []
        out = []
        for o in (r.get("r") or {}).get("obstacles") or []:
            m = o.get("mask")
            if o.get("r") is None or m is None:
                continue
            # BARRIERS ONLY. Panda's standard bits: 0x1 wall, 0x2 floor, 0x4 camera. Without
            # this the floor itself counted as an obstacle. Also drop the sky-dome tree
            # colliders, whose bounding radius reaches 124 units and would report the whole
            # playground as blocked. Together those two made clear_ahead read 0.0 while the
            # toon walked freely -- the first version of this was measurably useless.
            if not (int(m) & 0x1):
                continue
            if o["r"] > MAX_OBSTACLE_R or "sky" in (o.get("name") or ""):
                continue
            out.append({"x": o["x"] + (o.get("cx") or 0.0),
                        "y": o["y"] + (o.get("cy") or 0.0),
                        "z": o["z"] + (o.get("cz") or 0.0),
                        "r": o["r"], "name": o.get("name")})
        return out
    except Exception:
        return []


def clearance(me, obstacles, offset_deg, max_range=MAX_WHISKER, max_dz=10.0):
    """Distance to the nearest obstacle blocking a ray at (facing + offset), else max_range.

    An obstacle of radius r at distance d subtends asin(r/d); it blocks the ray when the ray's
    bearing falls inside that cone. This is the "whisker" a steering agent actually wants, and it
    is pure arithmetic over a cached snapshot -- no C-API calls per tick.
    """
    best = max_range
    for o in obstacles:
        dz = o["z"] - me["z"]
        if abs(dz) > max_dz:
            continue                      # another floor; not in the way
        b, d, _ = bearing_to(me, o)
        if d > max_range:
            continue
        r = o["r"]
        if d <= r:
            return 0.0                    # already inside it
        half = math.degrees(math.asin(min(r / d, 1.0)))
        if abs(norm180(b - offset_deg)) <= half:
            best = min(best, d - r)
    return best


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


def screen_buttons(ex):
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
    r = ex.buttons()
    if not r.get("ok"):
        return []
    bs = (r.get("r") or {}).get("buttons") or []
    if not bs:
        return []
    win = W.game_window()
    if not win or not win.get("clientH"):
        return []
    aspect = float(win["clientW"]) / float(win["clientH"])
    im = W.shot(os.path.join(SHOTDIR, "buttons.png"))
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
                    "w": b.get("w"), "h": b.get("h"),
                    "rgb": (rs // n, gs // n, bs_ // n)})
    return out


def classify_button(btn):
    """'cancel', 'ok', or None -- what pressing this widget would do.

    SHAPE IS THE SAFETY GATE. Close and confirm controls in this game are round/square; action
    buttons are wider than they are tall. In the Cartoonival token shop the "Buy" buttons are
    0.09x0.06 and one of them samples (204, 81, 81) -- redder than the actual close X, which is
    0.15x0.15 and samples a washed-out (209, 162, 157). A colour-only rule therefore picked a Buy
    button, which would spend the player's tokens rather than close the panel. Anything clearly
    rectangular is refused outright: leaving a panel open is recoverable, buying something is not.

    Colour thresholds are RELATIVE. The trampoline dialog's OK samples (7, 94, 31) -- plainly
    green but dim -- while the bluish laff meter at (114, 118, 154) is bright and not a control at
    all, so channel dominance separates them far better than brightness.
    """
    txt = (btn.get("text") or "").strip().lower()
    if txt in ("cancel", "no", "quit", "close", "back"):
        return "cancel"
    if txt in ("ok", "yes", "done", "continue"):
        return "ok"

    w, h = btn.get("w"), btn.get("h")
    if not w or not h or max(w, h) <= 0:
        return None
    if abs(w - h) / max(w, h) > 0.25:
        return None                       # rectangular: an action button, never press it blind

    r, g, b = btn["rgb"]
    if r > 120 and r > g and r > b:
        return "cancel"
    if g > 55 and g > 1.4 * max(r, 1) and g > 1.4 * max(b, 1):
        return "ok"
    if b > 100 and b > 1.5 * max(r, 1) and b > 1.5 * max(g, 1):
        return "ok"
    return None


def _point_click(ex, fx, fy, settle=0.3):
    """Put the cursor there via Panda, then click. False if the pointer could not be placed."""
    try:
        r = ex.point({"fx": float(fx), "fy": float(fy)})
        if not r.get("ok") or not (r.get("r") or {}).get("moved"):
            return False
        time.sleep(settle)
        W.click(fx, fy, input_mode="background")
        return True
    except Exception:
        return False


def unwedge(ex, hud_names=frozenset()):
    """Clear a UI panel that is swallowing movement keys. True if something was dismissed.

    Buttons come from memory, so the only question is WHICH to press. Prefer a cancel/close control
    over a confirm one: on the title screen's "Are you ready to leave Toontown?" the red X is the
    safe answer and OK quits the game outright.

    Escape is not tried -- verified against the live token shop, which ignored it completely.
    """
    btns = screen_buttons(ex)
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
    # Panda places the cursor, we only press. base.win.movePointer() takes window-relative pixels,
    # so the pointer ends up exactly where the engine thinks it is -- no screen mapping, DPI or
    # aspect arithmetic to get wrong. Panda's MouseWatcher reads the real cursor rather than the
    # posted message's coordinates (../winctl/bugs.md #1), so a BACKGROUND click then lands on the
    # right widget without taking focus. `raw` remains only as a fallback.
    if not _point_click(ex, 0.20, 0.30):        # park: DirectGUI arms on mouse-ENTER
        W.click(0.20, 0.30, input_mode="raw")
    time.sleep(0.4)
    if not _point_click(ex, float(btn["fx"]), float(btn["fy"])):
        W.click(float(btn["fx"]), float(btn["fy"]), input_mode="raw")
    print("[bot] pressed %s button at %.3f,%.3f (label=%r rgb=%s)"
          % (kind, btn["fx"], btn["fy"], btn.get("text"), btn["rgb"]), flush=True)
    return True


class Keys(object):
    """Owns key presses. One winctl invocation does down-hold-up, so a press cannot be left open.

    Movement uses the BACKGROUND backend, which posts window messages: no focus stolen, no cursor
    moved, so the machine stays usable while the bot plays. Measured against the raw backend on
    this client and identical -- a 500 ms turn gives -47.4 vs -47.1 degrees, a 700 ms walk 14.6 vs
    14.4 units -- so nothing about the movement model changes by using it.
    """

    def __init__(self, dry=False):
        self.dry = dry

    def pulse(self, key, seconds):
        """Press `key` for `seconds`. winctl holds and releases it, so an exception here cannot
        strand a key down in the game the way a separate down/up pair could."""
        if self.dry:
            time.sleep(min(seconds, 0.05))
            return
        try:
            W.key(key, hold_ms=int(seconds * 1000))
        except Exception as e:
            print("[bot] key %s failed: %s" % (key, e), file=sys.stderr)

    def release_all(self):
        """Belt and braces: tap each movement key so any left down by an interrupted pulse is
        released. A tap ends in a key-up regardless of the prior state."""
        if self.dry:
            return
        for k in ("w", "a", "s", "d"):
            try:
                W.key(k, hold_ms=1)
            except Exception:
                pass


def run_collector(ex, a, should_stop=None, keys=None):
    """Run the collect loop until `should_stop()` or `a.max_seconds`. Returns the count.

    Factored out of main() so the INJECTOR can host it in a thread against its own frida
    session -- one attach serving both the mods and the bot, rather than two attaches on the
    same process. `a` is the argparse namespace (or anything carrying the same attributes)
    and `ex` is the worldstate RPC export object.

    It owns no session and installs nothing, so the caller decides the lifetime: standalone
    beanbot passes a signal flag, the injector passes its own stop check.
    """
    should_stop = should_stop or (lambda: False)
    keys = keys or Keys()
    t_start = time.time()
    committed = None          # (x, y) of the target being chased, for hysteresis
    t_commit = time.time()    # when we committed to it, for the give-up timer
    best_dist = None
    last_progress = time.time()
    blacklist = []            # [(x, y, ignore_until)] -- treasures we could not reach
    backs = 0                 # consecutive reverses, to break the back-forever spiral
    obstacles = []            # static wall colliders, snapshotted (they do not move)
    obs_at = 0.0              # when that snapshot was taken
    hud_names = set()         # DirectGUI buttons present while moving freely = the permanent HUD
    hud_at = 0.0              # when that baseline was last refreshed
    closest = 1e9             # closest approach to the committed target, for fly-through detection
    prev_xy = None            # previous tick's position, to measure real movement
    detour_until = 0.0        # while in the future, steer along detour_brg, not at the target
    detour_brg = 0.0
    last_pose = None          # (x, y, h) last tick, to notice a UI panel eating input
    frozen = 0                # consecutive pulses with no movement at all
    picked = 0

    try:
        while not should_stop():
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

            # Static geometry does not move, so snapshot it rather than re-reading ~875
            # colliders every tick. The scan costs ~0.04s, so refreshing periodically is cheap
            # insurance against a zone change.
            if time.time() - obs_at > a.obstacle_refresh:
                obstacles = fetch_obstacles(ex)
                obs_at = time.time()
                print("[bot] %d wall colliders" % len(obstacles), file=sys.stderr)

            # WEDGED: a DirectGUI panel (the Cartoonival token shop, the cattlelog) swallows WASD
            # completely, so the toon freezes with position AND heading identical across pulses --
            # observed live as twelve consecutive 90-degree turn commands with the bearing pinned
            # at -106. Heading alone is not enough to detect it, since a turn leaves position
            # unchanged by design; it is the pair being frozen that means input is going nowhere.
            # Escape does NOT close these panels (verified against the live shop); the red X does.
            moved_last = (math.hypot(me["x"] - prev_xy[0], me["y"] - prev_xy[1])
                          if prev_xy else 0.0)
            prev_xy = (me["x"], me["y"])
            pose_now = (round(me["x"], 1), round(me["y"], 1), round(me["h"], 1))
            frozen = frozen + 1 if pose_now == last_pose else 0
            last_pose = pose_now
            # Refresh the HUD baseline only while the toon is demonstrably moving, because that is
            # the one moment we know nothing is blocking input and therefore that every button on
            # screen is permanent furniture.
            if frozen == 0 and not a.dry_run and time.time() - hud_at > 30.0:
                try:
                    seen = {b.get("name") for b in screen_buttons(ex) if b.get("name")}
                    if seen:
                        hud_names = seen
                        hud_at = time.time()
                except Exception:
                    pass
            if frozen >= a.frozen_pulses:
                print("[bot] no movement for %d pulses -- looking for a blocking UI panel" % frozen,
                      flush=True)
                frozen = 0
                if not a.dry_run and unwedge(ex, hud_names):
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

            clear_a = clearance(me, obstacles, 0.0)
            clear_l = clearance(me, obstacles, -45.0)
            clear_r = clearance(me, obstacles, +45.0)
            clear_t = clearance(me, obstacles, cur["bearing"])

            # DETOUR. Aiming at the target every tick is what produced the ping-pong: the
            # target pulls toward the wall, the wall guard pushes away, and neither wins.
            # Observed wedged between a booth and a tree with the bag 25 units off at +6
            # degrees and 0.7 clearance across the entire front arc. The fix is ordinary
            # wall-following: COMMIT to an open heading for a few seconds and ignore the
            # target while doing it, rather than re-deciding from scratch every tick.
            if now < detour_until:
                if clear_t > DETOUR_EXIT:
                    detour_until = 0.0
                    print("[bot] detour done -- line to target is clear", flush=True)
            elif clear_t < BLOCKED_CLEARANCE and stalled > a.stall_after * 0.5:
                best = None
                for off in (45.0, -45.0, 90.0, -90.0, 135.0, -135.0):
                    c = clearance(me, obstacles, off)
                    if c > DETOUR_CLEAR and (best is None or abs(off) < abs(best[0])):
                        best = (off, c)
                if best:
                    # Store the detour as an ABSOLUTE world heading, not a relative offset. Holding
                    # it relative meant re-applying "45 degrees right" every tick: the toon turned,
                    # the offset stayed 45, and it spun a full circle without ever walking
                    # (observed: +29 +58 +88 +117 +148 +178 -152, mv0.0 throughout). Panda heading
                    # increases to the LEFT while these bearings are positive to the RIGHT, hence
                    # the subtraction.
                    detour_brg = me["h"] - best[0]
                    detour_until = now + a.detour_seconds
                    print("[bot] blocked toward target (clr %.1f) -- detouring %+.0f deg for %.0fs"
                          % (clear_t, best[0], a.detour_seconds), flush=True)

            # Relative bearing to the detour heading: it shrinks to 0 as the toon comes round to
            # face it, so the controller stops turning and starts walking -- which is the whole
            # point of committing to a heading.
            steer_brg = (norm180(me["h"] - detour_brg) if now < detour_until else cur["bearing"])

            payload = {
                "target": {"bearing": cur["bearing"], "distance": cur["distance"],
                           "height_difference": cur["dz"],
                           "kind": cur["kind"], "value": cur["value"]},
                "others": [{"bearing": t["bearing"], "distance": t["distance"], "kind": t["kind"]}
                           for t in tg[1:4]],
                "seconds_without_progress": round(stalled, 1),
                "progress": "blocked" if blocked else "closing",
                "clear_ahead": round(clear_a, 1),
                "clear_toward_target": round(clear_t, 1),
                "moved_last_step": round(moved_last, 1),
                "clear_left": round(clear_l, 1),
                "clear_right": round(clear_r, 1),
            }

            if a.local:
                act, conf = local_decide(steer_brg, cur["distance"], blocked)
                via = "local"
            else:
                try:
                    act, conf = jev_decide(payload, a.timeout)
                    via = "jev"
                except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                        KeyError, ValueError) as e:
                    act, conf = local_decide(steer_brg, cur["distance"], blocked)
                    via = "local(%s)" % type(e).__name__
            if act not in ACTIONS:
                act, conf = local_decide(steer_brg, cur["distance"], blocked)
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

            # A detour overrides the model entirely: Jev is still aiming at the target and has
            # no idea we are deliberately walking around something.
            if now < detour_until:
                act, conf = local_decide(steer_brg, 999.0, False)
                via += "+detour"
            key, dur = ACTIONS[act]

            # Reversing is rarely the answer when a side is plainly open. Observed at
            # clr L36 A3 R3: it backed up, crept forward, backed up again, and only escaped
            # via the blind sidestep, with 36 units of room to its left the whole time.
            if key == "s":
                side = max(clear_l, clear_r)
                if side > 10.0 and side > 2.0 * clear_a:
                    act = "turn_left" if clear_l >= clear_r else "turn_right"
                    conf, via = 1.0, via + "+open"
                    key, dur = ACTIONS[act]

            # WALL GUARD -- but only when the toon is ALSO failing to move. Obstacles are
            # modelled as their BOUNDING SPHERES, which are far fatter than a flat booth wall,
            # so a gap the toon comfortably fits through can read as 0.7 clearance. Measured
            # movement is ground truth and predicted clearance is only a hint: if clearance
            # says blocked while the toon is visibly moving, keep going.
            if key == "w" and clear_a < BLOCKED_CLEARANCE and moved_last < MOVED_ENOUGH:
                act = "turn_left" if clear_l >= clear_r else "turn_right"
                conf, via = 1.0, via + "+wall"
                key, dur = ACTIONS[act]
            # ALIGNMENT GUARD: never take a long blind walk while badly misaligned. Jev was
            # seen choosing forward_far at -96 and -144 degrees -- a 4 second run in nearly the
            # opposite direction, the worst outcome available.
            elif key == "w" and abs(steer_brg) > a.max_walk_bearing:
                act, conf = local_decide(steer_brg, cur["distance"], blocked)
                via += "+align"
                key, dur = ACTIONS[act]
            elif key == "w" and abs(steer_brg) > 8.0:
                dur = min(dur, ACTIONS["forward"][1])      # slightly off: medium leg at most
            # SYMMETRIC COUNTERPART: when already facing the target, a turn can only take us
            # off it. This is where Jev is weakest -- 0.39-0.50 confidence inside the forward
            # band against 0.99 on unambiguous turns -- and it picked turn_left at +8 degrees,
            # swinging back out to +36 and spinning on the spot at a fixed distance of 183.
            elif key in ("a", "d") and abs(steer_brg) <= 8.0 and not blocked:
                act, conf = local_decide(steer_brg, cur["distance"], blocked)
                via += "+lock"
                key, dur = ACTIONS[act]
            # Never walk past the target: clamp a forward leg to the ground it actually has to
            # cover. This is what makes the long leg safe to offer -- if Jev picks forward_far at
            # 20 units, it simply becomes a 1s walk instead of a 4s run into the scenery beyond.
            if key == "w":
                dur = min(dur, walk_for(max(cur["distance"] - a.touch * 0.5, 1.0)))
                # Never walk further than the free space ahead -- unless we are demonstrably
                # moving, in which case the sphere model is being pessimistic about a gap.
                if moved_last < MOVED_ENOUGH:
                    dur = min(dur, walk_for(max(clear_a - 1.0, 1.0)))
            print("[bot] %-17s conf=%.2f via=%-11s | %s d=%.0f brg=%+.0f val=%s | clr L%.0f A%.0f R%.0f T%.0f mv%.1f | %s %.2fs stall=%.1fs"
                  % (act, conf, via, cur["kind"], cur["distance"], cur["bearing"],
                     cur["value"], clear_l, clear_a, clear_r, clear_t, moved_last,
                     key, dur, stalled), flush=True)
            keys.pulse(key, dur)
    finally:
        keys.release_all()
    return picked


def build_parser():
    """The CLI surface, in one place so every default has a single definition.

    `default_options()` reuses it, which is how the injector ends up with exactly the same
    defaults as the standalone bot without a second copy of every number.
    """
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
    ap.add_argument("--detour-seconds", type=float, default=6.0,
                    help="how long to commit to a detour heading before re-aiming at the target")
    ap.add_argument("--obstacle-refresh", type=float, default=30.0,
                    help="seconds between re-snapshotting the static collision geometry")
    ap.add_argument("--frozen-pulses", type=int, default=3,
                    help="pulses with zero movement before assuming a UI panel is blocking input")
    ap.add_argument("--stopfile", default=os.path.join(os.environ.get("TEMP", "/tmp"), "beanbot-stop"))
    ap.add_argument("--max-seconds", type=float, default=0.0, help="stop after N seconds (0 = forever)")
    return ap


def default_options(**overrides):
    """An options namespace carrying the CLI defaults, optionally overridden."""
    a = build_parser().parse_args([])
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


def main():
    ap = build_parser()
    a = ap.parse_args()

    if os.path.exists(a.stopfile):
        os.remove(a.stopfile)
    print("[bot] turn model: %.1f deg/s (+%.1f); stop with:  echo . > %s"
          % (TURN_RATE, TURN_OVERHEAD, a.stopfile), file=sys.stderr)

    if not a.dry_run:
        if not W.available():
            raise SystemExit("beanbot: winctl not found at %s (set WINCTL_EXE)" % W.WINCTL)
        if not W.game_window():
            raise SystemExit("beanbot: no game window (class WinGraphicsWindow0)")

    session, ex = WS.attach()
    keys = Keys(dry=a.dry_run)
    atexit.register(keys.release_all)

    stop = {"now": False}

    def _sig(_s, _f):
        stop["now"] = True
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _sig)
        except Exception:
            pass

    try:
        picked = run_collector(ex, a, should_stop=lambda: stop["now"], keys=keys)
    finally:
        try:
            session.detach()
        except Exception:
            pass
    print("[bot] stopped; keys released; %d treasures reached" % picked, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
