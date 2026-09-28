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

COLLECTION COOLDOWN (measured in-game, not guessed)
    Bags are hard rate limited, and the rule is not a rolling window:

      * the first ~3 pickups are free, and the clock starts at the FIRST of them
      * from then on it is ONE pickup per ~60s, timed from the last successful one
      * waiting longer than the cooldown does not bank credit -- it stays 1/min

    So the bot does what a player does: walk to the next bag, STOP a few units short of it, wait
    out the timer, and step in exactly when it expires. Flying through a bag while on cooldown
    achieves nothing (it only plays a sound) and used to send the bot wandering off to another bag
    to fail there too, which is most of what it did between pickups.

CONTROL LAW: align, then advance
    Every action is a discrete pulse -- press a key, hold it for a MEASURED duration, release.
    Turns happen in place (a/d alone), never while walking, so a turn and a translation can never
    confound each other. The loop re-reads the world after each pulse, so any residual error is
    corrected on the next tick rather than accumulating.

DURATIONS ARE MEASURED, NOT GUESSED
    `scripts/calibrate.py` holds a key for a set time and reads the heading delta out of
    memory. On this client, through the in-process input path, it fits over both directions and
    7 durations (and 5 walk durations):

        degrees = 93.2 * seconds + 0.9        (repeat spread < 2 deg, left/right within 1%)
        units   = 20.6 * seconds + 0.2        (repeat spread < 0.5 units)

    The first version of this bot held the turn key for a whole 500 ms tick regardless of the
    correction needed -- i.e. ~47 degrees every time -- which made it zig-zag violently past every
    target. Re-run the calibration if the client's turn rate ever changes, and update TURN_RATE.

WHAT JEV IS AND IS NOT DOING
    Mapping a bearing to a turn is arithmetic, and `local_decide()` does exactly that as the
    fallback whenever the network is slow or down. Jev's value is the judgement around it: which
    treasure to commit to, when to abandon one that is not getting closer, when to reverse. Its
    accuracy depends on the criteria carrying EXPLICIT NUMERIC BANDS -- measured at 10/10 against
    arithmetic with bands, 5/10 with vague wording. Do not soften them.

ROUTES, NOT REFLEXES
    The zone's walls are read exactly from the client's collision geometry (polygon edges plus the
    spheres/capsules of posts and trunks) and `nav.py` plans a route through them before setting
    off; the bot then steers at the furthest point of that route it can see. Aiming straight at
    the bag and relying on reflexes to get round what was in between could not work whenever the
    way to a bag starts by walking AWAY from it -- in the Cartoonival entrance corridor, with a bag
    off to one side, every reflex pointed back into the corridor's long side wall. The whiskers
    and wall guard remain, but only as reflexes for what the map does not know (other toons).

INPUT: IN-PROCESS, NOTHING OUTSIDE THE GAME
    Keys are pressed on the game window's own input device and buttons are pressed by queueing
    their click event, both through the same frida session that reads the world (worldstate's
    keyHold / press). No external tool, no focus change, no cursor movement -- the machine stays
    fully usable, and a click can no longer land wherever the user's pointer happens to be (which
    is how the out-of-process version once clicked into Make-a-Toon). Measured identical to real
    keys: 0.5s of 'a' turns 46.7 deg (model 47.5), 0.7s of 'w' walks 14.60 units.

SAFETY
    The AGENT releases every key on its own timer, so a host that dies mid-hold cannot strand a key
    down, and the script releases anything still held when it is unloaded. Stop it with the stop
    file rather than Ctrl+C -- per AGENTS.md the stop file is the only reliable stop on Windows:
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
import re
import signal
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "frida"))
import worldstate as WS                 # noqa: E402  -- world reader + in-process input
sys.path.insert(0, HERE)
import nav                              # noqa: E402  -- route planning over the real walls

API = "https://classifier.dev/v1/systemone"
MODEL = "jev-latest"                    # bare 'jev' is rejected: unpriced_model

# --- measured by scripts/calibrate.py against this client -----------------------------------
TURN_RATE = 93.2        # degrees per second of held a/d   (fit spread < 2 deg, L/R within 1%)
TURN_OVERHEAD = 0.9     # fixed degrees per pulse (key latency + accel ramp); small but real
WALK_SPEED = 20.6       # units per second of held w
WALK_OVERHEAD = 0.2     # fixed units per pulse


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
    "Steering a character toward treasure in a 3D game. The target is the next corner of a route "
    "already planned around the walls, so steer straight at it. Bearing is degrees relative to the "
    "way the character faces: negative is to the left, positive is to the right, 0 is dead ahead. Turns "
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


MOVED_ENOUGH = 1.5          # units of real movement that prove a gap is passable after all
BLOCKED_CLEARANCE = 4.0     # measured: at 1.4 the toon is stopped dead, at 3.1 it creeps,
                            # at 13+ it walks a full 10.5-unit leg
FREE_PICKUPS = 3            # collected freely before the rate limit engages
COOLDOWN_S = 60.0           # seconds between pickups once it has
TRAVEL_SLACK = 4.0          # seconds of margin for turning when timing the departure
# TRIGGERS the toon must never walk into, matched by NAME because their collide masks vary and
# at least the tunnel's is not a wall mask -- which is how the bot walked straight into
# tunnel_trigger_oz on a detour and ended up in another zone. Each maps to a safety margin added
# to the trigger's own radius. Inventory from Cartoonival: a zone-exit tunnel, the trampoline
# minigame, the picnic-table seats that start Picnic Games, fishing spots, and the cannons.
NO_GO = (
    ("tunnel_trigger", 8.0),
    ("TrampolineTrigger", 4.0),
    ("picnicTable_sphere", 2.0),
    ("FishingSpotSphere", 3.0),
    ("Cannon-", 3.0),
    ("target_trigger", 2.0),
)
MAX_WHISKER = 60.0          # units; beyond this, nothing is "in the way" for steering purposes


def fetch_nogo(ex):
    """No-go TRIGGERS as [{x, y, z, r, name, nogo}] in world space, or [] if unavailable.

    Only triggers. Walls used to come from here too, as each collision node's BOUNDING SPHERE --
    far fatter than a flat booth wall, so gaps the toon fits through read as blocked. Walls now
    come exactly from `worldstate.fetch_walls`; a trigger is a single sphere anyway, so its bounding
    sphere is the right shape. Position is the node plus its bounding volume's (local) centre.
    """
    try:
        r = ex.collision({"static_only": True})
        if not r.get("ok"):
            return []
        out = []
        for o in (r.get("r") or {}).get("obstacles") or []:
            if o.get("r") is None:
                continue
            name = o.get("name") or ""
            margin = next((mg for pat, mg in NO_GO if pat in name), None)
            if margin is not None:
                out.append({"x": o["x"] + (o.get("cx") or 0.0),
                            "y": o["y"] + (o.get("cy") or 0.0),
                            "z": o["z"] + (o.get("cz") or 0.0),
                            "r": o["r"] + margin, "name": name, "nogo": True})
        return out
    except Exception:
        return []


BODY_RADIUS = 1.2           # the toon's own half-width: a wall this close along the ray is contact


def _ray(me, offset_deg):
    ang = math.radians(me["h"] - offset_deg)       # bearings are positive-right; Panda H is CCW
    return -math.sin(ang), math.cos(ang)


def seg_clearance(me, walls, offset_deg, max_range=MAX_WHISKER):
    """Distance along a whisker to the nearest wall SEGMENT, else max_range.

    These are the real wall polygons' edges, read from the scene graph, so a whisker hits the
    actual surface. Walls entirely below the feet (curbs) or above the head (awnings) are ignored
    via each polygon's z-range.
    """
    dx, dy = _ray(me, offset_deg)
    mx, my = me["x"], me["y"]
    best = max_range
    for w in walls:
        if not nav.in_band(w[4], w[5], me["z"]):
            continue
        t = nav._ray_seg(mx, my, dx, dy, w[0], w[1], w[2], w[3])
        if t is not None and t < best:
            best = t
    return max(best - BODY_RADIUS, 0.0)


def round_clearance(me, rounds, offset_deg, max_range=MAX_WHISKER):
    """Distance along a whisker to the nearest round solid (post, trunk), else max_range."""
    dx, dy = _ray(me, offset_deg)
    best = max_range
    for rd in rounds:
        if not nav.in_band(rd[4], rd[5], me["z"]):
            continue
        t = nav.round_hit(me["x"], me["y"], dx, dy, rd)
        if t is not None and t < best:
            best = t
    return max(best - BODY_RADIUS, 0.0)


def nogo_clearance(me, nogo, offset_deg, max_range=MAX_WHISKER, max_dz=10.0):
    """Free distance along a whisker before entering a TRIGGER (tunnel, minigame, seat).

    From INSIDE a trigger's ring (arriving out of a tunnel lands you there), a direction leading
    out is free and one leading further in is not. Reporting 0 for every direction -- what a plain
    "am I inside it" test does -- would veto every step and leave the toon spinning in place.
    """
    dx, dy = _ray(me, offset_deg)
    mx, my = me["x"], me["y"]
    best = max_range
    for o in nogo:
        if abs(o["z"] - me["z"]) > max_dz:
            continue
        fx, fy = mx - o["x"], my - o["y"]
        if fx * fx + fy * fy <= o["r"] * o["r"]:
            if fx * dx + fy * dy < 0.0:            # heading deeper in
                return 0.0
            continue
        t = nav._ray_circle(mx, my, dx, dy, o["x"], o["y"], o["r"])
        if t is not None and t < best:
            best = t
    return best


def in_nogo(pt, nogo):
    """True if a point lies inside any trigger's no-go radius."""
    for o in nogo:
        if math.hypot(pt["x"] - o["x"], pt["y"] - o["y"]) < o["r"]:
            return True
    return False


def clearance(me, nogo, walls, rounds, offset_deg, max_range=MAX_WHISKER):
    """Free distance along a whisker: the nearest of walls, round solids and triggers."""
    return min(seg_clearance(me, walls or [], offset_deg, max_range),
               round_clearance(me, rounds or [], offset_deg, max_range),
               nogo_clearance(me, nogo or [], offset_deg, max_range))


def next_pickup_allowed(collect_times, free=FREE_PICKUPS, cooldown=COOLDOWN_S):
    """Unix time the next pickup will succeed, given the times of previous ones.

    The rule, from in-game testing: the first `free` pickups are unrestricted and the clock starts
    at the FIRST of them; after that it is one per `cooldown`, re-armed by each success. It is NOT
    a rolling window -- once the limit engages, earlier pickups ageing out does not buy a burst,
    and idling longer than the cooldown banks nothing.
    """
    if len(collect_times) < free:
        return 0.0                         # no restriction yet
    # While exactly at the free limit the anchor is the FIRST pickup; after that, the latest one.
    anchor = collect_times[0] if len(collect_times) == free else collect_times[-1]
    return anchor + cooldown


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


def button_list(ex):
    """[{name, x, z, w, h, text, geom, active}] of visible DirectGUI buttons, in aspect2d units.

    Memory only. Names and positions come from the scene graph, so building the HUD baseline
    cannot fail for a capture reason -- an empty baseline makes every HUD button look new, and the
    bot once "dismissed" the Friends List and Shticker Book buttons that way.
    """
    r = ex.buttons()
    if not r.get("ok"):
        return []
    out = []
    for b in (r.get("r") or {}).get("buttons") or []:
        if b.get("x") is None or b.get("z") is None:
            continue
        out.append({"name": b.get("name") or "", "x": b["x"], "z": b["z"],
                    "w": b.get("w"), "h": b.get("h"), "text": b.get("text"),
                    "geom": b.get("geom") or [], "active": b.get("active")})
    return out


def _pos_key(b):
    """Coarse screen position (aspect2d units, ~1% of the screen per step). HUD buttons keep their
    POSITION even when the game rebuilds them under a new pg id, so position is the identity that
    survives; the name is only a hint."""
    return (int(round(b["x"] / 0.035)), int(round(b["z"] / 0.02)))


# What a button's ART is called says what it does. Model node names are not vault-hashed:
# 'CloseBtn_UP' is the Friends List's X, 'ChtBx_OKBtn_UP' the stock OK. 'close(?!d)' because
# 'FriendsBox_Closed' is the Friends HUD button -- a state, not an action. No 'check': that is
# a checkbox, and pressing one changes a setting.
CANCEL_ART = re.compile(r"close(?!d)|cancel|exit|quit|(^|[^a-z])x(btn|button)?([^a-z]|$)", re.I)
OK_ART = re.compile(r"okbtn|(^|[^a-z])ok([^a-z]|$)|yes|confirm|done", re.I)


def classify_button(btn):
    """'cancel', 'ok', or None -- what pressing this widget would do.

    By its visible LABEL first, then by the NAME OF ITS ART. Never by colour: that needed a
    screenshot, and colour alone once picked a red Buy button in the Cartoonival token shop, which
    would have spent the player's tokens rather than closed the panel.

    SHAPE STAYS A SAFETY GATE for anything identified by art. Close and confirm controls here are
    round/square; action buttons (Buy, Play) are wider than they are tall. Leaving a panel open is
    recoverable, pressing the wrong button may not be.
    """
    if btn.get("active") is False:
        return None                       # greyed out: a player could not press it either
    txt = (btn.get("text") or "").strip().lower()
    if txt in ("cancel", "no", "quit", "close", "back", "exit"):
        return "cancel"
    if txt in ("ok", "yes", "done", "continue"):
        return "ok"

    art = " ".join(btn.get("geom") or [])
    if not art:
        return None
    w, h = btn.get("w"), btn.get("h")
    if not w or not h or max(w, h) <= 0:
        return None
    if abs(w - h) / max(w, h) > 0.25:
        return None                       # rectangular: an action button, never press it blind
    if CANCEL_ART.search(art):
        return "cancel"
    if OK_ART.search(art):
        return "ok"
    return None


def unwedge(ex, hud, duds):
    """Dismiss a panel that is swallowing movement. True ONLY if a press demonstrably did something.

    Hard rules, each from an observed failure:
      * No baseline, no press. Without knowing what the permanent HUD is, every button looks new.
      * A HUD button is never a candidate -- matched by name OR screen position, since the game
        can rebuild its HUD under new ids.
      * No new buttons means no panel: the toon is stuck on a WALL, and pressing anything is wrong.
      * Verify. A press that leaves the button on screen achieved nothing; after a few tries that
        button goes on a dud list and is not pressed again.

    The press itself is in-process (worldstate's `press`): the button's own click event is queued
    for the game to dispatch, exactly as a real click would be. No pointer is involved at all.
    """
    if not hud["names"] and not hud["pos"]:
        return False
    btns = button_list(ex)
    now = time.time()
    fresh = [b for b in btns
             if b.get("name") not in hud["names"] and _pos_key(b) not in hud["pos"]
             and duds["until"].get(_pos_key(b), 0) < now]
    if not fresh:
        return False
    ranked = []
    for b in fresh:
        kind = classify_button(b)
        if kind:
            ranked.append((0 if kind == "cancel" else 1, b, kind))
    if not ranked:
        print("[bot] a panel is up but none of its %d buttons is recognisably close/OK: %s"
              % (len(fresh), "; ".join("%s %s" % (b.get("text") or "-", "/".join(b["geom"][:2]) or "-")
                                      for b in fresh[:6])), flush=True)
        return False
    ranked.sort(key=lambda t: t[0])
    _, btn, kind = ranked[0]
    target = (btn["name"], _pos_key(btn))
    what = "%s (%s)" % (kind, btn.get("text") or "/".join(btn["geom"][:2]))

    try:
        res = ex.press({"name": btn["name"]})
        r = res.get("r") or {}
        if not res.get("ok") or r.get("err"):
            print("[bot] could not press %s: %s" % (what, r.get("err") or res.get("e")), flush=True)
            return False
    except Exception as e:
        print("[bot] could not press %s: %r" % (what, e), flush=True)
        return False

    # SUCCESS = THE BUTTON WE PRESSED WENT AWAY. A close control disappears with its panel; a
    # page-turn arrow or a "Play" button does not, so this cannot mistake navigating a panel for
    # dismissing it. Poll rather than wait a fixed time: panels animate shut, and a fixed 0.8s
    # check once judged the Picnic Games X -- the right button -- a dud.
    deadline = time.time() + 2.5
    while time.time() < deadline:
        time.sleep(0.25)
        if target not in {(b["name"], _pos_key(b)) for b in button_list(ex)}:
            duds["tries"].pop(target[1], None)
            print("[bot] pressed %s -- panel closed" % what, flush=True)
            return True

    # Not gone. A press during a panel's opening animation can be ignored, so allow a few tries
    # before writing the button off -- but only ever re-press the SAME button: after a panel
    # closes a different one can appear in that exact spot.
    n = duds["tries"].get(target[1], 0) + 1
    duds["tries"][target[1]] = n
    if n >= 3:
        duds["until"][target[1]] = time.time() + 120.0
        print("[bot] pressed %s %d times with no effect -- leaving it alone" % (what, n), flush=True)
    else:
        print("[bot] pressed %s, no effect yet (try %d of 3)" % (what, n), flush=True)
    return False


class Keys(object):
    """Owns key presses, made IN-PROCESS on the game window's own input device (worldstate's
    keyHold): no focus stolen, no cursor moved, nothing outside the game involved.

    The AGENT releases each key on its own timer, so nothing this side can strand one down; the
    host only waits out the hold (plus a frame or two for the release to be processed) so the
    next world read sees where the pulse actually left the toon.
    """
    SETTLE = 0.05

    def __init__(self, ex, dry=False):
        self.ex = ex
        self.dry = dry

    def pulse(self, key, seconds):
        """Hold `key` for `seconds`, returning once it has been released."""
        if self.dry:
            time.sleep(min(seconds, 0.05))
            return
        try:
            r = self.ex.key_hold(key, int(round(seconds * 1000)))
            if not r.get("ok"):
                print("[bot] key %s failed: %s" % (key, r.get("e")), file=sys.stderr)
        except Exception as e:
            print("[bot] key %s failed: %r" % (key, e), file=sys.stderr)
        time.sleep(seconds + self.SETTLE)

    def release_all(self):
        """Release anything this bot is holding (and nothing it is not)."""
        if self.dry:
            return
        try:
            self.ex.keys_release()
        except Exception:
            pass


def _nogo_sig(nogo):
    return sorted((round(o["x"]), round(o["y"]), round(o["r"])) for o in nogo)


def choose_target(grid, me, cands, limit):
    """Pick the bag with the SHORTEST ROUTE. Returns (best, unreachable).

    best is (target, route, route_length) or None; unreachable lists targets with no way through.
    Candidates arrive nearest-first by straight line, and a straight line is never longer than the
    route, so the search stops as soon as the next candidate cannot possibly win -- usually after
    planning one or two. Nearest-by-straight-line alone is how the bot picked the bag on the other
    side of the entrance corridor's wall over one it could simply walk to.
    """
    best, unreachable = None, []
    for t in cands[:limit]:
        if best is not None and t["distance"] >= best[2]:
            break
        r = grid.plan(me["x"], me["y"], t["x"], t["y"]) if grid else None
        if grid and r is None:
            unreachable.append(t)
            continue
        L = r.remaining(me["x"], me["y"]) if r else t["distance"]
        if best is None or L < best[2]:
            best = (t, r, L)
    return best, unreachable


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
    keys = keys or Keys(ex, dry=a.dry_run)
    t_start = time.time()
    committed = None          # (x, y) of the target being chased, for hysteresis
    t_commit = time.time()    # when we committed to it, for the give-up timer
    best_dist = None          # shortest ROUTE distance left so far, for the progress check
    walk_stall = 0.0          # seconds spent WALKING since that last improved
    blacklist = []            # [(x, y, ignore_until)] -- treasures we could not reach
    backs = 0                 # consecutive reverses, to break the back-forever spiral
    nogo = []                 # trigger spheres (tunnel mouths, minigame seats), snapshotted
    nogo_at = 0.0             # when that snapshot was taken
    walls, rounds = [], []    # the zone's wall geometry, one fetch per zone
    walls_at = 0.0            # when it was fetched
    walls_xy = None           # toon position at the last tick, to spot a zone change
    grid = None               # nav.NavGrid for this zone at the toon's height (False: failed)
    route = None              # nav.Route to the committed bag
    route_at = 0.0            # when it was planned
    reeval_at = 0.0           # when we last checked whether a nearer bag is worth switching to
    zone_changed_at = 0.0     # when we last jumped zones, to back out of a wrong one
    backouts = 0              # attempts to walk back out, so a genuine move is not fought forever
    hud = {"names": set(), "pos": set()}   # buttons present while moving freely = the permanent HUD
    hud_at = 0.0              # when that baseline was last refreshed
    duds = {"tries": {}, "until": {}}   # per screen position: presses without effect, and a
                                        # time before which that button is left alone
    closest = 1e9             # closest approach to the committed target, for fly-through detection
    prev_xy = None            # previous tick's position, to measure real movement
    collect_times = []        # unix time of each successful pickup, for the cooldown model
    committed_dist = None     # distance to the committed bag last tick, to tell ours from theirs
    last_act = None           # (key, seconds, heading before) of the previous pulse
    prev_act = None           # the same, kept for this tick's progress check
    dead_turns = 0            # consecutive turn pulses that did not turn
    wait_said = 0.0           # last time the 'waiting' line was printed, to keep the log readable
    frozen = 0
    picked = 0

    try:
        while not should_stop():
            if a.stopfile and os.path.exists(a.stopfile):
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
            now = time.time()

            # A jump of more than ~200 units between ticks is a teleport or tunnel, i.e. a new
            # zone: everything static is re-read AT ONCE. (Triggers used to wait for a 30s timer,
            # which left the old zone's tunnel positions in force after arriving somewhere new.)
            jumped = walls_xy is not None and math.hypot(me["x"] - walls_xy[0],
                                                         me["y"] - walls_xy[1]) > 200.0
            walls_xy = (me["x"], me["y"])
            if jumped:
                zone_changed_at = now
                route = None
            if jumped or not nogo_at or now - nogo_at > a.obstacle_refresh:
                fresh = fetch_nogo(ex)
                nogo_at = now
                if _nogo_sig(fresh) != _nogo_sig(nogo):
                    nogo = fresh
                    grid = None
            # Wall geometry: the whole zone is ~700 segments and 0.2s to read, so fetch it ONCE per
            # zone rather than repeatedly -- each read leaks a few thousand small objects (no
            # Py_DecRef in the Windows table). The timed refresh is only insurance.
            if not walls or jumped or now - walls_at > a.wall_refresh:
                try:
                    walls, rounds, _wst = WS.fetch_walls(ex, me["x"], me["y"], rng=5000.0)
                    print("[bot] %d wall segments, %d round solids, %d no-go triggers in this zone%s"
                          % (len(walls), len(rounds), len(nogo), " (zone change)" if jumped else ""),
                          file=sys.stderr)
                except Exception as e:
                    print("[bot] wall fetch failed: %r -- steering without a map" % (e,),
                          file=sys.stderr)
                walls_at = now
                grid = None
            # The map is built for the height the toon stands at (walls count only if they span
            # its feet-to-head band), so climbing or dropping a few units means rebuilding it.
            if grid is None or (grid and abs(me["z"] - grid.z) > a.replan_height):
                try:
                    grid = nav.NavGrid(walls, rounds, nogo, me["z"], include=[(me["x"], me["y"])])
                except Exception as e:
                    print("[bot] cannot build a route map (%r) -- steering without one" % (e,),
                          file=sys.stderr)
                    grid = False
                route = None

            # A DirectGUI panel (the Cartoonival token shop, Picnic Games) swallows WASD completely.
            moved_last = (math.hypot(me["x"] - prev_xy[0], me["y"] - prev_xy[1])
                          if prev_xy else 0.0)
            prev_xy = (me["x"], me["y"])
            # Refresh the HUD baseline only while the toon has demonstrably MOVED this tick: that
            # is the one moment we know nothing is blocking input and therefore that every button
            # on screen is permanent furniture. (Taken while seated at a picnic table, the Picnic
            # Games X became "permanent HUD" and was never pressed again.)
            if moved_last >= MOVED_ENOUGH and not a.dry_run and now - hud_at > 30.0:
                try:
                    seen = button_list(ex)
                    if seen:
                        first = not hud["pos"]
                        hud = {"names": {b["name"] for b in seen if b["name"]},
                               "pos": {_pos_key(b) for b in seen}}
                        hud_at = now
                        if first:
                            print("[bot] HUD baseline: %d buttons" % len(seen), file=sys.stderr)
                except Exception as e:
                    print("[bot] HUD baseline failed: %r" % (e,), file=sys.stderr)
            # SWALLOWED INPUT is recognised by a TURN that did not turn. A wall stops walking but
            # never stops turning on the spot, so this can only mean a panel (or a seated
            # minigame) is eating the keys. "Pose unchanged for N ticks" was the earlier test, and
            # a wall satisfies it too -- which sent the bot pressing HUD buttons.
            if last_act is not None and last_act[0] in ("a", "d") and not a.dry_run:
                expect = TURN_RATE * last_act[1] + TURN_OVERHEAD
                got = abs(norm180(me["h"] - last_act[2]))
                dead_turns = dead_turns + 1 if got < 0.25 * expect else 0
            prev_act, last_act = last_act, None
            frozen = a.frozen_pulses if dead_turns >= 2 else 0
            if frozen >= a.frozen_pulses:
                dead_turns = 0
                print("[bot] turns are not turning -- a panel is eating input; looking for its "
                      "close button", flush=True)
                frozen = 0
                if not a.dry_run and unwedge(ex, hud, duds):
                    best_dist = None
                    time.sleep(0.5)
                    continue
                # No panel: the toon is against scenery. Fall THROUGH deliberately rather than
                # resetting the clock, so `stalled` keeps growing and the recovery can fire.

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
                if in_nogo(t, nogo):
                    continue              # sitting in a trigger: fetching it would start a minigame
                tg.append({"bearing": round(b, 1), "distance": round(d, 1), "dz": round(dz, 1),
                           "kind": t["kind"], "value": t.get("value"), "x": t["x"], "y": t["y"]})
            if not tg and now - zone_changed_at < 20.0 and backouts < 2:
                # We just changed zones and there is nothing to collect here: the bot walked into
                # a tunnel. Arriving leaves the toon facing away from the tunnel it came through,
                # so walking BACKWARDS a few steps re-enters it and returns us.
                backouts += 1
                print("[bot] left the bag zone (no bags here) -- walking back out, try %d"
                      % backouts, flush=True)
                keys.pulse("s", 1.5)
                time.sleep(3.0)
                continue
            if tg:
                backouts = 0
            if not tg:
                print("[bot] no reachable treasures in this zone -- waiting", file=sys.stderr)
                time.sleep(2.0)
                continue

            # rank by true 3D separation, so a treasure overhead is not mistaken for an adjacent one
            tg.sort(key=lambda t: math.hypot(t["distance"], t["dz"]))

            # COLLECTION IS DETECTED BY DISAPPEARANCE, not by proximity: when the object leaves
            # doId2do it is genuinely collected -- by us or by another player.
            cur = None
            if committed is not None:
                for t in tg:
                    if abs(t["x"] - committed[0]) < 1.0 and abs(t["y"] - committed[1]) < 1.0:
                        cur = t
                        break
                if cur is None:
                    # Vanishing is ALSO what happens when another player takes it. Only a bag that
                    # vanished while we were within reach is ours; crediting the others both lied
                    # in the tally and re-armed the cooldown for a pickup we never made.
                    if committed_dist is not None and committed_dist <= a.touch * 4.0:
                        picked += 1
                        collect_times.append(time.time())
                        nxt = next_pickup_allowed(collect_times, a.free_pickups, a.cooldown)
                        wait_s = max(nxt - time.time(), 0.0)
                        print("[bot] COLLECTED -- %d so far%s"
                              % (picked, "" if wait_s <= 0 else "  (next in %.0fs)" % wait_s),
                              flush=True)
                    else:
                        print("[bot] bag %.0f units away was taken by someone else"
                              % (committed_dist or -1), flush=True)
                    committed = None
                    route = None

            # Drop targets we have already failed to reach (unreachable ledges, blocked routes).
            live = [t for t in tg
                    if not any(abs(t["x"] - bx) < 1.0 and abs(t["y"] - by) < 1.0 and now < until
                               for bx, by, until in blacklist)]
            if not live:
                print("[bot] every treasure is blacklisted or gone -- waiting", file=sys.stderr)
                time.sleep(2.0)
                continue

            # CHOOSE BY ROUTE LENGTH, and reconsider now and then in case a bag has appeared much
            # nearer (bags respawn). Planning is cheap but not free, so not every tick.
            left_now = route.remaining(me["x"], me["y"]) if (cur and route) else \
                (cur["distance"] if cur else None)
            if cur is None or (now - reeval_at > 5.0 and live[0] is not cur
                               and live[0]["distance"] < left_now * 0.6):
                reeval_at = now
                best, unreachable = choose_target(grid, me, live, a.route_candidates)
                for t in unreachable:
                    print("[bot] no route to %s at d=%.0f -- skipping it for %.0fs"
                          % (t["kind"], t["distance"], a.blacklist_for), flush=True)
                    blacklist.append((t["x"], t["y"], now + a.blacklist_for))
                if best is None:
                    if cur is None:
                        time.sleep(1.0)
                        continue
                elif cur is None or best[2] < left_now * 0.6:
                    cur, route = best[0], best[1]
                    route_at = now
                    committed = (cur["x"], cur["y"])
                    t_commit = now
                    best_dist = None
                    closest = cur["distance"]
                    if route:
                        print("[bot] heading for %s (val=%s): route %.0f units in %d legs, straight "
                              "line %.0f" % (cur["kind"], cur["value"], best[2], len(route.pts) - 1,
                                             cur["distance"]), flush=True)

            # WALKED THROUGH IT AND IT IS STILL THERE -> it is not collectible right now. For a
            # BAG this is almost always the collection cooldown, which is temporary, so back off
            # for a few seconds and come again rather than writing the bag off.
            closest = min(closest, cur["distance"])
            if closest <= a.touch and cur["distance"] > a.touch * 3.0:
                wait = a.retry_after if cur["kind"] == "bag" else a.blacklist_for
                print("[bot] passed through %s at d=%.1f and it remains (cooldown?) -- retrying in "
                      "%.0fs" % (cur["kind"], closest, wait), flush=True)
                blacklist.append((cur["x"], cur["y"], now + wait))
                committed = None
                route = None
                continue

            committed_dist = cur["distance"]

            # Give up on one we cannot get to, so a bag on a ledge cannot trap the bot forever.
            if now - t_commit > a.give_up:
                print("[bot] giving up on %s at d=%.0f after %.0fs -- blacklisting for %.0fs"
                      % (cur["kind"], cur["distance"], now - t_commit, a.blacklist_for), flush=True)
                blacklist.append((cur["x"], cur["y"], now + a.blacklist_for))
                committed = None
                route = None
                continue

            # FOLLOW THE ROUTE: steer at the furthest point of it we can see directly. Replan when
            # it goes stale, or when none of it is visible any more (pushed off it by another toon).
            if grid:
                goal_moved = route is not None and (abs(route.goal[0] - cur["x"]) > 1.0 or
                                                    abs(route.goal[1] - cur["y"]) > 1.0)
                if route is None or goal_moved or now - route_at > a.replan_every:
                    route = grid.plan(me["x"], me["y"], cur["x"], cur["y"])
                    route_at = now
                    if route is None:
                        print("[bot] no route to %s at d=%.0f any more -- skipping it for %.0fs"
                              % (cur["kind"], cur["distance"], a.blacklist_for), flush=True)
                        blacklist.append((cur["x"], cur["y"], now + a.blacklist_for))
                        committed = None
                        continue
                wp = grid.waypoint(route, me["x"], me["y"])
                if wp is None and now - route_at > 0.5:
                    route = grid.plan(me["x"], me["y"], cur["x"], cur["y"]) or route
                    route_at = now
                    wp = grid.waypoint(route, me["x"], me["y"])
            else:
                route, wp = None, None
            if wp is None:
                wp = (cur["x"], cur["y"])        # no map, or lost: straight at it; reflexes do the rest
            final_leg = route is None or route.idx >= len(route.pts) - 1
            steer_brg, wp_dist, _ = bearing_to(me, {"x": wp[0], "y": wp[1]})
            route_left = route.remaining(me["x"], me["y"]) if route else cur["distance"]

            # Progress is measured ALONG THE ROUTE, and only WALKING that fails to shorten it
            # counts as being stuck. A route that starts by walking away from the bag increases
            # the straight-line distance, and turning on the spot to line up with a waypoint makes
            # no progress by design -- counted as stalling, a couple of alignment turns flagged the
            # bot "blocked", which switched off the guard against dithering and left Jev turning
            # left and right at a bearing of 0 for fifteen seconds.
            if best_dist is None or route_left < best_dist - 0.5:
                best_dist = route_left
                walk_stall = 0.0
            elif prev_act is not None and prev_act[0] in ("w", "s"):
                walk_stall += max(prev_act[1], 0.5)
            stalled = walk_stall
            blocked = stalled >= a.stall_after
            if blocked and now - route_at > a.stall_after:
                route = None                      # something the map does not know is in the way

            clear_a = clearance(me, nogo, walls, rounds, 0.0)
            clear_l = clearance(me, nogo, walls, rounds, -45.0)
            clear_r = clearance(me, nogo, walls, rounds, +45.0)
            clear_t = clearance(me, nogo, walls, rounds, steer_brg)

            # COOLDOWN. Walking into a bag while rate limited only plays a sound, so the bot waits
            # IN PLACE, and only sets off when there is just enough time left to arrive as the
            # timer expires -- timed on the ROUTE, not the straight line. Standing still on purpose
            # must not look like being stuck, so every stuck detector is reset while waiting.
            allowed_at = next_pickup_allowed(collect_times, a.free_pickups, a.cooldown)
            left = allowed_at - time.time()
            cooling = left > 0
            if cooling:
                travel = route_left / WALK_SPEED + TRAVEL_SLACK
                in_position = cur["distance"] <= a.standoff
                if in_position or left > travel:
                    t_commit = time.time()
                    best_dist = None
                    frozen = 0
                    backs = 0
                    if time.time() - wait_said > 10.0:
                        where = ("in position %.1f units from" % cur["distance"] if in_position
                                 else "%.0f units (by route) from" % route_left)
                        print("[bot] cooldown %.0fs left -- waiting %s %s (val=%s)%s"
                              % (left, where, cur["kind"], cur["value"],
                                 "" if in_position else ", leaving in %.0fs" % (left - travel)),
                              flush=True)
                        wait_said = time.time()
                    time.sleep(min(max(left - (0 if in_position else travel), 0.2), 1.0))
                    continue

            payload = {
                "target": {"bearing": round(steer_brg, 1), "distance": round(wp_dist, 1),
                           "height_difference": cur["dz"],
                           "kind": cur["kind"], "value": cur["value"]},
                "route_distance_left": round(route_left, 1),
                "others": [{"bearing": t["bearing"], "distance": t["distance"], "kind": t["kind"]}
                           for t in tg[1:4]],
                "seconds_without_progress": round(stalled, 1),
                "progress": "blocked" if blocked else "closing",
                "clear_ahead": round(clear_a, 1),
                "clear_toward_target": round(clear_t, 1),
                "seconds_until_pickup_allowed": round(max(allowed_at - time.time(), 0.0), 1),
                "moved_last_step": round(moved_last, 1),
                "clear_left": round(clear_l, 1),
                "clear_right": round(clear_r, 1),
            }

            if a.local:
                act, conf = local_decide(steer_brg, wp_dist, blocked)
                via = "local"
            else:
                try:
                    act, conf = jev_decide(payload, a.timeout)
                    via = "jev"
                except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                        KeyError, ValueError) as e:
                    act, conf = local_decide(steer_brg, wp_dist, blocked)
                    via = "local(%s)" % type(e).__name__
            if act not in ACTIONS:
                act, conf = local_decide(steer_brg, wp_dist, blocked)
                via = "local(bad)"

            # Reversing is an ESCAPE, not a state. After a few in a row, sidestep instead: turn 90
            # degrees and commit to a short walk, then plan again from wherever that leaves us.
            backs = backs + 1 if act == "back" else 0
            if backs >= a.max_backs:
                print("[bot] %d reverses in a row is not working -- sidestepping" % backs, flush=True)
                keys.pulse("a", hold_for(90))
                keys.pulse("w", 1.0)
                backs = 0
                best_dist = None
                route = None
                continue
            key, dur = ACTIONS[act]

            # Reversing is rarely the answer when a side is plainly open.
            if key == "s":
                side = max(clear_l, clear_r)
                if side > 10.0 and side > 2.0 * clear_a:
                    act = "turn_left" if clear_l >= clear_r else "turn_right"
                    conf, via = 1.0, via + "+open"
                    key, dur = ACTIONS[act]

            # WALL GUARD -- a reflex for what the map does not know: only when a wall is nearer
            # than the waypoint (the route says the line is clear) AND the toon is failing to move.
            if (key == "w" and clear_a < BLOCKED_CLEARANCE and clear_a < wp_dist - 0.5
                    and moved_last < MOVED_ENOUGH):
                act = "turn_left" if clear_l >= clear_r else "turn_right"
                conf, via = 1.0, via + "+wall"
                key, dur = ACTIONS[act]
            # ALIGNMENT GUARD: never take a long blind walk while badly misaligned. Jev was
            # seen choosing forward_far at -96 and -144 degrees.
            elif key == "w" and abs(steer_brg) > a.max_walk_bearing:
                act, conf = local_decide(steer_brg, wp_dist, blocked)
                via += "+align"
                key, dur = ACTIONS[act]
            elif key == "w" and abs(steer_brg) > 8.0:
                dur = min(dur, ACTIONS["forward"][1])      # slightly off: medium leg at most
            # SYMMETRIC COUNTERPART: when already facing the waypoint, a turn can only take us off
            # it. Jev is weakest here (0.39-0.50 confidence inside the forward band).
            elif key in ("a", "d") and abs(steer_brg) <= 8.0 and not blocked:
                act, conf = local_decide(steer_brg, wp_dist, blocked)
                via += "+lock"
                key, dur = ACTIONS[act]
            # HARD NO-GO VETO. A trigger never stops you -- you walk straight through it -- so this
            # ignores movement entirely.
            if key == "w":
                ng = nogo_clearance(me, nogo, 0.0)
                if ng < 3.0:
                    act = "turn_left" if nogo_clearance(me, nogo, -45.0) >= \
                        nogo_clearance(me, nogo, 45.0) else "turn_right"
                    conf, via = 1.0, via + "+nogo"
                    key, dur = ACTIONS[act]
                else:
                    dur = min(dur, walk_for(max(ng - 2.0, 0.5)))
            if key == "w":
                # Never past the waypoint: a corner is where the route turns, and the bag is where
                # it ends.
                dur = min(dur, walk_for(max(wp_dist - (a.touch * 0.5 if final_leg else 0.0), 1.0)))
                # Never so far that the remaining heading error carries us off the line: steering
                # is only good to a few degrees, and a long leg magnifies it.
                if abs(steer_brg) > 1.0:
                    dur = min(dur, walk_for(max(a.max_drift / math.sin(math.radians(abs(steer_brg))),
                                                1.0)))
                # Never further than the free space ahead -- unless we are demonstrably moving.
                if moved_last < MOVED_ENOUGH:
                    dur = min(dur, walk_for(max(clear_a - 1.0, 1.0)))
                if cooling and final_leg:
                    # stop short of the bag so the approach does not spend the pickup early
                    dur = min(dur, walk_for(max(cur["distance"] - a.standoff, 0.5)))
            print("[bot] %-17s conf=%.2f via=%-11s | %s d=%.0f route=%.0f wp=%.0f@%+.0f val=%s | clr L%.0f A%.0f R%.0f T%.0f mv%.1f | %s %.2fs stall=%.1fs"
                  % (act, conf, via, cur["kind"], cur["distance"], route_left, wp_dist, steer_brg,
                     cur["value"], clear_l, clear_a, clear_r, clear_t, moved_last,
                     key, dur, stalled), flush=True)
            last_act = (key, dur, me["h"])
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
                    help="seconds of walking without getting closer (along the route) before "
                         "reporting blocked")
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
                    help="seconds before re-approaching a bag that did not collect")
    ap.add_argument("--cooldown", type=float, default=COOLDOWN_S,
                    help="seconds between pickups once the rate limit engages")
    ap.add_argument("--free-pickups", type=int, default=FREE_PICKUPS,
                    help="pickups allowed before the rate limit engages")
    ap.add_argument("--standoff", type=float, default=7.0,
                    help="units to hold short of a bag while waiting out the cooldown")
    ap.add_argument("--replan-every", type=float, default=15.0,
                    help="seconds before a route is planned afresh from wherever the toon is")
    ap.add_argument("--replan-height", type=float, default=4.0,
                    help="rebuild the route map after climbing or dropping this many units")
    ap.add_argument("--route-candidates", type=int, default=5,
                    help="nearest bags to plan routes to when choosing the next one")
    ap.add_argument("--max-drift", type=float, default=3.0,
                    help="cap a forward leg so the heading error drifts at most this many units")
    ap.add_argument("--wall-refresh", type=float, default=300.0,
                    help="seconds between wall-polygon refreshes (a zone change refetches at once)")
    ap.add_argument("--obstacle-refresh", type=float, default=30.0,
                    help="seconds between re-reading the no-go triggers (a zone change re-reads at once)")
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

    session, ex = WS.attach()
    keys = Keys(ex, dry=a.dry_run)
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
