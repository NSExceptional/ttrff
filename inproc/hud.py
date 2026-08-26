# hud.py -- runs INSIDE the live TTREngine CPython interpreter.
#
# The driver concatenates this file AHEAD of payload.py into one marshalled code
# object, so setup_hud/teardown_hud share payload.py's module namespace (they can
# see `report` and `_log_err`, defined there). payload.main() calls setup_hud on
# apply and teardown_hud on revert.
#
# It draws an always-on, read-only overlay: current street name, active ToonTasks,
# and gag inventory -- so you don't have to open the Shticker Book. It reads only
# client-side state the game already has; it changes NO game logic and talks to no
# server. Everything is:
#   - idempotent  (re-applying tears the old overlay down first)
#   - reversible  (teardown_hud destroys the nodes + removes the tasks)
#   - defensive   (every game-module lookup is guarded; a rename can blank a
#                  panel but never crashes the interpreter)
#
# `base`, `taskMgr`, `aspect2d`, and the a2d* corner anchors are Panda3D builtins
# (ShowBase installs them into builtins), so they resolve as globals here.
#
# Attribute paths are from open-toontown/master (cross-checked vs TT-CL-Edition);
# see docs. A few are medium-confidence and flagged; if TTR renamed one, the guard
# degrades that panel gracefully and payload's status still reports "hud applied".

import builtins


def _hudstate():
    reg = getattr(builtins, "_ttrmod", None)
    if reg is None:
        # payload.py normally creates this; be safe if load order ever changes
        reg = {}
        builtins._ttrmod = reg
    return reg.setdefault("hud", {"overlay": None, "cfg": None})


# --------------------------------------------------------------------------
# Defensive module / engine-type resolution
# --------------------------------------------------------------------------
def _mod(name):
    import sys
    m = sys.modules.get(name)
    if m is not None:
        return m
    try:
        __import__(name)
        return sys.modules.get(name)
    except Exception:
        return None


def _text_node():
    # Panda3D 1.11: prefer the modern module, fall back to the legacy shim.
    try:
        from panda3d.core import TextNode
        return TextNode
    except Exception:
        try:
            from pandac.PandaModules import TextNode
            return TextNode
        except Exception:
            return None


def _interface_font():
    tg = _mod("ToontownGlobals")
    try:
        return tg.getInterfaceFont()
    except Exception:
        return None


# --------------------------------------------------------------------------
# Read-only game-state extraction (all guarded)
# --------------------------------------------------------------------------
def current_zone():
    """zoneId of the place the local toon is in, or None between zones."""
    try:
        place = base.cr.playGame.getPlace()
        if place is None:
            return None
        return place.getZoneId()
    except Exception:
        return None


def is_on_street():
    z = current_zone()
    if z is None:
        return False
    zu = _mod("ZoneUtil")
    try:
        return zu.getWhereName(z, True) == "street"
    except Exception:
        return False


def street_name(z):
    """Human-readable name for a street/playground zoneId, with fallbacks."""
    tg = _mod("ToontownGlobals")
    zu = _mod("ZoneUtil")
    try:
        branch = zu.getBranchZone(z)
        entry = tg.StreetNames.get(branch)   # == TTLocalizer.GlobalStreetNames
        if entry:
            return entry[-1]                 # e.g. 'Silly Street' / 'Playground'
    except Exception:
        pass
    try:
        hood_id = zu.getHoodId(z)
        return tg.hoodNameMap[hood_id][-1]   # e.g. 'Toontown Central'
    except Exception:
        return "Zone %s" % z


def quest_lines(av):
    """Each active quest as: objective (progress) location -> turn-in NPC.
    Reuses the game's own Quest objects rather than reimplementing quest text."""
    Quests = _mod("Quests")
    NPCToons = _mod("NPCToons")
    out = []
    if Quests is None:
        return out
    try:
        quests = list(av.quests)
    except Exception:
        return out
    for qd in quests:
        try:
            quest_id = qd[0]
            to_npc = qd[2] if len(qd) > 2 else None
            quest = Quests.getQuest(quest_id)
            if quest is None:
                continue
            parts = []
            try:
                parts.append(quest.getString())            # objective
            except Exception:
                parts.append("Task %s" % quest_id)
            try:
                prog = quest.getProgressString(av, qd)      # "3 of 8" / "Complete"
                if prog:
                    parts.append("(%s)" % prog)
            except Exception:
                pass
            loc_fn = getattr(quest, "getLocationName", None)
            if loc_fn is not None:
                try:
                    loc = loc_fn()
                    if loc:
                        parts.append(loc)                   # "on Silly Street"
                except Exception:
                    pass
            if NPCToons is not None and to_npc is not None:
                try:
                    nm = NPCToons.getNPCName(to_npc)
                    zn = NPCToons.getNPCZone(to_npc)
                    parts.append("-> %s (%s)" % (nm, street_name(zn)))
                except Exception:
                    pass
            out.append(" ".join(parts))
        except Exception:
            continue
    return out


def inventory_lines(av):
    """One row per accessible gag track: track name + count per level (1..7),
    '.' where the level isn't unlocked yet."""
    TBG = _mod("ToontownBattleGlobals")
    lines = []
    if TBG is None:
        return lines
    try:
        inv = av.inventory
    except Exception:
        return lines
    ntracks = getattr(TBG, "NUM_GAG_TRACKS", 7)
    tracks = getattr(TBG, "Tracks", None)
    levels = getattr(TBG, "Levels", None)
    for track in range(ntracks):
        try:
            if hasattr(av, "hasTrackAccess") and not av.hasTrackAccess(track):
                continue
        except Exception:
            pass
        counts = []
        for lvl in range(7):
            try:
                counts.append(int(inv.numItem(track, lvl)))
            except Exception:
                counts.append(0)
        # which levels are unlocked (exp thresholds); fall back to "has any"
        unlocked = [c > 0 for c in counts]
        try:
            exp = av.experience.getExp(track)   # medium-confidence attr; guarded
            if levels is not None:
                unlocked = [exp >= levels[track][lvl] for lvl in range(7)]
        except Exception:
            pass
        cells = ["%2d" % counts[lvl] if unlocked[lvl] else " ." for lvl in range(7)]
        try:
            name = tracks[track].title() if tracks else "Track %d" % track
        except Exception:
            name = "Track %d" % track
        lines.append("%-8s %s" % (name, " ".join(cells)))
    if lines:
        lines.insert(0, "%-8s  1  2  3  4  5  6  7" % "Gags")
    return lines


# --------------------------------------------------------------------------
# The overlay (built on the main thread via taskMgr; survives lldb detach)
# --------------------------------------------------------------------------
REFRESH_TASK = "ttrmodHudRefresh"
BUILD_TASK = "ttrmodHudBuild"
KILL_TASK = "ttrmodHudKill"


class HudOverlay:
    def __init__(self, cfg):
        self.cfg = cfg
        self.interval = 1.0 / max(1, int(cfg.get("refresh_hz", 4)))
        self.scale = float(cfg.get("scale", 0.05))
        self.nodes = []
        self.left = None      # street name + tasks (top-left)
        self.inv = None       # gag grid (bottom-left)

        from direct.gui.OnscreenText import OnscreenText
        TextNode = _text_node()
        align = TextNode.ALeft if TextNode is not None else 0
        font = _interface_font()
        common = dict(fg=(1, 1, 1, 1), shadow=(0, 0, 0, 1), mayChange=1,
                      scale=self.scale, align=align)
        if font is not None:
            common["font"] = font

        if cfg.get("show_street_name", True) or cfg.get("show_tasks", True):
            self.left = OnscreenText(parent=base.a2dTopLeft, text="",
                                     pos=(0.04, -0.10), wordwrap=26, **common)
            self.nodes.append(self.left)
        if cfg.get("show_inventory", True):
            self.inv = OnscreenText(parent=base.a2dBottomLeft, text="",
                                    pos=(0.04, 0.34), **common)
            self.nodes.append(self.inv)

        taskMgr.doMethodLater(self.interval, self._refresh, REFRESH_TASK)

    def _refresh(self, task):
        try:
            self._update()
        except Exception:
            pass
        task.delayTime = self.interval
        return task.again

    def _update(self):
        av = getattr(base, "localAvatar", None)
        visible = self.cfg.get("always_show", False) or is_on_street()
        if av is None or not visible:
            for n in self.nodes:
                n.hide()
            return
        for n in self.nodes:
            n.show()

        if self.left is not None:
            block = []
            z = current_zone()
            if self.cfg.get("show_street_name", True) and z is not None:
                block.append(street_name(z))
                block.append("")
            if self.cfg.get("show_tasks", True):
                ql = quest_lines(av)
                block.append("Tasks:" if ql else "Tasks: (none)")
                block.extend("- " + q for q in ql)
            self.left["text"] = "\n".join(block)

        if self.inv is not None:
            self.inv["text"] = "\n".join(inventory_lines(av))

    def destroy(self):
        try:
            taskMgr.remove(REFRESH_TASK)
        except Exception:
            pass
        for n in self.nodes:
            try:
                n.destroy()
            except Exception:
                pass
        self.nodes = []
        self.left = self.inv = None


# --------------------------------------------------------------------------
# Entry points called from payload.main()
# --------------------------------------------------------------------------
def setup_hud(cfg):
    st = _hudstate()
    st["cfg"] = cfg

    def _build(task):
        old = st.get("overlay")
        if old is not None:
            try:
                old.destroy()
            except Exception:
                pass
            st["overlay"] = None
        try:
            st["overlay"] = HudOverlay(cfg)
        except Exception as e:
            _log_err("HudOverlay build", e)
        return task.done

    # defer to the main task loop: thread-safe scene-graph construction, and it
    # persists after lldb detaches (like the animation patches' import hook)
    taskMgr.doMethodLater(0, _build, BUILD_TASK)
    report["applied"].append({
        "id": "hud", "target": "OnscreenText overlay",
        "detail": "tasks=%s inv=%s street=%s always=%s hz=%s" % (
            cfg.get("show_tasks", True), cfg.get("show_inventory", True),
            cfg.get("show_street_name", True), cfg.get("always_show", False),
            cfg.get("refresh_hz", 4))})


def teardown_hud():
    st = _hudstate()
    ov = st.get("overlay")

    def _kill(task):
        cur = st.get("overlay")
        if cur is not None:
            try:
                cur.destroy()
            except Exception:
                pass
            st["overlay"] = None
        return task.done

    if ov is not None:
        try:
            taskMgr.doMethodLater(0, _kill, KILL_TASK)
        except Exception:
            try:
                ov.destroy()
            except Exception:
                pass
            st["overlay"] = None
    report["reverted"].append({"id": "hud", "target": "OnscreenText overlay"})
