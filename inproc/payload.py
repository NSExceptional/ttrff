# payload.py -- runs INSIDE the live TTREngine CPython interpreter.
#
# Injected by driver.py via the marshal_evalcode primitive (host-marshalled code
# object -> marshal.loads -> PyEval_EvalCode; see STATUS.md). Monkeypatches the
# already-loaded (decrypted-in-RAM) Toontown modules to speed up a set of COSMETIC
# animations. Everything here is:
#   - idempotent  (re-running never double-wraps; always re-wraps the true original)
#   - reversible  ({"revert": true} in the config restores every original)
#   - defensive   (unknown/absent names are logged and skipped, never fatal)
#
# COSMETIC ONLY: no movement/turn/aim/damage logic is touched.
#
# --------------------------------------------------------------------------
# CRITICAL TECHNIQUE (learned the hard way in the open-toontown port):
#   Panda's `Interval.start(startT, endT, playRate=1.0)` RESETS the play rate every
#   call, so `ival.setPlayRate(f)` BEFORE `.start()` is a SILENT NO-OP (this is what
#   the old version of this file did -- it never actually sped anything up). But
#   `setPlayRate` AFTER the interval is already playing changes its speed on the fly.
#   So every speed patch here wraps the method that builds+starts a track, lets the
#   original run (which starts the track), then setPlayRate's the now-playing track.
#   The track is retrieved from a known `self.<attr>` or from `self.activeIntervals`.
#
#   The book (open/close) uses the same mechanism with a huge factor -> effectively
#   instant. The iris/fade transitions are scaled directly in the Transitions methods.
# --------------------------------------------------------------------------

import os
import sys
import json
import traceback

CFG_PATH = os.environ.get("TTRMOD_CFG", "")
STATUS_PATH = os.environ.get("TTRMOD_STATUS", "/tmp/ttrmod-status.json")

report = {
    "ok": False,
    "revert": False,
    "probe": [],
    "applied": [],
    "skipped": [],
    "reverted": [],
    "errors": [],
    "modules_seen": {},
}


def _log_err(where, exc):
    report["errors"].append("%s: %s" % (where, "".join(
        traceback.format_exception_only(type(exc), exc)).strip()))


# --------------------------------------------------------------------------
# Persistent registry, anchored on builtins so it survives across injections.
# --------------------------------------------------------------------------
import builtins

reg = getattr(builtins, "_ttrmod", None)
if reg is None:
    reg = {"orig": {}, "orig_import": None, "hook_installed": False}
    builtins._ttrmod = reg


# --------------------------------------------------------------------------
# Patch table.
#
# Each speed patch wraps `cls.method`; after the original runs it locates the track
# it started and `setPlayRate`s it. `after` selects HOW to find the track:
#   {"attr": "track"}            -> setPlayRate(self.track)
#   {"iname_attr": "faceOffName"}-> setPlayRate(self.activeIntervals[self.faceOffName])
#   {"iname_sub": "to-pending"}  -> setPlayRate every self.activeIntervals[k] with sub in k
#
# TTR's frozen build imports modules by BARE name ("MovieUtil"); open-toontown by
# dotted name. We try both. `group` selects the factor/enable from the config.
# --------------------------------------------------------------------------
PATCHES = [
    # ---- whole battle round movie: every attack + nested cog-death + dodge --------
    {"id": "battle_movie", "group": "battle", "kind": "wrap_after",
     "modules": ["Movie", "toontown.battle.Movie"], "cls": "Movie",
     "methods": ["play"], "after": {"attr": "track"}},

    # ---- combat intro (FaceOff): taunt-stare + walk-to-spots ----------------------
    {"id": "faceoff", "group": "battle", "kind": "wrap_after",
     "modules": ["DistributedBattle", "toontown.battle.DistributedBattle"],
     "cls": "DistributedBattle", "methods": ["enterFaceOff"],
     "after": {"iname_attr": "faceOffName"}},

    # ---- run-in (join walk) -> earlier client-driven d_joinDone -------------------
    {"id": "runin", "group": "runin", "kind": "wrap_after",
     "modules": ["DistributedBattleBase", "toontown.battle.DistributedBattleBase"],
     "cls": "DistributedBattleBase", "methods": ["makeSuitJoin", "_DistributedBattleBase__makeToonJoin"],
     "after": {"iname_sub": "to-pending"}},

    # ---- teleport out/in ----------------------------------------------------------
    {"id": "teleport", "group": "teleport", "kind": "wrap_after",
     "modules": ["Toon", "toontown.toon.Toon"], "cls": "Toon",
     "methods": ["enterTeleportOut", "enterTeleportIn"], "after": {"attr": "track"}},

    # ---- street tunnel walk-in / walk-out -----------------------------------------
    {"id": "tunnel", "group": "tunnel", "kind": "wrap_after",
     "modules": ["LocalToon", "toontown.toon.LocalToon"], "cls": "LocalToon",
     "methods": ["handleTunnelIn", "handleTunnelOut"], "after": {"attr": "tunnelTrack"}},

    # ---- Shticker Book open/close (huge factor => effectively instant) -------------
    {"id": "book", "group": "book", "kind": "wrap_after",
     "modules": ["Toon", "toontown.toon.Toon"], "cls": "Toon",
     "methods": ["enterOpenBook", "enterCloseBook"], "after": {"attr": "track"}},

    # ---- iris + fade screen wipes (door/street/teleport/playground) ----------------
    # Scaled directly in the transition methods (dividing `t`), not via a track.
    {"id": "transitions", "group": "iris", "kind": "transitions",
     "modules": ["direct.showbase.Transitions"], "cls": "Transitions",
     "methods": ["fadeIn", "fadeOut", "irisIn", "irisOut"]},
]


def resolve_module(modnames):
    # ONLY look at already-imported modules. Do NOT __import__ here: this code runs
    # inside an injected frame while HOLDING the GIL, and importing a game module can
    # transitively wait on the main thread (which is blocked on that same GIL) ->
    # deadlock -> frozen game. Modules that load later are handled by the import hook,
    # which runs on the main thread (GIL already held by it) where importing is safe.
    for name in modnames:
        m = sys.modules.get(name)
        if m is not None:
            return m, name
    return None, None


def _get_class(patch):
    mod, name = resolve_module(patch["modules"])
    if mod is None:
        return None, None
    cls = getattr(mod, patch["cls"], None)
    return cls, name


def _apply_after(self, spec, factor):
    """Locate the just-started track on `self` and setPlayRate it (on-the-fly)."""
    try:
        if "attr" in spec:
            iv = getattr(self, spec["attr"], None)
            if iv is not None:
                iv.setPlayRate(factor)
        elif "iname_attr" in spec:
            nm = getattr(self, spec["iname_attr"], None)
            ivals = getattr(self, "activeIntervals", {}) or {}
            iv = ivals.get(nm)
            if iv is not None:
                iv.setPlayRate(factor)
        elif "iname_sub" in spec:
            sub = spec["iname_sub"]
            ivals = getattr(self, "activeIntervals", {}) or {}
            for k, iv in list(ivals.items()):
                if sub in k:
                    iv.setPlayRate(factor)
    except Exception:
        pass


def _make_wrap_after(true_orig, factor, after_spec):
    def wrapped(self, *a, **k):
        result = true_orig(self, *a, **k)   # builds + starts the track
        _apply_after(self, after_spec, factor)   # setPlayRate the now-playing track
        return result
    wrapped._ttrmod_orig = true_orig
    return wrapped


def _make_transition_scaler(true_orig, factor):
    # fadeIn/Out/irisIn/Out(self, t=0.5, ...): divide t (keep the t==0 instant path).
    def wrapped(self, t=0.5, *a, **k):
        if t:
            t = t / factor
        return true_orig(self, t, *a, **k)
    wrapped._ttrmod_orig = true_orig
    return wrapped


def _patch_one(holder, attr, key, make_wrapper):
    if not hasattr(holder, attr):
        return False, "attr %r absent" % attr
    if key not in reg["orig"]:
        reg["orig"][key] = getattr(holder, attr)
    true_orig = reg["orig"][key]
    setattr(holder, attr, make_wrapper(true_orig))
    return True, None


def apply_patch(patch, group_cfg):
    pid = patch["id"]
    factor = float(group_cfg.get("factor", 2.0))
    cls, modname = _get_class(patch)
    if cls is None:
        report["skipped"].append({"id": pid, "reason": "module/class not loaded yet"})
        return
    for method in patch["methods"]:
        key = "%s|%s.%s.%s" % (pid, modname, patch["cls"], method)
        if patch["kind"] == "wrap_after":
            ok, err = _patch_one(cls, method, key,
                                 lambda o: _make_wrap_after(o, factor, patch["after"]))
        elif patch["kind"] == "transitions":
            ok, err = _patch_one(cls, method, key,
                                 lambda o: _make_transition_scaler(o, factor))
        else:
            ok, err = False, "unknown kind %r" % patch["kind"]
        if ok:
            report["applied"].append({"id": pid, "target": "%s.%s.%s" % (modname, patch["cls"], method),
                                       "detail": "x%.3g" % factor})
        else:
            present = [n for n in dir(cls) if not n.startswith("__")]
            report["modules_seen"].setdefault("%s.%s" % (modname, patch["cls"]), sorted(present)[:80])
            report["skipped"].append({"id": pid, "reason": "%s.%s: %s" % (patch["cls"], method, err)})


def revert_all():
    report["revert"] = True
    for key, orig in list(reg["orig"].items()):
        pid = key.split("|", 1)[0]
        patch = next((p for p in PATCHES if p["id"] == pid), None)
        if patch is None:
            continue
        cls, _ = _get_class(patch)
        if cls is None:
            report["skipped"].append({"id": pid, "reason": "module gone; nothing to revert"})
            continue
        # key = "pid|modname.clsname.method"
        method = key.rsplit(".", 1)[1]
        try:
            setattr(cls, method, orig)
            report["reverted"].append({"id": pid, "target": key.split("|", 1)[1]})
        except Exception as e:
            _log_err("revert %s" % pid, e)
    reg["orig"].clear()
    remove_import_hook()


# --------------------------------------------------------------------------
# Import hook: re-apply when a target module loads later (attach at login,
# patches kick in as battle/toon modules import). Reversible.
# --------------------------------------------------------------------------
def install_import_hook(cfg):
    if reg["hook_installed"]:
        return
    target = set()
    for p in PATCHES:
        for m in p["modules"]:
            target.add(m)
    orig_import = builtins.__import__
    reg["orig_import"] = orig_import
    _busy = {"v": False}

    def hooked(name, *a, **k):
        module = orig_import(name, *a, **k)
        if not _busy["v"] and name in target:
            _busy["v"] = True
            try:
                apply_enabled(cfg)
            except Exception:
                pass
            finally:
                _busy["v"] = False
        return module

    builtins.__import__ = hooked
    reg["hook_installed"] = True


def remove_import_hook():
    if reg["hook_installed"] and reg["orig_import"] is not None:
        builtins.__import__ = reg["orig_import"]
    reg["orig_import"] = None
    reg["hook_installed"] = False


def apply_enabled(cfg):
    groups = cfg.get("groups", {})
    for patch in PATCHES:
        gc = groups.get(patch["group"], {})
        if not gc.get("enabled", False):
            continue
        apply_patch(patch, gc)


def probe_all(cfg):
    """Read-only: report whether each target class/method is present. Proves the
    inject->marshal->eval->payload pipeline ran and can see the game modules, without
    changing anything. Run this FIRST on the live smoke test."""
    for patch in PATCHES:
        pid = patch["id"]
        cls, modname = _get_class(patch)
        if cls is None:
            report["probe"].append({"id": pid, "target": patch["modules"][0], "value": "module/class not loaded yet"})
            continue
        found = {}
        for method in patch["methods"]:
            found[method] = hasattr(cls, method)
        report["probe"].append({"id": pid, "target": "%s.%s" % (modname, patch["cls"]), "value": found})


# --------------------------------------------------------------------------
# HUD bridge (hud.py is concatenated ahead of this file so it shares this namespace).
# --------------------------------------------------------------------------
def _hud_apply(cfg):
    hud_cfg = cfg.get("hud", {})
    if not hud_cfg.get("enabled", False):
        return
    fn = globals().get("setup_hud")
    if fn is None:
        report["skipped"].append({"id": "hud", "reason": "hud.py not injected"})
        return
    try:
        fn(hud_cfg)
    except Exception as e:
        _log_err("setup_hud", e)


def _hud_teardown():
    fn = globals().get("teardown_hud")
    if fn is None:
        return
    try:
        fn()
    except Exception as e:
        _log_err("teardown_hud", e)


# --------------------------------------------------------------------------
# Entry
# --------------------------------------------------------------------------
def main():
    try:
        cfg = json.load(open(CFG_PATH)) if CFG_PATH and os.path.exists(CFG_PATH) else {}
    except Exception as e:
        _log_err("load cfg", e)
        cfg = {}

    if cfg.get("revert"):
        revert_all()
        _hud_teardown()
    elif cfg.get("probe"):
        probe_all(cfg)
    else:
        apply_enabled(cfg)
        _hud_apply(cfg)
        if cfg.get("install_import_hook", True):
            try:
                install_import_hook(cfg)
            except Exception as e:
                _log_err("install_import_hook", e)

    report["ok"] = not report["errors"]
    try:
        with open(STATUS_PATH, "w") as f:
            json.dump(report, f, indent=2, default=repr)
    except Exception:
        pass
    try:
        sys.stdout.write("[ttrmod] applied=%d skipped=%d reverted=%d errors=%d\n" % (
            len(report["applied"]), len(report["skipped"]),
            len(report["reverted"]), len(report["errors"])))
        sys.stdout.flush()
    except Exception:
        pass


main()
