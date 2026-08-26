# payload.py -- runs INSIDE the live TTREngine CPython interpreter.
#
# Injected by driver.py via lldb using the marshal_evalcode primitive
# (host-marshalled code object -> marshal.loads -> PyEval_EvalCode); see STATUS.md.
# It monkeypatches the already-loaded Toontown game modules to shorten a few
# COSMETIC battle animations. Everything here is:
#   - idempotent   (re-running never double-wraps; it always re-wraps the true original)
#   - reversible   ({"revert": true} in the config restores every original)
#   - defensive    (unknown/absent names are logged and skipped, never fatal)
#
# Config path comes in via env TTRMOD_CFG; a JSON result is written to TTRMOD_STATUS.
#
# NOTE: This is cosmetic playback-rate scaling in a Panda3D game the owner owns.
# No movement/turn/aim/damage logic is touched.

import os
import sys
import json
import traceback

CFG_PATH = os.environ.get("TTRMOD_CFG", "")
STATUS_PATH = os.environ.get("TTRMOD_STATUS", "/tmp/ttrmod-status.json")

report = {
    "ok": False,
    "revert": False,
    "applied": [],     # [{"id","target","detail"}]
    "skipped": [],      # [{"id","reason"}]
    "reverted": [],
    "errors": [],
    "modules_seen": {}, # modname -> [candidate attrs present] for diagnostics
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
    reg = {"orig": {}, "wrapped": set(), "orig_import": None, "hook_installed": False}
    builtins._ttrmod = reg


# --------------------------------------------------------------------------
# Patch table.  Each patch names its group (whose factor/enable comes from the
# config) and a list of candidate module names -- TTR's frozen build imports
# these by BARE name ("MovieUtil"), open-toontown by dotted name; we try both.
# --------------------------------------------------------------------------
PATCHES = [
    # ---- Cog-death explosion (cosmetic) --------------------------------
    {"id": "cog_death_duration", "group": "cog_death", "kind": "const", "op": "div",
     "modules": ["MovieUtil", "toontown.battle.MovieUtil"], "target": "SUIT_LOSE_DURATION"},
    {"id": "cog_death_track", "group": "cog_death", "kind": "wrap_func",
     "modules": ["MovieUtil", "toontown.battle.MovieUtil"], "target": "createSuitDeathTrack"},
    {"id": "cog_revive_track", "group": "cog_death", "kind": "wrap_func",
     "modules": ["MovieUtil", "toontown.battle.MovieUtil"], "target": "createSuitReviveTrack"},

    # ---- Dodge "step back" (cosmetic playback) -------------------------
    {"id": "toon_dodge", "group": "dodge", "kind": "wrap_func",
     "modules": ["MovieUtil", "toontown.battle.MovieUtil"], "target": "createToonDodgeMultitrack"},
    {"id": "suit_dodge", "group": "dodge", "kind": "wrap_func",
     "modules": ["MovieUtil", "toontown.battle.MovieUtil"], "target": "createSuitDodgeMultitrack"},

    # ---- Door client-side animation (client half only) -----------------
    {"id": "door_enter", "group": "door", "kind": "wrap_method",
     "modules": ["DistributedDoor", "toontown.building.DistributedDoor"],
     "cls": "DistributedDoor", "target": "avatarEnterDoorTrack"},
    {"id": "door_exit", "group": "door", "kind": "wrap_method",
     "modules": ["DistributedDoor", "toontown.building.DistributedDoor"],
     "cls": "DistributedDoor", "target": "avatarExitDoorTrack"},

    # ---- Combat run-in (client run-in => earlier client-driven d_joinDone)
    {"id": "runin_suit", "group": "runin", "kind": "attr", "op": "mul",
     "modules": ["BattleBase", "toontown.battle.BattleBase"],
     "cls": "BattleBase", "target": "suitSpeed"},
    {"id": "runin_toon", "group": "runin", "kind": "attr", "op": "mul",
     "modules": ["BattleBase", "toontown.battle.BattleBase"],
     "cls": "BattleBase", "target": "toonSpeed"},
]


def resolve_module(modnames):
    """Return an already-imported module from the candidate names, or try to
    import it.  Returns (module, name) or (None, None)."""
    for name in modnames:
        m = sys.modules.get(name)
        if m is not None:
            return m, name
    for name in modnames:
        try:
            __import__(name)
            m = sys.modules.get(name)
            if m is not None:
                return m, name
        except Exception:
            continue
    return None, None


def _holder_and_attr(patch):
    """Return (holder_object, attr_name, module_name) for a patch, or (None,...).
    holder is the module for const/wrap_func, or the class for attr/wrap_method."""
    mod, name = resolve_module(patch["modules"])
    if mod is None:
        return None, None, None
    if patch.get("cls"):
        cls = getattr(mod, patch["cls"], None)
        if cls is None:
            # diagnostics
            report["modules_seen"].setdefault(name, [])
            return None, None, name
        return cls, patch["target"], name
    return mod, patch["target"], name


def _make_playrate_wrapper(true_orig, factor, is_method):
    if is_method:
        def wrapped(self, *a, **k):
            ival = true_orig(self, *a, **k)
            try:
                ival.setPlayRate(factor)
            except Exception:
                pass
            return ival
    else:
        def wrapped(*a, **k):
            ival = true_orig(*a, **k)
            try:
                ival.setPlayRate(factor)
            except Exception:
                pass
            return ival
    wrapped._ttrmod_wrapped = True
    wrapped._ttrmod_orig = true_orig
    return wrapped


def apply_patch(patch, group_cfg):
    pid = patch["id"]
    factor = float(group_cfg.get("factor", 2.0))
    holder, attr, modname = _holder_and_attr(patch)
    if holder is None:
        report["skipped"].append({"id": pid, "reason": "module/class not loaded yet"})
        return
    if not hasattr(holder, attr):
        # log what similar names ARE present so a renamed build is diagnosable
        present = [n for n in dir(holder) if not n.startswith("__")]
        hint = [n for n in present if attr.split("createSuit")[-1][:4].lower() in n.lower()] if "create" in attr else []
        report["modules_seen"].setdefault(modname, sorted(present)[:60])
        report["skipped"].append({"id": pid, "reason": "attr %r absent (hint: %s)" % (attr, hint)})
        return

    key = "%s|%s.%s" % (pid, modname, attr)
    # store the TRUE original exactly once
    if key not in reg["orig"]:
        reg["orig"][key] = getattr(holder, attr)
    true_orig = reg["orig"][key]

    try:
        if patch["kind"] in ("const", "attr"):
            base = true_orig
            if patch["op"] == "div":
                new = base / factor
            else:
                new = base * factor
            setattr(holder, attr, new)
            report["applied"].append({"id": pid, "target": "%s.%s" % (modname, attr),
                                       "detail": "%r -> %r (op=%s x%.3g)" % (base, new, patch["op"], factor)})
        elif patch["kind"] in ("wrap_func", "wrap_method"):
            is_method = patch["kind"] == "wrap_method"
            wrapped = _make_playrate_wrapper(true_orig, factor, is_method)
            setattr(holder, attr, wrapped)
            reg["wrapped"].add(key)
            report["applied"].append({"id": pid, "target": "%s.%s" % (modname, attr),
                                       "detail": "setPlayRate(%.3g) wrapper" % factor})
        else:
            report["skipped"].append({"id": pid, "reason": "unknown kind %r" % patch["kind"]})
    except Exception as e:
        _log_err("apply %s" % pid, e)


def revert_all():
    report["revert"] = True
    for key, orig in list(reg["orig"].items()):
        pid, dotted = key.split("|", 1)
        modname, attr = dotted.rsplit(".", 1)
        # re-resolve holder for this patch id
        patch = next((p for p in PATCHES if p["id"] == pid), None)
        if patch is None:
            continue
        holder, attr2, _ = _holder_and_attr(patch)
        if holder is None:
            report["skipped"].append({"id": pid, "reason": "module gone; nothing to revert"})
            continue
        try:
            setattr(holder, attr, orig)
            report["reverted"].append({"id": pid, "target": dotted})
        except Exception as e:
            _log_err("revert %s" % pid, e)
    reg["orig"].clear()
    reg["wrapped"].clear()
    remove_import_hook()


# --------------------------------------------------------------------------
# Optional import hook: re-apply patches when a target module loads later
# (e.g. attach at the login screen, patches kick in when the battle modules
# get imported).  Wraps builtins.__import__ once; fully reversible.
# --------------------------------------------------------------------------
def install_import_hook(cfg):
    if reg["hook_installed"]:
        return
    target_mod_names = set()
    for p in PATCHES:
        for m in p["modules"]:
            target_mod_names.add(m)
    orig_import = builtins.__import__
    reg["orig_import"] = orig_import
    _busy = {"v": False}

    def hooked(name, *a, **k):
        module = orig_import(name, *a, **k)
        if not _busy["v"] and name in target_mod_names:
            _busy["v"] = True
            try:
                apply_enabled(cfg)  # cheap + idempotent
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
    else:
        apply_enabled(cfg)
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
    # Also echo to the game's stdout/log for good measure.
    try:
        sys.stdout.write("[ttrmod] applied=%d skipped=%d reverted=%d errors=%d\n" % (
            len(report["applied"]), len(report["skipped"]),
            len(report["reverted"]), len(report["errors"])))
        sys.stdout.flush()
    except Exception:
        pass


main()
