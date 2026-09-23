#!/usr/bin/env python3
# trampoline_inject.py -- LIVE C-API-orchestration injector for TTREngine.
#
# The engine's opcode cipher makes injected BYTECODE unrunnable (see STATUS.md journey #9),
# so instead of running a Python payload we install native method-wrappers ("trampolines"):
# a frida NativeCallback -> PyCFunction_NewEx -> instancemethod (self-binding) -> setattr onto
# the game class. NO Python bytecode is ever executed, so the cipher is irrelevant. The
# mechanism is proven offline (localtest/trampoline_test.py = PASS).
#
# MILESTONE 1 (--probe / TTRMOD_MODE=install|selftest): install a PASS-THROUGH trampoline on ONE
# real, loaded game method (default direct.showbase.Transitions.fadeOut) that just calls the
# original and reports each time it fires. Proves the mechanism works IN THE LIVE ENGINE with zero
# behavior change / minimal crash risk.
#
# MILESTONE 2 (TTRMOD_MODE=mod1): the first REAL cosmetic speedup -- a "wrap-after" trampoline on
# the street-tunnel walk (LocalToon.handleTunnelIn/handleTunnelOut). It calls the original, finds
# the tunnelTrack interval it just started, and setPlayRate(5.0)s it (float built by hand via the
# STATUS.md recipe). Chosen as the first live target because it is triggerable with pure keyboard
# movement (walk into any street tunnel) -- no menus/clicks. The wrap-after + manual-PyFloat
# machinery is validated offline in localtest/wrapafter_test.py and localtest/pyfloat_test.py.
#
# Symbols come from capi-symbols.json (+ capi-symbols2.json), the RE'd C-API addresses; the
# agent adds the runtime ASLR slide (base - image_base), same model as inject.py. Run as root:
#   sudo -n TTRMOD_SCRIPT=frida/trampoline_inject.py frida/run-injector.sh --probe
#   sudo -n env TTRMOD_MODE=mod1 TTRMOD_SCRIPT=frida/trampoline_inject.py frida/run-injector.sh

import os
import sys
import json
import signal
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMAGE_BASE = 0x100000000

# Host platform (the AGENT runs inside the target and is per-build; this only gates HOST plumbing).
IS_WINDOWS = sys.platform.startswith("win")
# Substring(s) that identify the engine process by name (frida's Windows enumeration exposes the
# exe name, e.g. TTREngine.exe; posix keeps the proven `pgrep -f TTREngine`). Env-overridable so the
# Windows agent can retarget with no code edits (mirrors the tray's TTRFF_ENGINE_NAMES).
ENGINE_NEEDLES = [s.strip().lower() for s in
                  os.environ.get("TTRMOD_ENGINE_NAMES", "TTREngine,Toontown Rewritten").split(",")
                  if s.strip()]

# milestone-1 target (env-overridable): a class that is always loaded and easy to trigger.
T_MODULE = os.environ.get("TTRMOD_TMOD", "direct.showbase.Transitions")
T_CLASS  = os.environ.get("TTRMOD_TCLS", "Transitions")
T_METHOD = os.environ.get("TTRMOD_TMETH", "fadeOut")

# Constants confirmed by the RE pass (capi-symbols.json _meta).
INSTANCEMETHOD_TYPE = 0x101a79c20
TSTATE_CELL         = 0x101c0acd8   # *cell = current PyThreadState
INTERP_OFF          = 0x10          # tstate -> interp
MODULES_OFF         = 0x38          # interp -> modules dict (== sys.modules)
# CPython 3.8 struct offsets for reading the SPAWNING frame's function name (approach-2
# spawn-context scaling). ABI-fixed by the interpreter version (3.8.x, 64-bit) -- identical
# between TTR's 3.8.17 and stock 3.8.14, and VERIFIED end-to-end offline against real CPython
# 3.8 frames (localtest/spawnctx_test.py asserts co_name reads back correctly). Chain:
# tstate->frame (PyThreadState.frame) -> f_code (PyFrameObject.f_code) -> co_name (PyCodeObject.co_name).
FRAME_OFF           = 0x18          # PyThreadState.frame   (interp @ +0x10, curexc @ +0x58 bracket it)
FCODE_OFF           = 0x20          # PyFrameObject.f_code   (after PyObject_VAR_HEAD 0x18 + f_back 0x18)
CONAME_OFF          = 0x70          # PyCodeObject.co_name   (a str; read via PyUnicode_AsUTF8)

# milestone-2 manual PyFloat builder (STATUS.md recipe; PyFloat_FromDouble is inlined away).
# Absolute vmaddrs -> slid at runtime. Layout validated offline in localtest/pyfloat_test.py
# (stock 3.8 has the IDENTICAL 24-byte layout: ob_type @ +8, ob_fval @ +0x10; only addrs differ).
FLOAT_TYPE      = 0x101aae5c8       # &PyFloat_Type
FLOAT_FREELIST  = 0x101be9588       # float free-list head
FLOAT_NUMFREE   = 0x101be9590       # int32 numfree (8 after the head, MAXFREELIST 100)
PYMALLOC_FN     = 0x101a7a668       # _PyObject allocator .malloc (fn ptr)
PYMALLOC_CTX    = 0x101a7a660       # _PyObject allocator .ctx

# ---- Windows per-build overrides (TTREngine64.exe 3.2.0.609, PDB GUID 51124cdf...) ----
# Derived 2026-09-23 from an OUT-OF-PROCESS dump of the unpacked image; see STATUS.md
# "Windows per-build derivation" and capi-symbols-win.json. Every value here was confirmed by
# capstone disassembly, not inferred. The four `None`s below are the ONLY thing still blocking a
# Windows attach -- and they are WRITE targets used by the agent's hand-built makeFloat(), so a
# wrong value corrupts the client rather than merely failing. WIN_MISSING gates the attach on them.
WIN_IMAGE_BASE          = 0x140000000
WIN_INSTANCEMETHOD_TYPE = 0x141ea2950   # tp_name "instancemethod"
WIN_TSTATE_CELL         = 0x1420d2fb8   # read out of PyObject_Call's _PyThreadState_GET()
WIN_FLOAT_TYPE          = 0x141f76c68   # tp_name "float", tp_basicsize == 24 (unambiguous)
# Not needed on Windows: PyFloat_FromDouble is OUT-OF-LINE in this build (it is inlined away on
# arm64, which is the only reason the hand-built makeFloat recipe exists), so the agent calls it
# and CPython does its own freelist bookkeeping. Left here, recorded, because they are the
# arm64-style fallback inputs and are useful if a future Windows build inlines it after all:
#   float freelist head 0x141fc3838, numfree 0x141fc3840 (verified: head non-NULL iff numfree > 0)
WIN_FLOAT_FREELIST      = None
WIN_FLOAT_NUMFREE       = None
WIN_PYMALLOC_FN         = None
WIN_PYMALLOC_CTX        = None
# Struct offsets are CPython-version-specific, NOT architecture-specific: INTERP_OFF, MODULES_OFF,
# FRAME_OFF, FCODE_OFF and CONAME_OFF above were re-confirmed unchanged on x86-64, so they stand.

if IS_WINDOWS:
    IMAGE_BASE          = WIN_IMAGE_BASE
    INSTANCEMETHOD_TYPE = WIN_INSTANCEMETHOD_TYPE
    TSTATE_CELL         = WIN_TSTATE_CELL
    FLOAT_TYPE          = WIN_FLOAT_TYPE
    FLOAT_FREELIST      = WIN_FLOAT_FREELIST
    FLOAT_NUMFREE       = WIN_FLOAT_NUMFREE
    PYMALLOC_FN         = WIN_PYMALLOC_FN
    PYMALLOC_CTX        = WIN_PYMALLOC_CTX

def win_float_gap(syms):
    """[] when the Windows build can build a Python float, else the reason it cannot.

    Two ways to satisfy it: a real PyFloat_FromDouble (preferred -- CPython does its own freelist
    bookkeeping, so we never write to interpreter state), or the arm64-style hand-built recipe,
    which needs all four allocator constants. Anything else and setPlayRate cannot be called."""
    if "PyFloat_FromDouble" in syms:
        return []
    need = [n for n, v in (("FLOAT_FREELIST", WIN_FLOAT_FREELIST),
                           ("FLOAT_NUMFREE", WIN_FLOAT_NUMFREE),
                           ("PYMALLOC_FN", WIN_PYMALLOC_FN),
                           ("PYMALLOC_CTX", WIN_PYMALLOC_CTX)) if v is None]
    return need

# mod1 -- the FIRST live target: the street tunnel walk, triggerable with pure keyboard movement
# (walk the toon into/out of any street tunnel; no mouse). From inproc/payload.py's `tunnel` group:
#   class LocalToon; methods handleTunnelIn/handleTunnelOut; wrap-after; interval attr 'tunnelTrack';
#   factor 5.0. The vault loads LocalToon under a fully HASHED module name (vlt24ab6c6d.<hash>.<hash>),
#   so name-based resolution FAILS. mod1 now SELF-DISCOVERS the target class by its method signature
#   (the shared read-only scan), preferring the class where both methods are defined directly. A
#   TTRMOD_TMOD/TTRMOD_TCLS pair (both set) forces name-based resolution instead. `methods` is filled
#   from TTRMOD_METHODS at startup (default handleTunnelIn,handleTunnelOut).
MOD1 = {
    "methods":  ["handleTunnelIn", "handleTunnelOut"],   # overwritten from TTRMOD_METHODS in main()
    "spec":     {"mode": "attr", "attr": "tunnelTrack"},
    "factor":   5.0,
    "override": None,                                    # {"module":..,"cls":..} if TTRMOD_TMOD+TCLS set
    "context":  [],                                      # wrap-around context targets (modset only): [{method,factor,group}]
}

# GENERAL INTERVAL HOOK target (the proven-live modset class). Every Panda Sequence/Parallel/Track
# is one Python MetaInterval whose .start() we wrap; reading self.getName() then setPlayRate(self,..)
# scales it on-the-fly. This is the class the first measured live speedup (teleport ~4.9x) went
# through. Names are per-build (hashed) -> re-derive on an engine auto-patch (signature scan below).
META_INTERVAL_MODULE = "direct.vltf283acbe.vlt615404bc"
META_INTERVAL_CLASS  = "vlt615404bc"
# discovery signature (only used if the pinned override is cleared): the Python MetaInterval is the
# class defining start+setPlayRate+append+clearIntervals (the C++ CInterval base lacks the list
# builders; NB addSequence from vanilla Panda is renamed away here -> use clearIntervals).
META_INTERVAL_SIG    = ["start", "setPlayRate", "append", "clearIntervals"]

# C-API needed for milestone 1 (pass-through install). vmaddr+prologue pulled from the JSONs.
NEED = ["PyObject_Call", "PyObject_GetAttrString", "PyObject_SetAttrString",
        "PyCFunction_NewEx", "PyDict_GetItemString"]
# a way to build the 1-tuple (callable,) for the self-bind: PyTuple_New(+SetItem) OR PyTuple_Pack
TUPLE_EITHER = ["PyTuple_New", "PyTuple_Pack"]


def load_symbols():
    syms = {}
    # Windows has its own per-build table (different binary, different image base); the macOS
    # arm64 tables must never be loaded there -- their vmaddrs would be garbage.
    tables = ("capi-symbols-win.json",) if IS_WINDOWS else ("capi-symbols.json", "capi-symbols2.json")
    for fn in tables:
        p = os.path.join(ROOT, fn)
        if not os.path.exists(p):
            continue
        data = json.load(open(p))
        for name, ent in data.items():
            if name == "_meta" or not isinstance(ent, dict):
                continue
            va = ent.get("vmaddr")
            if va and str(ent.get("found", "")).lower() in ("yes", "true", ""):
                syms[name] = {"vmaddr": int(str(va), 16),
                              "prologue16": ent.get("prologue16") or ent.get("verify")}
    return syms


def load_modset(path):
    """Load the modset name->factor table. Each active entry -> {match, factor, group, prefix}.
    Entries with enabled:false (the stubbed/pending groups, e.g. battle) are skipped. `pending`
    is a free-form list ignored by the loader (documentation of names still to confirm live).

    Also loads the `context` section: entries -> {method, factor, group}. These are wrap-AROUND
    CONTEXT targets -- a method (resolved to its owning class by its signature) whose call sets a
    global context so that intervals STARTED during it are scaled by CREATION CONTEXT rather than by
    name (for fire-and-forget / auto-named intervals like the tunnel walk). enabled:false skips a
    context entry (e.g. tunnelIn, whose real method name is hashed and still to be discovered).

    And the `spawn_context` section: entries -> {co_name, factor, group}. These scale an interval by
    the co_name of the Python frame that CALLED start() -- i.e. the (possibly hashed) name of the
    function that spawned it. This is the approach-2 mechanism for fire-and-forget / auto-named
    intervals whose OWN name matches nothing and whose synchronous creator is a HASHED method that
    can't be wrapped by readable name (the street-tunnel WALK: LocalToon.handleTunnelOut/In build an
    unnamed self.tunnelTrack and start() it). Exact co_name match, so only intervals spawned by a
    named function are touched. enabled:false skips one."""
    data = json.load(open(path))
    entries = []
    for e in data.get("entries", []):
        if not e.get("enabled", True):
            continue
        m = e.get("match")
        if not m:
            continue
        entries.append({"match": m, "factor": float(e.get("factor", 3.0)),
                        "group": e.get("group", "?"), "prefix": bool(e.get("prefix", False))})
    context = []
    for c in data.get("context", []):
        if not c.get("enabled", True):
            continue
        meth = c.get("method")
        if not meth:
            continue
        context.append({"method": meth, "factor": float(c.get("factor", 3.0)),
                        "group": c.get("group", "?")})
    spawn = []
    for s in data.get("spawn_context", []):
        if not s.get("enabled", True):
            continue
        co = s.get("co_name")
        if not co:
            continue
        spawn.append({"co_name": co, "factor": float(s.get("factor", 3.0)),
                      "group": s.get("group", "?")})
    # `tunnel_identity`: the street-tunnel WALK, scaled by OBJECT IDENTITY (localAvatar.tunnelTrack), not
    # by name/co_name. attr=null -> auto-discover the hashed attr on the first iris-correlated walk, then
    # pin it in memory; set attr to pin it up front (no discovery). factor/iris_window_ms tune it;
    # enabled:false turns the whole tunnel-identity path off. A free-form object, passed through as-is.
    tunnel = data.get("tunnel_identity") or {}
    # `tunnel_localtoon_iris`: the DETERMINISTIC tunnel-ARRIVAL mechanism (the primary one). The arrival
    # handler handleTunnelIn is a (HASHED) method of the LocalToon CLASS -- which resolves reliably by the
    # `tunnelOut` method signature -- and it calls base.transitions.irisIn synchronously right before it
    # starts the walk Sequence. So an interval whose SPAWNING-FRAME co_name is a member of LocalToon's own
    # method set AND which started inside the iris window is the local toon's tunnel walk -- regardless of
    # the per-session hash (no hardcoded co_name; the whole method set is re-derived live each session).
    # factor/iris_window_ms tune it; lt_signature = the readable method(s) that uniquely resolve LocalToon
    # (default ["tunnelOut"]); enabled:false turns it off. A free-form object, passed through as-is.
    ltiris = data.get("tunnel_localtoon_iris") or {}
    return entries, bool(data.get("log_unmatched", True)), context, spawn, tunnel, ltiris


def readiness(syms):
    missing = [n for n in NEED if n not in syms]
    tuple_fn = next((n for n in TUPLE_EITHER if n in syms), None)
    if tuple_fn is None:
        missing.append("PyTuple_New|PyTuple_Pack")
    elif tuple_fn == "PyTuple_New" and "PyTuple_SetItem" not in syms:
        # PyTuple_New alone can't fill the tuple; need SetItem too (unless Pack is available)
        if "PyTuple_Pack" in syms:
            tuple_fn = "PyTuple_Pack"
        else:
            missing.append("PyTuple_SetItem (needed with PyTuple_New)")
    return missing, tuple_fn


AGENT = r"""
'use strict';
var ST = null;
function vf(name, addr, want){   // verify prologue bytes
  if (!want) return true;
  var b = new Uint8Array(addr.readByteArray(want.length));
  for (var i=0;i<want.length;i++){ if (b[i]!==want[i]) return false; }
  return true;
}
rpc.exports = {
  init: function (p) {
    var out = { ok:false, verified:true, notes:[], resolved:{} };
    try {
      var base = Process.mainModule.base;
      var slide = base.sub(ptr(p.image_base));
      out.slide = slide.toString();
      function rt(v){ return ptr(v).add(slide); }
      var F = {};
      for (var name in p.syms){
        var a = rt(p.syms[name].vmaddr);
        var pl = p.syms[name].prologue16;
        if (pl){ var arr = pl.trim().split(/\s+/).map(function(h){return parseInt(h,16);});
                 if (!vf(name, a, arr)){ out.notes.push('VERIFY FAILED: '+name); out.verified=false; } }
        F[name] = a; out.resolved[name] = a.toString();
      }
      ST = {
        slide: slide,
        hook:       rt(p.hook_va),   // _PyEval_EvalFrameDefault: install on main thread, GIL held
        Call:       new NativeFunction(F['PyObject_Call'],          'pointer', ['pointer','pointer','pointer']),
        GetAttrStr: new NativeFunction(F['PyObject_GetAttrString'], 'pointer', ['pointer','pointer']),
        SetAttrStr: new NativeFunction(F['PyObject_SetAttrString'], 'int',     ['pointer','pointer','pointer']),
        CFuncNewEx: new NativeFunction(F['PyCFunction_NewEx'],      'pointer', ['pointer','pointer','pointer']),
        DictGetStr: new NativeFunction(F['PyDict_GetItemString'],   'pointer', ['pointer','pointer']),
        imType:     rt(p.instancemethod_type),
        cell:       rt(p.tstate_cell),
        interp_off: p.interp_off, modules_off: p.modules_off,
        frame_off:  p.frame_off, fcode_off: p.fcode_off, coname_off: p.coname_off,
        tmod: p.tmod, tcls: p.tcls, tmeth: p.tmeth,
        done:false, keep:[], installed:[],
        // WRAP-AROUND CONTEXT (context-scaling). ctx is null except while a wrapped context
        // method (e.g. LocalToon.tunnelOut) is on the stack, when it holds {group, factor, label}.
        // The MetaInterval.start hook scales -- by ctx.factor -- any interval that STARTS while
        // ctx is set, so fire-and-forget / auto-named intervals (the tunnel walk) are caught by
        // CREATION CONTEXT instead of by name. Nesting-safe: each ctx wrapper saves+restores prev.
        ctx: null
      };
      // 1-tuple builder for the self-bind: prefer PyTuple_New+SetItem, else PyTuple_Pack.
      if (F['PyTuple_New'] && F['PyTuple_SetItem']){
        ST.TupleNew = new NativeFunction(F['PyTuple_New'], 'pointer', ['long']);
        ST.TupleSet = new NativeFunction(F['PyTuple_SetItem'], 'int', ['pointer','long','pointer']);
        ST.pack1 = function(o){ var t = ST.TupleNew(1); ST.TupleSet(t, 0, o); return t; };  // SetItem steals ref
      } else if (F['PyTuple_Pack']){
        ST.TuplePack = new NativeFunction(F['PyTuple_Pack'], 'pointer', ['long','...','pointer']);
        ST.pack1 = function(o){ return ST.TuplePack(1, o); };
      } else { out.notes.push('no tuple builder'); }
      // read-only module-listing / signature-scan helpers (present in capi-symbols2)
      if (F['PyObject_GetIter']) ST.GetIter = new NativeFunction(F['PyObject_GetIter'], 'pointer', ['pointer']);
      if (F['PyIter_Next'])      ST.IterNext = new NativeFunction(F['PyIter_Next'], 'pointer', ['pointer']);
      if (F['PyUnicode_AsUTF8']) ST.AsUTF8   = new NativeFunction(F['PyUnicode_AsUTF8'], 'pointer', ['pointer']);
      if (F['PyObject_GetItem']) ST.GetItem  = new NativeFunction(F['PyObject_GetItem'], 'pointer', ['pointer','pointer']);
      if (F['PyDict_GetItem'])   ST.DictGetItem = new NativeFunction(F['PyDict_GetItem'], 'pointer', ['pointer','pointer']);
      ST.methods = p.methods || [];          // requested method-signature for findcls/mod1 self-discovery
      ST.methodGroups = p.method_groups || []; // findmeth: N exact all-present group scans
      ST.substrs = p.substrs || [];          // findmeth: method-name substring discovery
      ST.listClasses = p.list_classes || []; // findmeth: dump these classes' own method names
      ST.tpname = function(o){ try { return o.add(8).readPointer().add(0x18).readPointer().readCString(); } catch(e){ return '?'; } };
      ST.mode = p.mode || 'install';
      // sys.modules = *(*(*cell + interp_off) + modules_off)
      ST.sysmodules = function(){
        var t = ST.cell.readPointer(); if (t.isNull()) return ptr(0);
        var interp = t.add(ST.interp_off).readPointer(); if (interp.isNull()) return ptr(0);
        return interp.add(ST.modules_off).readPointer();
      };
      // co_name of the CURRENT Python frame = tstate->frame->f_code->co_name (approach-2 spawn
      // context). Read from inside the wrap-after start() trampoline, where the current frame is the
      // CALLER of start() (our native start trampoline pushes no Python frame), i.e. the function
      // that spawned the interval -- the hashed handleTunnelOut/handleTunnelIn for the tunnel walk.
      // Pure pointer reads + one PyUnicode_AsUTF8; returns a JS string or null (never leaves an exc).
      ST.spawnCoName = function(){
        try {
          if (!ST.AsUTF8) return null;
          var t = ST.cell.readPointer(); if (t.isNull()) return null;
          var fr = t.add(ST.frame_off).readPointer(); if (fr.isNull()) return null;
          var code = fr.add(ST.fcode_off).readPointer(); if (code.isNull()) return null;
          var nameObj = code.add(ST.coname_off).readPointer(); if (nameObj.isNull()) return null;
          var s = null; try { s = ST.AsUTF8(nameObj).readCString(); } catch(e){ s = null; }
          if (s === null) ST.clearExc();
          return s;
        } catch(e){ ST.clearExc(); return null; }
      };
      // CRITICAL: a failed C-API call (esp. PyObject_GetAttrString on a missing attr) leaves a
      // pending Python exception on the tstate; if we detach without clearing it, the game's next
      // task inherits it -> AttributeError -> panic/disconnect. Clear curexc (+0x58/+0x60/+0x68,
      // verified) on EVERY abort/exit path. (Leaks up to 3 refs on the error path -- negligible.)
      ST.clearExc = function(){
        try { var t = ST.cell.readPointer();
              if (!t.isNull()){ t.add(0x58).writePointer(ptr(0)); t.add(0x60).writePointer(ptr(0)); t.add(0x68).writePointer(ptr(0)); } }
        catch(e){}
      };
      // clear-then-report-done: use for ALL onEnter exits so no exception ever leaks into the game.
      ST.fin = function(r){ ST.clearExc(); try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){} send({t:'done', r:r}); };
      // RECORD EVERY INSTALLED WRAP IN ONE PLACE. revert() restores exactly what is in ST.installed,
      // so any wrap that is SetAttrStr'd onto a class MUST be recorded here or revert will skip it --
      // and a skipped wrap leaves its trampoline (native agent memory) installed, so when the session
      // drops that method points at freed memory and the game crashes on the very next call. Every
      // install site (the MetaInterval.start wrap-after, each context wrap-around like tunnelOut, and
      // the legacy single install) funnels through this; revert enumerates ST.installed to restore ALL.
      ST.recordInstall = function(cls, mn, orig){ try { ST.installed.push({cls:cls, mn:mn, orig:orig}); } catch(e){} };

      // ---- milestone-2: manual PyFloat builder + generic wrap-after (payload.py port) ----
      // PREFERRED: a real out-of-line PyFloat_FromDouble. It exists on the Windows build; on the
      // arm64 build it is inlined away, which is the only reason the hand-built recipe below exists.
      // Calling it lets CPython manage its own freelist, so we never WRITE to interpreter
      // bookkeeping ourselves -- strictly safer than popping the freelist by hand.
      ST.FloatFromDouble = null;
      try {
        if (F['PyFloat_FromDouble'])
          ST.FloatFromDouble = new NativeFunction(F['PyFloat_FromDouble'], 'pointer', ['double']);
      } catch(e){ ST.FloatFromDouble = null; }
      if (p.floatv){
        ST.FloatType     = p.floatv.type      ? rt(p.floatv.type)      : null;
        ST.floatFreelist = p.floatv.freelist  ? rt(p.floatv.freelist)  : null;
        ST.floatNumfree  = p.floatv.numfree   ? rt(p.floatv.numfree)   : null;
        ST.mallocFnPtr   = p.floatv.malloc_fn ? rt(p.floatv.malloc_fn) : null;
        ST.mallocCtxPtr  = p.floatv.malloc_ctx ? rt(p.floatv.malloc_ctx) : null;
        ST.Malloc = null; ST.mallocCtx = null;
      }
      ST.mod1 = p.mod1 || null;
      ST.probeAttrs = !!(ST.mod1 && ST.mod1.probe_attrs);   // mod1 first-fire __dict__ diagnostic
      // ---- BATTLETRACE (READ-ONLY diagnosis, TTRMOD_BATTLETRACE=1) ----
      // Purpose: attribute each inter-step battle delay to a CLIENT timer (scalable) or a SERVER-gated
      // event (a hard limit). It changes NOTHING -- it installs logging-only wraps that timestamp the
      // key battle events so their ordering + gaps are visible, on top of (and orthogonal to) whatever
      // scaling the modset is doing. HASHING-PROOF: the battle FSM class + the d_*Done helper methods are
      // per-build HASHED (co_name AND class-dict key), so nothing is named. Two layers:
      //   (1) METHOD trace -- resolve the battle class by a signature of PRESERVED INBOUND DC field names
      //       (btSig, default setState+setMembers+setMovie: a DC field's method name is fixed by the wire
      //       contract -- C++ receiveUpdate calls it by that name -- so it survives obfuscation). Then wrap
      //       the INBOUND `setState` (server state-change: names the state; we wrap setState not the FSM
      //       enter* methods because ClassicFSM captures `self.enterX` as a bound method at __init__, so
      //       replacing enterX on the class is invisible to it -- whereas setState is the DC field the
      //       server calls by name and it synchronously drives the enter, so its timestamp == the
      //       state-enter time AND names the state) and the OUTBOUND `sendUpdate` (the readable direct-tree
      //       DistributedObject sender; d_movieDone/d_faceOffDone/d_rewardDone/d_joinDone are each just
      //       `self.sendUpdate('<name>Done', ...)`, so wrapping sendUpdate ON THE BATTLE CLASS and logging
      //       only field names ending in 'Done' captures the client's "step finished" reports by their
      //       fixed DC string, regardless of the hashed d_* helper name, and scoped to battle objects).
      //   (2) INTERVAL trace -- in the modset start hook, timestamp when a battle interval (faceoff-battle
      //       / movie-track / movie-reward-track / to-pending) STARTS and read its getDuration()/
      //       getPlayRate() (read-only), so the movie's real end == start + duration/playRate can be
      //       compared to when the outbound movieDone fires.
      ST.bt        = (ST.mod1 && ST.mod1.battletrace) ? ST.mod1.battletrace : null;
      ST.btEnabled = !!(ST.bt && ST.bt.enabled);
      ST.btMethods = (ST.bt && ST.bt.methods && ST.bt.methods.length) ? ST.bt.methods : [];
      ST.btSig     = (ST.bt && ST.bt.sig && ST.bt.sig.length) ? ST.bt.sig : ['setState', 'setMembers', 'setMovie'];
      ST.btNames   = (ST.bt && ST.bt.names && ST.bt.names.length) ? ST.bt.names : [];
      ST.btInstalled = false;   // idempotent guard: the FSM class may load only on the first battle
      // TUNNEL-IDENTITY (the street-tunnel WALK). The walk interval is localAvatar.tunnelTrack -- an
      // UNNAMED Sequence (auto-named vlt8e0d5a85-<n>) built + start()ed by the HASHED handlers
      // handleTunnelOut/handleTunnelIn and stored under a HASHED attr -- so it matches NO name entry and
      // its spawn co_name is hashed. It is therefore identified by OBJECT IDENTITY: the starting interval
      // IS localAvatar.<tunnelAttr>. The (hashed) attr is auto-discovered on the first iris-correlated
      // walk (handleTunnelIn calls base.transitions.irisIn synchronously right before start), then PINNED
      // so every later walk (both directions) scales by identity alone. Config arrives via the modset spec
      // (modset.json `tunnel_identity`, env-overridable). See STATUS.md "Tunnel walk by object identity".
      var tcfg = (ST.mod1 && ST.mod1.spec && ST.mod1.spec.tunnel) ? ST.mod1.spec.tunnel : null;
      ST.tunnelCfg = tcfg;
      ST.tunnelEnabled = !!(tcfg && tcfg.enabled !== false);
      ST.tunnelAttr = (tcfg && tcfg.attr) ? tcfg.attr : null;         // pinned hashed attr, else discover
      ST.tunnelFactor = (tcfg && tcfg.factor) ? tcfg.factor : 4.0;
      ST.irisWindowMs = (tcfg && tcfg.iris_window_ms) ? tcfg.iris_window_ms : 200;
      ST.lastIrisMs = 0;                                              // Date.now() of the last iris start
      ST.localAvatar = null; ST.localAvatarDict = null;               // cached once in-world (stable identity)
      // TUNNEL-LOCALTOON-IRIS (the DETERMINISTIC tunnel-ARRIVAL mechanism, PRIMARY). The arrival handler
      // handleTunnelIn is a HASHED method of the LocalToon CLASS (which resolves reliably by the
      // `tunnelOut` signature) and it calls base.transitions.irisIn synchronously right before starting
      // the walk Sequence. So: an interval whose SPAWNING-FRAME co_name is a member of LocalToon's OWN
      // method set AND which started inside the iris window IS the local toon's tunnel walk -- regardless
      // of the per-session hash. No hardcoded co_name: the whole method set is re-derived live each
      // session, so whatever hash handleTunnelIn got this session is in the set. Config from spec.ltiris.
      var lcfg = (ST.mod1 && ST.mod1.spec && ST.mod1.spec.ltiris) ? ST.mod1.spec.ltiris : null;
      ST.ltIrisEnabled = !!(lcfg && lcfg.enabled !== false);
      ST.ltIrisFactor  = (lcfg && lcfg.factor) ? lcfg.factor : 4.0;
      ST.ltIrisWindowMs = (lcfg && lcfg.iris_window_ms) ? lcfg.iris_window_ms : 200;
      ST.ltSig = (lcfg && lcfg.lt_signature && lcfg.lt_signature.length) ? lcfg.lt_signature : ['tunnelOut'];
      ST.localToonMethods = null;      // SET (co_name -> true) of LocalToon's own methods; null until resolved
      ST.localToonName = null;         // resolved LocalToon class __name__ (for logging)
      ST.lastLtScanMs = 0;             // rate-limit the heavy sys.modules scan while LocalToon is unresolved
      // build a float by hand (STATUS.md recipe): pop the free-list head (relink via +8, numfree--),
      // else pymalloc(24); then ob_refcnt=1 @+0, ob_type=&PyFloat_Type @+8, ob_fval @+0x10.
      ST.makeFloat = function(v){
        // Real PyFloat_FromDouble when the build has one (Windows): CPython does the freelist
        // bookkeeping itself, so nothing here writes to interpreter state.
        if (ST.FloatFromDouble){
          try { return ST.FloatFromDouble(v); } catch(e){ return ptr(0); }
        }
        // Fallback (arm64, where PyFloat_FromDouble is inlined): build one by hand per the
        // STATUS.md recipe. Requires floatFreelist/floatNumfree/malloc pointers.
        if (!ST.floatFreelist || !ST.FloatType) return ptr(0);
        try {
          var op = ptr(0);
          var head = ST.floatFreelist.readPointer();
          if (!head.isNull()){
            var next = head.add(8).readPointer();               // next stored in the ob_type slot
            ST.floatFreelist.writePointer(next);
            ST.floatNumfree.writeS32(ST.floatNumfree.readS32() - 1);
            op = head;
          } else {
            if (ST.Malloc === null){                            // pymalloc: ( *fn )( *ctx, size )
              var fn = ST.mallocFnPtr.readPointer();
              if (fn.isNull()) return ptr(0);
              ST.Malloc = new NativeFunction(fn, 'pointer', ['pointer','ulong']);
              ST.mallocCtx = ST.mallocCtxPtr.readPointer();
            }
            op = ST.Malloc(ST.mallocCtx, 24);
            if (op.isNull()) return ptr(0);
          }
          op.writeU64(1); op.add(8).writePointer(ST.FloatType); op.add(0x10).writeDouble(v);
          return op;
        } catch(e){ return ptr(0); }
      };
      // interval.setPlayRate(factor): getattr the method, call it with a freshly-built float. Any
      // miss clears the pending exception (never leave one set on the tstate -> live-crash guard).
      ST.setPlayRate = function(iv, factorVal){
        try {
          var meth = ST.GetAttrStr(iv, Memory.allocUtf8String('setPlayRate'));
          if (meth.isNull()){ ST.clearExc(); return false; }
          var f = ST.makeFloat(factorVal); if (f.isNull()) return false;
          var r = ST.Call(meth, ST.pack1(f), ptr(0));
          if (r.isNull()){ ST.clearExc(); return false; }
          return true;
        } catch(e){ ST.clearExc(); return false; }
      };
      // ---- TUNNEL WALK by OBJECT IDENTITY (localAvatar.tunnelTrack) ----
      // Resolve + cache base.localAvatar and its instance __dict__ (whose object identity is stable for
      // the avatar's life -- caching one ref keeps it alive). Path mirrors the selftest:
      // sys.modules['builtins'].base.localAvatar, fallback builtins.localAvatar. Caches only a NON-null
      // result, so it retries each start() until the local toon exists (injector may attach pre-login).
      ST.resolveLocalAvatar = function(){
        try {
          if (ST.localAvatar && !ST.localAvatar.isNull()) return ST.localAvatar;
          if (!(ST.DictGetStr && ST.GetAttrStr)) return ptr(0);
          var md = ST.sysmodules(); if (md.isNull()) return ptr(0);
          var bi = ST.DictGetStr(md, Memory.allocUtf8String('builtins'));   // borrowed
          if (bi.isNull()){ ST.clearExc(); return ptr(0); }
          var base = ST.GetAttrStr(bi, Memory.allocUtf8String('base'));
          var av = ptr(0);
          if (!base.isNull()){ av = ST.GetAttrStr(base, Memory.allocUtf8String('localAvatar')); if (av.isNull()) ST.clearExc(); }
          else { ST.clearExc(); }
          if (av.isNull()){ av = ST.GetAttrStr(bi, Memory.allocUtf8String('localAvatar')); if (av.isNull()){ ST.clearExc(); return ptr(0); } }
          ST.localAvatar = av; ST.keep.push(av);
          var d = ST.GetAttrStr(av, Memory.allocUtf8String('__dict__'));
          if (!d.isNull()){ ST.localAvatarDict = d; ST.keep.push(d); } else { ST.clearExc(); ST.localAvatarDict = null; }
          try { send({t:'avatar', tp: ST.tpname(av)}); } catch(e){}
          return av;
        } catch(e){ ST.clearExc(); return ptr(0); }
      };
      // does the interval name look like the screen iris (irisTask, or anything containing 'iris')?
      ST.isIrisName = function(nm){ return !!(nm && nm.toLowerCase().indexOf('iris') >= 0); };
      // scale `inst` as the tunnel walk (tunnel factor), emit [SCALED] with group 'tunnel'; tstate-clean.
      ST.scaleTunnel = function(inst, nm, why){
        var ok = ST.setPlayRate(inst, ST.tunnelFactor);
        if (ok){ try {
          ST.scaledNames = ST.scaledNames || {}; var first = (ST.scaledNames[nm] === undefined);
          ST.scaledNames[nm] = (ST.scaledNames[nm]||0) + 1;
          ST.scaledGroups = ST.scaledGroups || {}; ST.scaledGroups['tunnel'] = (ST.scaledGroups['tunnel']||0) + 1;
          if (first) send({t:'scaled', name:nm, factor:ST.tunnelFactor, group:'tunnel', tunnel:why});
        } catch(e){} }
        ST.clearExc();
        return ok;
      };
      // FAST PATH (pinned attr known): is the starting interval EXACTLY localAvatar.<tunnelAttr>?
      // Borrowed dict read (no descriptor call, no ref leak). ATTR-SPECIFIC -> can never match a
      // different toon interval: the teleport self.track lives under a different attr, so getattr of the
      // tunnel attr returns the tunnel track (or None), never the teleport track. Runs before the name
      // table; the tunnel track is unnamed so ordering is harmless, and this keeps identity authoritative.
      ST.tunnelFastPath = function(inst, nm){
        try {
          if (!ST.tunnelAttr) return false;
          var av = ST.resolveLocalAvatar(); if (av.isNull()) return false;
          var d = ST.localAvatarDict; if (!d || d.isNull()) return false;
          var v = ST.DictGetStr(d, Memory.allocUtf8String(ST.tunnelAttr));   // borrowed
          if (v.isNull()){ ST.clearExc(); return false; }
          if (!v.equals(inst)) return false;
          return ST.scaleTunnel(inst, nm, 'pinned');
        } catch(e){ ST.clearExc(); return false; }
      };
      // DISCOVERY (attr not yet pinned): only NAME-UNMATCHED intervals reach here (teleport & co.
      // returned above via the name table), so this NEVER touches the named teleport self.track. When an
      // unmatched interval starts within the iris window (an irisTask fired in the same handler --
      // handleTunnelIn's synchronous base.transitions.irisIn) AND it IS a value in localAvatar's instance
      // dict, that dict key is the (hashed) tunnel-track attr: pin it (so the fast path scales every
      // later walk in BOTH directions), log [TUNNELATTR], and scale. The iris gate + avatar-ownership
      // keep discovery off unrelated intervals. Borrowed dict iteration (no ref leak). tstate-clean.
      ST.tunnelDiscover = function(inst, nm){
        try {
          if ((Date.now() - (ST.lastIrisMs||0)) > ST.irisWindowMs) return false;   // not iris-correlated
          var av = ST.resolveLocalAvatar(); if (av.isNull()) return false;
          var d = ST.localAvatarDict; if (!d || d.isNull()) return false;
          if (!(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.DictGetItem)) return false;
          var it = ST.GetIter(d); if (it.isNull()){ ST.clearExc(); return false; }
          var k, foundKey = null;
          while (!(k = ST.IterNext(it)).isNull()){
            var v = ST.DictGetItem(d, k);                            // borrowed value
            if (!v.isNull() && v.equals(inst)){ try { foundKey = ST.AsUTF8(k).readCString(); } catch(e){ foundKey = null; } break; }
          }
          ST.clearExc();
          if (foundKey === null) return false;
          ST.tunnelAttr = foundKey;                                  // PIN -> fast path handles both dirs
          var co = null; try { co = ST.spawnCoName(); } catch(e){ co = null; }
          try { send({t:'tunnelattr', attr:foundKey, co:co, sample:nm}); } catch(e){}
          return ST.scaleTunnel(inst, nm, 'discovered');
        } catch(e){ ST.clearExc(); return false; }
      };
      // ---- TUNNEL-LOCALTOON-IRIS (the DETERMINISTIC tunnel-ARRIVAL path) ----
      // Resolve LocalToon by the ltSig signature (default ['tunnelOut'] -- a UNIQUE signature that
      // resolves LocalToon without ever naming its per-build hash) and cache the SET of its OWN method
      // names (the class's tp_dict keys @ +0x108). This set includes the HASHED handleTunnelIn/
      // handleTunnelOut, because the vault renames a `def NAME`'s co_name AND its class-attribute key to
      // the SAME hash -- so co_name == tp_dict key for a method. Non-dunder keys only (drop __init__/etc.,
      // which are collision-prone shared names -- the tunnel handlers are never underscore-prefixed), which
      // matches the existing listcls/scanBySubstr filter. Read-only (borrowed lookups + pointer reads);
      // clears the tstate on exit. Idempotent: returns the cached set once resolved. Heavy (iterates
      // sys.modules), so it is called ONCE at install and thereafter only when iris-correlated + unresolved.
      ST.resolveLocalToonMethods = function(md){
        try {
          if (ST.localToonMethods) return ST.localToonMethods;       // cached (resolve at most once)
          // RATE-LIMIT: the scan iterates all of sys.modules, so while LocalToon is unresolved (e.g. attach
          // preceded login) never scan more than once per second -- otherwise a burst of iris-correlated
          // unmatched intervals could each trigger a full scan. Resolves for good on the first success.
          var now = Date.now();
          if (ST.lastLtScanMs && (now - ST.lastLtScanMs) < 1000) return null;
          ST.lastLtScanMs = now;
          if (!(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.DictGetStr && ST.DictGetItem && ST.GetAttrStr)){ ST.clearExc(); return null; }
          md = md || ST.sysmodules(); if (md.isNull()){ ST.clearExc(); return null; }
          var found = ST.scanBySignature(md, ST.ltSig);              // classes defining ALL of ltSig
          if (!found || !found.length){ ST.clearExc(); return null; }
          // prefer the class that defines the signature DIRECTLY (the real LocalToon, not a subclass that
          // merely inherits it); else take the first full match.
          var direct = found.filter(function(r){ return r.all_direct; });
          var rec = direct.length ? direct[0] : found[0];
          var cls = rec.clsPtr; ST.keep.push(cls);
          var owndict = ptr(0); try { owndict = cls.add(0x108).readPointer(); } catch(e){ owndict = ptr(0); }
          if (owndict.isNull()){ ST.clearExc(); return null; }
          var set = {}, cnt = 0;
          var it = ST.GetIter(owndict);
          if (!it.isNull()){
            var k;
            while (!(k = ST.IterNext(it)).isNull()){
              var nm = null; try { nm = ST.AsUTF8(k).readCString(); } catch(e){ nm = null; }
              if (nm && nm[0] !== '_'){ set[nm] = true; cnt++; }     // co_name == attr key for a method
            }
          }
          ST.clearExc();
          if (cnt === 0) return null;                                // no methods -> treat as unresolved (retry)
          ST.localToonMethods = set; ST.localToonName = rec.class_name;
          try { send({t:'ltmethods', cls:rec.class_name, sig:ST.ltSig, count:cnt}); } catch(e){}
          return set;
        } catch(e){ ST.clearExc(); return null; }
      };
      // scale `inst` as the tunnel walk via the LocalToon-method+iris signal; [SCALED] via=localtoon-method.
      ST.scaleTunnelLtIris = function(inst, nm, co){
        var ok = ST.setPlayRate(inst, ST.ltIrisFactor);
        if (ok){ try {
          ST.scaledNames = ST.scaledNames || {}; var first = (ST.scaledNames[nm] === undefined);
          ST.scaledNames[nm] = (ST.scaledNames[nm]||0) + 1;
          ST.scaledGroups = ST.scaledGroups || {}; ST.scaledGroups['tunnel'] = (ST.scaledGroups['tunnel']||0) + 1;
          if (first) send({t:'scaled', name:nm, factor:ST.ltIrisFactor, group:'tunnel', via:'localtoon-method', co:co});
        } catch(e){} }
        ST.clearExc();
        return ok;
      };
      // The DETERMINISTIC ARRIVAL check. DOUBLE-GATED so it can NEVER scale non-tunnel intervals:
      //   (1) iris-correlated: an iris-named interval started within ltIrisWindowMs (handleTunnelIn's
      //       synchronous base.transitions.irisIn, stamped as lastIrisMs), AND
      //   (2) LocalToon-owned: the spawning frame's co_name is in LocalToon's OWN method set.
      // Only handleTunnelIn/handleTunnelOut satisfy BOTH (other LocalToon methods -- emotes etc. -- have no
      // iris; other players'/cogs'/NPCs' walks are spawned by OTHER classes' methods, not in the set).
      // Reached only for intervals the name table + context + spawn_context did NOT already scale (teleport
      // is name-matched and returns first; the ctx-scaled departure returns first -> no double-scale). The
      // co_name is passed in (already read once per start). Returns true iff it scaled. tstate-clean.
      ST.tryTunnelLtIris = function(inst, nm, coName, md){
        try {
          if (!ST.ltIrisEnabled) return false;
          if ((Date.now() - (ST.lastIrisMs||0)) > ST.ltIrisWindowMs) return false;   // gate (1): iris-correlated
          if (coName === null || coName === undefined) return false;
          if (!ST.localToonMethods){ ST.resolveLocalToonMethods(md); }               // lazy (iris-gated) resolve
          if (!ST.localToonMethods) return false;
          if (ST.localToonMethods[coName] !== true) return false;                    // gate (2): LocalToon method
          return ST.scaleTunnelLtIris(inst, nm, coName);
        } catch(e){ ST.clearExc(); return false; }
      };

      // GENERIC discovery == payload.py's _apply_after: attr / iname_attr / iname_sub. Every getattr
      // that can miss is followed by clearExc so a failed lookup never leaks onto the tstate.
      ST.applyAfter = function(inst, spec, factorVal){
        try {
          if (spec.mode === 'attr'){
            var iv = ST.GetAttrStr(inst, Memory.allocUtf8String(spec.attr));
            if (iv.isNull()){ ST.clearExc(); return 0; }
            return ST.setPlayRate(iv, factorVal) ? 1 : 0;
          } else if (spec.mode === 'iname_attr'){
            var nm = ST.GetAttrStr(inst, Memory.allocUtf8String(spec.iname_attr));
            if (nm.isNull()){ ST.clearExc(); return 0; }
            var ivals = ST.GetAttrStr(inst, Memory.allocUtf8String('activeIntervals'));
            if (ivals.isNull()){ ST.clearExc(); return 0; }
            var iv2 = ST.GetItem ? ST.GetItem(ivals, nm) : ptr(0);
            if (iv2.isNull()){ ST.clearExc(); return 0; }
            return ST.setPlayRate(iv2, factorVal) ? 1 : 0;
          } else if (spec.mode === 'iname_sub'){
            var ivals2 = ST.GetAttrStr(inst, Memory.allocUtf8String('activeIntervals'));
            if (ivals2.isNull()){ ST.clearExc(); return 0; }
            if (!(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.GetItem)){ ST.clearExc(); return 0; }
            var it = ST.GetIter(ivals2); if (it.isNull()){ ST.clearExc(); return 0; }
            var k, n = 0;
            while (!(k = ST.IterNext(it)).isNull()){
              var ks = null; try { ks = ST.AsUTF8(k).readCString(); } catch(e){ ks = null; }
              if (ks && ks.indexOf(spec.iname_sub) >= 0){
                var iv3 = ST.GetItem(ivals2, k);
                if (!iv3.isNull()){ if (ST.setPlayRate(iv3, factorVal)) n++; } else { ST.clearExc(); }
              }
            }
            ST.clearExc(); return n;
          } else if (spec.mode === 'byname'){
            // GENERAL INTERVAL HOOK: `inst` IS the interval (we wrapped its start()). Read its
            // getName(); optionally LOG it (deduped, capped) so we can discover the real names live;
            // and scale (setPlayRate on-the-fly, AFTER start() already ran) ONLY when the name
            // contains one of spec.subs -- so we never globally rescale every interval.
            var gm = ST.GetAttrStr(inst, Memory.allocUtf8String('getName'));
            if (gm.isNull()){ ST.clearExc(); return 0; }
            var nm3 = ST.TupleNew ? ST.Call(gm, ST.TupleNew(0), ptr(0)) : ptr(0);
            if (nm3.isNull()){ ST.clearExc(); return 0; }
            var nms = null; try { nms = ST.AsUTF8(nm3).readCString(); } catch(e){ nms = null; }
            if (nms === null){ ST.clearExc(); return 0; }
            if (spec.log){
              ST.seenNames = ST.seenNames || {}; ST.nameCount = ST.nameCount || 0;
              if (ST.seenNames[nms] === undefined && ST.nameCount < 250){ ST.seenNames[nms] = 1; ST.nameCount++; try { send({t:'ivalname', name:nms}); } catch(e){} }
            }
            var subs = spec.subs || [], hit = false;
            for (var si=0; si<subs.length; si++){ if (subs[si] && nms.indexOf(subs[si]) >= 0){ hit = true; break; } }
            if (hit){
              var ok = ST.setPlayRate(inst, factorVal);
              if (ok){ try { ST.scaledNames = ST.scaledNames || {}; ST.scaledNames[nms] = (ST.scaledNames[nms]||0)+1; send({t:'scaled', name:nms, factor:factorVal}); } catch(e){} }
              ST.clearExc(); return ok ? 1 : 0;
            }
            ST.clearExc(); return 0;
          } else if (spec.mode === 'modset'){
            // MODSET (the production mode): the GENERAL INTERVAL HOOK driven by a curated
            // name->factor TABLE instead of one substring+factor. `inst` IS the interval (we
            // wrapped its start()). Read getName(); find the FIRST table entry whose `match` is a
            // substring (or, with entry.prefix, a prefix) of the name; setPlayRate with THAT
            // entry's own factor. A name matching NO entry is LOGGED (spec.log) but NEVER scaled --
            // so gameplay-timing intervals are always left untouched. Every miss clears the tstate.
            var gm2 = ST.GetAttrStr(inst, Memory.allocUtf8String('getName'));
            if (gm2.isNull()){ ST.clearExc(); return 0; }
            var nm4 = ST.TupleNew ? ST.Call(gm2, ST.TupleNew(0), ptr(0)) : ptr(0);
            if (nm4.isNull()){ ST.clearExc(); return 0; }
            var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
            if (nms4 === null){ ST.clearExc(); return 0; }
            // BATTLETRACE (READ-ONLY, runs BEFORE any scaling; changes nothing). When a battle interval
            // starts: (a) lazily arm the method wraps if the FSM class only loaded now (idempotent), and
            // (b) emit a timestamped [BT] line with its base duration + current playRate. This does not
            // return -- the interval then flows through the normal scaling path below, unchanged.
            if (ST.btEnabled && ST.btHit(nms4)){
              if (!ST.btInstalled){ try { ST.installBattleTrace(null); } catch(e){ ST.clearExc(); } }
              ST.btEmitIval(inst, nms4);
            }
            // (0) IRIS STAMP + (1) TUNNEL WALK BY OBJECT IDENTITY (fast path, pinned attr). The iris stamp
            // records when the screen iris (irisTask) fires so BOTH tunnel-arrival paths -- the LocalToon-
            // method+iris check (4.5) and the object-identity discovery (5) -- can correlate handleTunnelIn's
            // synchronous irisIn with the walk's start; it is needed whenever EITHER path is enabled. The
            // object-identity fast path (attr-specific -> can only match the tunnel track, never teleport)
            // is gated on ST.tunnelEnabled alone. The street-tunnel walk interval is unnamed, so it matches
            // no name entry and is identified by co_name-membership (4.5) or object identity (5), not name.
            if (ST.tunnelEnabled || ST.ltIrisEnabled){
              if (ST.isIrisName(nms4)) ST.lastIrisMs = Date.now();
            }
            if (ST.tunnelEnabled){
              if (ST.tunnelFastPath(inst, nms4)){ ST.clearExc(); return 1; }
            }
            // CONTEXT SCALING (takes priority over the name table): if a wrap-around context method
            // is on the stack (ST.ctx set), this interval was CREATED inside it -> scale it by the
            // context's factor regardless of its (possibly auto-named/hashed) getName(). ALWAYS log
            // the name via the [IVALNAME] path with a ctx= tag so we finally learn the real hashed
            // name of the tunnel walk. This reaches fire-and-forget intervals that no substring could
            // safely target. Every miss clears the tstate (same crash-guard discipline as below).
            if (ST.ctx){
              ST.ctxSeen = ST.ctxSeen || {}; ST.ctxCount = ST.ctxCount || 0;
              if (ST.ctxSeen[nms4] === undefined && ST.ctxCount < 400){
                ST.ctxSeen[nms4] = 1; ST.ctxCount++; try { send({t:'ivalname', name:nms4, ctx:ST.ctx.group}); } catch(e){}
              }
              var okc = ST.setPlayRate(inst, ST.ctx.factor);
              if (okc){ try {
                ST.scaledNames = ST.scaledNames || {}; var firstSeenC = (ST.scaledNames[nms4] === undefined);
                ST.scaledNames[nms4] = (ST.scaledNames[nms4]||0) + 1;
                ST.scaledGroups = ST.scaledGroups || {}; ST.scaledGroups[ST.ctx.group] = (ST.scaledGroups[ST.ctx.group]||0) + 1;
                if (firstSeenC) send({t:'scaled', name:nms4, factor:ST.ctx.factor, group:ST.ctx.group, ctx:ST.ctx.group});
              } catch(e){} }
              ST.clearExc(); return okc ? 1 : 0;
            }
            // SPAWN-CONTEXT SCALING (approach 2; takes priority over the name table, after ctx):
            // read the co_name of the frame that CALLED start() -- for a fire-and-forget/auto-named
            // interval (the tunnel walk) this is the hashed name of the spawning method
            // (handleTunnelOut/handleTunnelIn). If it EXACTLY matches a configured spawn_context
            // entry, scale by that entry's factor regardless of the interval's own (unmatchable)
            // name. Exact match => ONLY intervals spawned by a named function are touched (a hashed
            // co_name is unique to its source, so nothing unrelated collides). Read once per start
            // when spawn entries exist OR logging is on; the read is pure pointer derefs (no getattr,
            // no exception risk). Every miss clears the tstate (same crash-guard discipline).
            var spawnList = spec.spawn || [];
            var coName = (spawnList.length || spec.log || ST.ltIrisEnabled) ? ST.spawnCoName() : null;
            if (spawnList.length && coName !== null){
              var smatch = null;
              for (var sp=0; sp<spawnList.length; sp++){ if (spawnList[sp] && spawnList[sp].co_name === coName){ smatch = spawnList[sp]; break; } }
              if (smatch){
                var oks = ST.setPlayRate(inst, smatch.factor);
                if (oks){ try {
                  ST.scaledNames = ST.scaledNames || {}; var firstSeenS = (ST.scaledNames[nms4] === undefined);
                  ST.scaledNames[nms4] = (ST.scaledNames[nms4]||0) + 1;
                  ST.scaledGroups = ST.scaledGroups || {}; ST.scaledGroups[smatch.group] = (ST.scaledGroups[smatch.group]||0) + 1;
                  if (firstSeenS) send({t:'scaled', name:nms4, factor:smatch.factor, group:smatch.group, co:coName});
                } catch(e){} }
                ST.clearExc(); return oks ? 1 : 0;
              }
            }
            var entries = spec.entries || [], matched = null;
            for (var mi=0; mi<entries.length; mi++){
              var en = entries[mi]; if (!en || !en.match) continue;
              var isHit = en.prefix ? (nms4.lastIndexOf(en.match, 0) === 0) : (nms4.indexOf(en.match) >= 0);
              if (isHit){ matched = en; break; }              // FIRST match wins -> order specific->broad
            }
            if (matched){
              var okm = ST.setPlayRate(inst, matched.factor);
              if (okm){ try {
                ST.scaledNames = ST.scaledNames || {}; var firstSeen = (ST.scaledNames[nms4] === undefined);
                ST.scaledNames[nms4] = (ST.scaledNames[nms4]||0) + 1;
                ST.scaledGroups = ST.scaledGroups || {}; ST.scaledGroups[matched.group] = (ST.scaledGroups[matched.group]||0) + 1;
                if (firstSeen) send({t:'scaled', name:nms4, factor:matched.factor, group:matched.group});
              } catch(e){} }
              ST.clearExc(); return okm ? 1 : 0;
            }
            // (4.5) TUNNEL ARRIVAL by LOCALTOON-METHOD + IRIS (the DETERMINISTIC primary tunnel path).
            // Only NAME-UNMATCHED intervals reach here (teleport/book/door/iris returned above via the name
            // table, and the ctx-scaled DEPARTURE returned at the ctx block -> no double-scale). If this
            // interval was spawned by a method of the LocalToon CLASS (co_name in the live-resolved method
            // set) AND it started inside the iris window, it is the local toon's tunnel walk (handleTunnelIn
            // on ARRIVAL) -> scale it x tunnel factor, regardless of the per-session hash. Doubly-gated
            // (LocalToon-method membership AND iris correlation) so it can never touch MMO-noise walks
            // (spawned by OTHER classes) or non-tunnel LocalToon animations (no iris). See ST.tryTunnelLtIris.
            if (ST.ltIrisEnabled){
              if (ST.tryTunnelLtIris(inst, nms4, coName, null)){ ST.clearExc(); return 1; }
            }
            // (5) TUNNEL WALK BY OBJECT IDENTITY (discovery). Only NAME-UNMATCHED intervals reach here
            // (teleport & every named group returned above via the name table), so discovery can NEVER
            // touch the teleport self.track. When an unmatched interval starts within the iris window AND
            // it IS a value in localAvatar's instance dict, that attr is the (hashed) tunnel-track attr:
            // pin it, log [TUNNELATTR], and scale as tunnel. Once pinned, the fast path (above) scales
            // every later walk in BOTH directions with no iris needed.
            if (ST.tunnelEnabled && !ST.tunnelAttr){
              if (ST.tunnelDiscover(inst, nms4)){ ST.clearExc(); return 1; }
            }
            // unmatched: log its NAME once (deduped, capped) so the operator sees what's available,
            // AND log its spawning co_name once per DISTINCT co_name -- so a single street-tunnel
            // walk reveals the hashed handleTunnelOut/handleTunnelIn co_names to paste into
            // spawn_context. (Deduping by co_name, not by interval name, is what makes the tunnel
            // handler stand out: the ~1240 ambient sequences share a handful of spawner co_names, and
            // the walk's auto-named interval name changes every counter so name-dedup would never
            // surface it.)
            if (spec.log){
              ST.seenNames = ST.seenNames || {}; ST.nameCount = ST.nameCount || 0;
              if (ST.seenNames[nms4] === undefined && ST.nameCount < 400){ ST.seenNames[nms4] = 1; ST.nameCount++; try { send({t:'ivalname', name:nms4}); } catch(e){} }
              if (coName !== null){
                ST.spawnSeen = ST.spawnSeen || {}; ST.spawnCount = ST.spawnCount || 0;
                if (ST.spawnSeen[coName] === undefined && ST.spawnCount < 200){ ST.spawnSeen[coName] = 1; ST.spawnCount++; try { send({t:'spawnco', co:coName, sample:nms4}); } catch(e){} }
              }
            }
            ST.clearExc(); return 0;
          }
        } catch(e){ ST.clearExc(); }
        return 0;
      };
      // wrap-after NativeCallback (METH_VARARGS|KEYWORDS=0x3): call the ORIGINAL once, then (only if
      // it did not raise) discover the just-started interval and setPlayRate it; return the original
      // result. args = (inst, *call_args); inst = ob_item[0] @ tuple+0x18 (ob_size @ +0x10).
      ST.makeWrapAfter = function(orig, spec, factorVal, label){
        var cb = new NativeCallback(function (self, args, kwargs) {
          try { ST.fires = (ST.fires||0) + 1; if (ST.fires<=8) send({t:'fired', n:ST.fires, method:label}); } catch(e){}
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // original, exactly once
          if (result.isNull()){ return result; }              // original raised -> propagate untouched
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            var _applied = 0;
            if (!inst.isNull()) _applied = ST.applyAfter(inst, spec, factorVal);   // # intervals setPlayRate'd
            // count landed applications per wrapped method -> identifies WHICH (hashed) method scaled a
            // real interval (i.e. is a transition-starter), and confirms the attr resolved.
            try { if (_applied > 0){ ST.appliedBy = ST.appliedBy || {}; ST.appliedBy[label] = (ST.appliedBy[label]||0) + _applied; } } catch(e){}
            try { if ((ST.fires||0) <= 8 || _applied > 0) send({t:'applied', fire:(ST.fires||0), method:label, n:_applied, attr:spec.attr, factor:factorVal}); } catch(e){}
            // DIAGNOSTIC: dump the instance's __dict__ (VALUE types) to reveal the REAL interval attr
            // even when spec.attr was hashed/renamed. Widened to the first several fires (nested
            // transition calls burn through the count fast) and only SENT when it actually finds an
            // Interval-typed attr (or on the very first fire), so it isn't noisy. Read-only + cleared.
            if (ST.probeAttrs && !inst.isNull() && (ST.fires||0) <= 15){
              try {
                var pinfo = { fire:(ST.fires||0), method:label };
                // (a) instance __dict__ keys that look interval/animation-ish
                var idict = ST.GetAttrStr(inst, Memory.allocUtf8String('__dict__'));
                if (!idict.isNull() && ST.GetIter && ST.IterNext && ST.AsUTF8){
                  var iit = ST.GetIter(idict), ik, hits = [], tot = 0;
                  while (!(ik = ST.IterNext(iit)).isNull()){ tot++;
                    var kn = null; try { kn = ST.AsUTF8(ik).readCString(); } catch(e){ kn = null; }
                    if (kn && /track|tunnel|ival|interval|seq|walk|anim|move|lerp/i.test(kn) && hits.length < 40) hits.push(kn);
                  }
                  pinfo.dict_size = tot; pinfo.dict_ival_like = hits;
                }
                ST.clearExc();
                // (b) the TYPE of self.track (None? an Interval/Sequence?)
                var tk = ST.GetAttrStr(inst, Memory.allocUtf8String('track'));
                pinfo.track_type = tk.isNull() ? 'ABSENT' : ST.tpname(tk);
                ST.clearExc();
                // (b2) scan ALL __dict__ VALUES by TYPE for an Interval/Sequence (finds the walk interval
                // even under a hashed attr name). Uses getattr per key then tp_name of the value.
                if (!idict.isNull() && ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.tpname){
                  var jit = ST.GetIter(idict), jk, ivalAttrs = [];
                  while (!(jk = ST.IterNext(jit)).isNull()){
                    var jn = null; try { jn = ST.AsUTF8(jk).readCString(); } catch(e){ jn = null; }
                    if (!jn) continue;
                    var jv = ST.GetAttrStr(inst, Memory.allocUtf8String(jn));
                    if (!jv.isNull()){
                      var tn = ST.tpname(jv);
                      if (tn && /Interval|Sequence|Parallel|Ival|Lerp|MopathInterval|CInterval|Track|Func/i.test(tn) && ivalAttrs.length < 30)
                        ivalAttrs.push({attr:jn, type:tn});
                    } else { ST.clearExc(); }
                  }
                  pinfo.interval_typed_attrs = ivalAttrs;
                }
                ST.clearExc();
                // (c) self.activeIntervals registry -> the live interval NAMES right after the walk starts
                var ai = ST.GetAttrStr(inst, Memory.allocUtf8String('activeIntervals'));
                if (!ai.isNull() && ST.GetIter && ST.IterNext && ST.AsUTF8){
                  var ait = ST.GetIter(ai), ak2, ivn = [], c = 0;
                  if (!ait.isNull()){
                    while (!(ak2 = ST.IterNext(ait)).isNull()){ c++;
                      var an = null; try { an = ST.AsUTF8(ak2).readCString(); } catch(e){ an = null; }
                      if (an && ivn.length < 40) ivn.push(an);
                    }
                  }
                  pinfo.activeIntervals_count = c; pinfo.activeIntervals = ivn;
                } else { pinfo.activeIntervals = 'ABSENT'; }
                ST.clearExc();
                // send only when it found an interval-typed attr (the payload we're after) or on the
                // first fire (baseline), to avoid spamming for the nested no-op transition calls.
                if ((pinfo.interval_typed_attrs && pinfo.interval_typed_attrs.length) || (ST.fires||0) <= 1)
                  send({t:'probe', p:pinfo});
              } catch(e){}
              ST.clearExc();
            }
          } catch(e){ ST.clearExc(); }
          ST.clearExc();                                       // nothing of OURS pending on return
          return result;                                       // pass the original result through
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = Memory.allocUtf8String('ttrmod_wrapafter'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };
      // WRAP-AROUND context wrapper (METH_VARARGS|KEYWORDS=0x3): for a configured context method
      // (e.g. LocalToon.tunnelOut) SET the global ST.ctx BEFORE calling the original and RESTORE the
      // previous value AFTER, in a finally -- so ctx clears even if the original raises (same
      // exception-clear discipline as wrap-after) and nested/reentrant context methods save+restore
      // correctly. While ctx is set, the MetaInterval.start hook scales every interval that starts
      // (by ctx.factor) -- that is how the fire-and-forget tunnel-walk interval is caught. The
      // original result is passed straight through (NULL => it raised => propagate untouched, exc
      // left intact -- we NEVER clear a genuine exception from the original).
      ST.makeCtxWrap = function(orig, group, factorVal, label){
        var cb = new NativeCallback(function (self, args, kwargs) {
          try { ST.ctxFires = (ST.ctxFires||0) + 1; if (ST.ctxFires<=8) send({t:'fired', n:ST.ctxFires, method:label, ctx:group}); } catch(e){}
          var prev = ST.ctx;                                   // save (nesting/reentrancy safe)
          ST.ctx = { group: group, factor: factorVal, label: label };
          var result;
          try {
            result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // original, exactly once
          } finally {
            ST.ctx = prev;                                     // restore ALWAYS (finally == cleared-on-raise)
          }
          return result;                                       // pass the original result through
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = Memory.allocUtf8String('ttrmod_ctxwrap'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };

      // ---- BATTLETRACE helpers (READ-ONLY) ----
      // Read a Python float's C double WITHOUT a C-API call: PyFloat_AsDouble is inlined away in the
      // engine, but the layout is fixed -- if ob_type == &PyFloat_Type, the double lives at +0x10
      // (STATUS.md recipe). Returns null for a non-float / null obj. Never raises, never leaks an exc.
      ST.floatDouble = function(obj){
        try {
          if (!obj || obj.isNull()) return null;
          if (ST.FloatType && obj.add(8).readPointer().equals(ST.FloatType)) return obj.add(0x10).readDouble();
          return null;
        } catch(e){ return null; }
      };
      // Call a no-arg method that returns a float (getDuration / getPlayRate) and read it as a JS number.
      // Pure read (these are const accessors on a Panda interval); any miss clears the tstate (crash-guard).
      ST.callFloat0 = function(inst, name){
        try {
          if (!ST.TupleNew) return null;
          var m = ST.GetAttrStr(inst, Memory.allocUtf8String(name));
          if (m.isNull()){ ST.clearExc(); return null; }
          var r = ST.Call(m, ST.TupleNew(0), ptr(0));
          if (r.isNull()){ ST.clearExc(); return null; }
          var d = ST.floatDouble(r);
          ST.clearExc();
          return d;
        } catch(e){ ST.clearExc(); return null; }
      };
      // Is this interval name one of the battle intervals we trace?
      ST.btHit = function(nm){
        if (!nm || !ST.btNames.length) return false;
        for (var i=0;i<ST.btNames.length;i++){ if (ST.btNames[i] && nm.indexOf(ST.btNames[i]) >= 0) return true; }
        return false;
      };
      // Emit a timestamped [BT] interval line: when a battle interval STARTED, its base duration, and its
      // CURRENT playRate (as read right after the game's own start(); the modset's setPlayRate has not run
      // yet at this point, so rate here is the CLIENT's own rate -- proving the client does not natively
      // speed the movie and OUR mod is what scales it). Real playback == dur / (playRate * modFactor).
      ST.btEmitIval = function(inst, nm){
        try {
          var dur = ST.callFloat0(inst, 'getDuration');
          var rate = ST.callFloat0(inst, 'getPlayRate');
          send({t:'bt', ms:Date.now(), ev:'ival', name:nm, dur:dur, rate:rate});
        } catch(e){ ST.clearExc(); }
      };
      // Build a LOGGING-ONLY wrap-after (METH_VARARGS|KEYWORDS=0x3): timestamp the call, read the DC
      // field/state NAME (ob_item[1], a str -- self is ob_item[0]), then call the ORIGINAL exactly once
      // and pass its result straight through (NULL-on-raise included -- we NEVER clear the ORIGINAL's
      // exception, only our own arg-read miss, and only BEFORE running the original so it starts clean).
      // Changes nothing. `kind` selects the HASHING-PROOF signal:
      //   'setState' -- INBOUND: the server-sent DC field setState(stateName, ts). ob_item[1] is the state
      //                 name (a str). The battle class is hashed but the DC field NAME setState is fixed by
      //                 the wire contract (C++ receiveUpdate calls it by that name), so this fires + names
      //                 the state regardless of the per-build hash.
      //   'send'     -- OUTBOUND: DistributedObject.sendUpdate(fieldName, args). ob_item[1] is the DC field
      //                 name (a str). We log ONLY when it ends in 'Done' (movieDone/faceOffDone/rewardDone/
      //                 joinDone -- the client's "step finished" reports); every other sendUpdate passes
      //                 through silently. `d_movieDone` etc. are hashed, but the STRING they pass to
      //                 sendUpdate is the fixed DC field name, so the name is visible here regardless.
      //   null       -- plain timestamp under `label` (legacy: a readable d_*Done, if ever un-hashed).
      ST.makeTraceWrap = function(orig, label, kind){
        var cb = new NativeCallback(function (self, args, kwargs) {
          try {
            var arg1 = null;
            if (kind && ST.AsUTF8){
              try {
                var n = args.add(0x10).readS64().toNumber();          // tuple ob_size (self is ob_item[0])
                if (n >= 2){
                  var sObj = args.add(0x18 + 8).readPointer();        // ob_item[1] = state / DC field name (a str)
                  if (!sObj.isNull()){ try { arg1 = ST.AsUTF8(sObj).readCString(); } catch(e){ arg1 = null; } }
                }
              } catch(e){ arg1 = null; }
              ST.clearExc();   // clear any exc from OUR arg read BEFORE the original runs (never leak into it)
            }
            if (kind === 'send'){
              // OUTBOUND: only the DC done-reports (field name ends in 'Done'); other sendUpdates are ignored.
              if (arg1 && arg1.length >= 4 && arg1.slice(-4) === 'Done'){
                try { ST.btFires = (ST.btFires||0) + 1; } catch(e){}
                send({t:'bt', ms:Date.now(), ev:'m', dir:'out', label:arg1, field:arg1, state:null});
              }
            } else if (kind === 'setState'){
              try { ST.btFires = (ST.btFires||0) + 1; } catch(e){}
              send({t:'bt', ms:Date.now(), ev:'m', dir:'in', label:'setState', state:arg1});
            } else {
              try { ST.btFires = (ST.btFires||0) + 1; } catch(e){}
              send({t:'bt', ms:Date.now(), ev:'m', dir:'out', label:label, state:null});
            }
          } catch(e){ ST.clearExc(); }
          return ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // original once; result passed through UNTOUCHED
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = Memory.allocUtf8String('ttrmod_bt'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };

      // ===================== SHARED with localtest/findcls_test.py (verbatim) =====================
      // Find a target class by the METHODS it defines (the robust replacement for resolving a
      // vault-HASHED class by module/name -- LocalToon loads under vlt24ab6c6d.<hash>.<hash>).
      // classSignature(cls, methods, methCStrs): walk cls's MRO (tp_mro @ +0x158; a tuple, ob_size @
      // +0x10, items @ +0x18) and record, per requested method, whether it is defined DIRECTLY on cls
      // (MRO[0]) or INHERITED (and from which base). Membership tested against each base's tp_dict
      // (@ +0x108) via PyDict_GetItemString (borrowed, clears-on-miss). class __name__ = tp_name @
      // +0x18. Returns a record, or null on a hard read error.
      ST.classSignature = function(cls, methods, methCStrs){
        try {
          var className = '?'; try { className = cls.add(0x18).readPointer().readCString(); } catch(e){ className = '?'; }
          var mro = [];
          try {
            var mroTup = cls.add(0x158).readPointer();
            if (!mroTup.isNull()){
              var n = mroTup.add(0x10).readS64().toNumber();
              if (n > 0 && n < 512){ for (var i=0;i<n;i++){ mro.push(mroTup.add(0x18 + 8*i).readPointer()); } }
            }
          } catch(e){ mro = []; }
          if (mro.length === 0) mro = [cls];
          var rec = { class_name: className, clsPtr: cls, methods: {}, match_count: 0,
                      full: false, all_direct: true, bindings: [] };
          for (var mi=0; mi<methods.length; mi++){
            var where = 'absent', baseName = null;
            for (var bi=0; bi<mro.length; bi++){
              var B = mro[bi]; if (B.isNull()) continue;
              var bdict = ptr(0); try { bdict = B.add(0x108).readPointer(); } catch(e){ bdict = ptr(0); }
              if (bdict.isNull()) continue;
              var hit = ST.DictGetStr(bdict, methCStrs[mi]);   // borrowed; clears lookup error on miss
              if (!hit.isNull()){
                if (bi === 0){ where = 'direct'; }
                else { where = 'inherited'; try { baseName = B.add(0x18).readPointer().readCString(); } catch(e){ baseName = '?'; } }
                break;
              }
            }
            rec.methods[methods[mi]] = { where: where, base: baseName };
            if (where === 'direct'){ rec.match_count++; }
            else if (where === 'inherited'){ rec.match_count++; rec.all_direct = false; }
            else { rec.all_direct = false; }
          }
          rec.full = (rec.match_count === methods.length);
          return rec;
        } catch(e){ return null; }
      };
      // scanBySignature(md, methods): iterate sys.modules (md); for each module iterate its __dict__;
      // for each value that IS a type (PyType_Check: Py_TYPE(v).tp_flags TYPE_SUBCLASS bit == byte @
      // tp+0xab bit7), compute its signature ONCE (cached by class pointer) and, if ALL methods are
      // present, record this (module,attr) binding. Returns the list of full-match classes (deduped
      // by class pointer). Pure reads + borrowed lookups; clears the tstate exception on exit.
      ST.scanBySignature = function(md, methods){
        var byCls = {}, order = [];
        try {
          if (md.isNull() || !(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.DictGetStr && ST.DictGetItem && ST.GetAttrStr)){ ST.clearExc(); return []; }
          var methCStrs = []; for (var mi=0; mi<methods.length; mi++){ methCStrs.push(Memory.allocUtf8String(methods[mi])); }
          var dictStr = Memory.allocUtf8String('__dict__');
          var mit = ST.GetIter(md); if (mit.isNull()){ ST.clearExc(); return []; }
          var mk;
          while (!(mk = ST.IterNext(mit)).isNull()){
            var modObj = ST.DictGetItem(md, mk);              // borrowed module object (no re-encode)
            if (modObj.isNull()){ ST.clearExc(); continue; }
            var mdict = ST.GetAttrStr(modObj, dictStr);       // module namespace (real dict); getset, no bytecode
            if (mdict.isNull()){ ST.clearExc(); continue; }
            var dit = ST.GetIter(mdict); if (dit.isNull()){ ST.clearExc(); continue; }
            var modName = null, ak;
            while (!(ak = ST.IterNext(dit)).isNull()){
              var val = ST.DictGetItem(mdict, ak);            // borrowed value (no re-encode)
              if (val.isNull()){ ST.clearExc(); continue; }
              var isType = false;
              try { isType = (val.add(8).readPointer().add(0xab).readU8() & 0x80) !== 0; } catch(e){ isType = false; }
              if (!isType) continue;                          // skip ints/functions/modules/C objects/etc.
              var clsKey = val.toString();
              var rec = byCls[clsKey];
              if (rec === undefined){ rec = ST.classSignature(val, methods, methCStrs); byCls[clsKey] = rec; if (rec) order.push(clsKey); }
              if (rec && rec.full){
                if (modName === null){ try { modName = ST.AsUTF8(mk).readCString(); } catch(e){ modName = '?'; } }
                var attr = '?'; try { attr = ST.AsUTF8(ak).readCString(); } catch(e){ attr = '?'; }
                rec.bindings.push({ module: modName, attr: attr });
              }
            }
          }
        } catch(e){ /* fall through to clear */ }
        ST.clearExc();
        var outl = [];
        for (var i=0;i<order.length;i++){ var r = byCls[order[i]]; if (r && r.full) outl.push(r); }
        return outl;
      };
      // scanBySubstr(md, substrs): DISCOVERY tool for when the exact method names are hashed away.
      // Iterate sys.modules -> modules -> __dict__; for each type value (dedup by class ptr), iterate
      // its OWN tp_dict (MRO[0] @ +0x108) method-name KEYS and record any name containing ANY of the
      // substrs. Returns classes with >=1 hit: {class_name, clsPtr, hits:[names], own_method_count,
      // bindings:[{module,attr}]}. Own-dict only (the DEFINING class), so a subclass that merely
      // inherits the method is not re-reported. Read-only; clears the tstate exc on exit.
      ST.scanBySubstr = function(md, substrs){
        var byCls = {}, order = [];
        try {
          if (md.isNull() || !(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.DictGetItem && ST.GetAttrStr)){ ST.clearExc(); return []; }
          var dictStr = Memory.allocUtf8String('__dict__');
          var mit = ST.GetIter(md); if (mit.isNull()){ ST.clearExc(); return []; }
          var mk;
          while (!(mk = ST.IterNext(mit)).isNull()){
            var modObj = ST.DictGetItem(md, mk); if (modObj.isNull()){ ST.clearExc(); continue; }
            var mdict = ST.GetAttrStr(modObj, dictStr); if (mdict.isNull()){ ST.clearExc(); continue; }
            var dit = ST.GetIter(mdict); if (dit.isNull()){ ST.clearExc(); continue; }
            var modName = null, ak;
            while (!(ak = ST.IterNext(dit)).isNull()){
              var val = ST.DictGetItem(mdict, ak); if (val.isNull()){ ST.clearExc(); continue; }
              var isType = false;
              try { isType = (val.add(8).readPointer().add(0xab).readU8() & 0x80) !== 0; } catch(e){ isType = false; }
              if (!isType) continue;
              var clsKey = val.toString();
              var rec = byCls[clsKey];
              if (rec === undefined){
                rec = null;
                try {
                  var className = '?'; try { className = val.add(0x18).readPointer().readCString(); } catch(e){ className = '?'; }
                  var owndict = ptr(0); try { owndict = val.add(0x108).readPointer(); } catch(e){ owndict = ptr(0); }
                  var hits = [], cnt = 0;
                  if (!owndict.isNull()){
                    var kit = ST.GetIter(owndict);
                    if (!kit.isNull()){
                      var kk;
                      while (!(kk = ST.IterNext(kit)).isNull()){
                        cnt++;
                        var nm = null; try { nm = ST.AsUTF8(kk).readCString(); } catch(e){ nm = null; }
                        if (nm){ for (var si=0; si<substrs.length; si++){ if (nm.indexOf(substrs[si]) >= 0){ if (hits.indexOf(nm) < 0 && hits.length < 40) hits.push(nm); break; } } }
                      }
                    }
                  }
                  rec = { class_name: className, clsPtr: val, hits: hits, own_method_count: cnt, bindings: [] };
                } catch(e){ rec = null; }
                byCls[clsKey] = rec; if (rec) order.push(clsKey);
              }
              if (rec && rec.hits.length){
                if (modName === null){ try { modName = ST.AsUTF8(mk).readCString(); } catch(e){ modName = '?'; } }
                var attr = '?'; try { attr = ST.AsUTF8(ak).readCString(); } catch(e){ attr = '?'; }
                rec.bindings.push({ module: modName, attr: attr });
              }
            }
          }
        } catch(e){}
        ST.clearExc();
        var outl = [];
        for (var i=0;i<order.length;i++){ var r = byCls[order[i]]; if (r && r.hits.length) outl.push(r); }
        return outl;
      };
      // ================================ end shared block ================================

      // Install the BATTLETRACE method wraps (READ-ONLY), HASHING-PROOF. The battle FSM class + its
      // d_*Done senders are per-build HASHED (co_name AND class-dict key), so we never name them. Instead:
      //   * RESOLVE the battle class by a signature of PRESERVED INBOUND DC field names (btSig, default
      //     setState+setMembers+setMovie): a DC field's method name is fixed by the wire contract (C++
      //     receiveUpdate calls it by that name), so it survives the obfuscator -- setState+setMembers+
      //     setMovie together uniquely pick out DistributedBattleBase. Prefer the class defining them
      //     DIRECTLY.
      //   * WRAP each btMethod (default setState + sendUpdate) ON THAT CLASS. `setState` is defined there
      //     (INBOUND server state, ob_item[1]=state name). `sendUpdate` is INHERITED from DistributedObject
      //     (readable direct-tree method; GetAttrStr walks the MRO to it) -- setting the wrap on the battle
      //     class SCOPES it to battle objects only (no global hot path) and captures OUTBOUND done-reports
      //     by the DC field string (ob_item[1] ending in 'Done'), regardless of the hashed d_* helper name.
      // A hashed/absent method is reported + skipped, never fatal. Idempotent (ST.btInstalled). Called
      // eagerly at arm (if the battle module is already loaded = you are in a battle) AND lazily from the
      // modset start hook on the first battle interval (so it still arms if you attach BEFORE the fight).
      // Every wrap is recorded in ST.installed -> reverted on stop like any other (reverting an inherited
      // wrap re-sets the real inherited function as an own attr: behaviourally identical, changes nothing).
      // Pure resolution + setattr; clears the tstate on exit.
      ST.installBattleTrace = function(md){
        try {
          if (!ST.btEnabled || ST.btInstalled) return null;
          if (!(ST.GetAttrStr && ST.SetAttrStr && ST.scanBySignature)){ ST.clearExc(); return null; }
          md = md || ST.sysmodules(); if (md.isNull()){ ST.clearExc(); return null; }
          var found = ST.scanBySignature(md, ST.btSig);
          if (!found || !found.length){ ST.clearExc(); return null; }   // battle module not loaded yet -> retry later
          var direct = found.filter(function(r){ return r.all_direct; });
          var rec = direct.length ? direct[0] : found[0];
          var cls = rec.clsPtr; ST.keep.push(cls);
          ST.btInstalled = true;   // set BEFORE wiring so a re-entrant start() can't double-install
          var wired = [];
          for (var i=0;i<ST.btMethods.length;i++){
            var meth = ST.btMethods[i];
            var mn = Memory.allocUtf8String(meth);
            var orig = ST.GetAttrStr(cls, mn);   // walks the MRO -> finds inherited sendUpdate too
            if (orig.isNull()){ ST.clearExc(); wired.push({method:meth, ok:false, reason:'absent/hashed'}); continue; }
            var otn = ST.tpname(orig);
            if (otn !== 'function'){ ST.clearExc(); wired.push({method:meth, ok:false, reason:'not a function ('+otn+')'}); continue; }
            ST.keep.push(orig); ST.keep.push(mn);
            var kind = (meth === 'setState') ? 'setState' : ((meth === 'sendUpdate') ? 'send' : null);
            var im = ST.makeTraceWrap(orig, meth, kind);
            if (im.isNull()){ wired.push({method:meth, ok:false, reason:'wrap build NULL'}); continue; }
            var rc = ST.SetAttrStr(cls, mn, im);
            ST.recordInstall(cls, mn, orig);   // revert restores it
            wired.push({method:meth, ok:(rc===0), kind:kind, setattr_rc:rc});
          }
          ST.clearExc();
          var info = {cls:rec.class_name, sig:ST.btSig, all_direct:rec.all_direct,
                      module:(rec.bindings && rec.bindings[0] ? rec.bindings[0].module : '?'), wired:wired};
          try { send({t:'btinstall', info:info}); } catch(e){}
          return info;
        } catch(e){ ST.clearExc(); return null; }
      };

      out.ok = !!ST.pack1; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },

  arm: function () {
    try {
      ST.listener = Interceptor.attach(rpcHook(), {
        onEnter: function () {
          if (ST.done) return; ST.done = true;      // once, main thread, GIL held
          // read-only diagnostic: enumerate sys.modules to find the real names of our targets
          if (ST.mode === 'list') {
            try {
              var md = ST.sysmodules();
              if (md.isNull()){ ST.fin({ok:false, stage:'no sys.modules'}); return; }
              var it = ST.GetIter(md), all = [], total = 0, k;
              while (!(k = ST.IterNext(it)).isNull()) {
                total++;
                try { var s = ST.AsUTF8(k).readCString(); if (s) all.push(s); } catch(e){}
              }
              try { var f = new File('/tmp/ttrmod-modules.txt', 'w'); f.write(all.join('\n') + '\n'); f.flush(); f.close(); } catch(e){}
              var re = /Movie|Transition|Battle|Tunnel|Teleport|Book|LocalToon|[.]Toon$|showbase|DistributedBattle/;
              var matched = all.filter(function(s){ return re.test(s); }).sort();
              try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
              send({t:'done', r:{ok:true, stage:'listmods', total:total,
                                 wrote:'/tmp/ttrmod-modules.txt', matched_count:matched.length, sample:matched.slice(0,50)}});
            } catch(e){ send({t:'done', r:{ok:false, stage:'list ex', e:String(e)}}); }
            return;
          }
          // read-only DIAGNOSTIC: find the class(es) that define ALL requested methods, by SIGNATURE
          // (sidesteps the vault-hashed module/class names). Reports module key + bound attr name +
          // class __name__ + direct-vs-inherited (and base) per method, deduped by class pointer.
          if (ST.mode === 'findcls') {
            try {
              var mdF = ST.sysmodules();
              if (mdF.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }
              var methodsF = ST.methods || [];
              if (!methodsF.length){ ST.fin({ok:false, stage:'no TTRMOD_METHODS given'}); return; }
              var foundF = ST.scanBySignature(mdF, methodsF);
              var serF = foundF.map(function(r){
                return { class_name:r.class_name, cls_ptr:r.clsPtr.toString(), match_count:r.match_count,
                         all_direct:r.all_direct, methods:r.methods, bindings:r.bindings };
              });
              ST.clearExc();
              try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
              send({t:'done', r:{ok:(serF.length>0), stage:'findcls', methods:methodsF,
                                 match_count:serF.length, matches:serF}});
            } catch(e){ send({t:'done', r:{ok:false, stage:'findcls ex', e:String(e)}}); }
            return;
          }
          // read-only DISCOVERY: when exact method names are hashed, (a) run N exact all-present
          // signature scans (TTRMOD_METHODS, ';'-separated groups) and (b) a method-name SUBSTRING
          // scan (TTRMOD_SUBSTR) to reveal what the tunnel-ish methods are ACTUALLY called.
          if (ST.mode === 'findmeth') {
            try {
              var mdM = ST.sysmodules();
              if (mdM.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }
              var exact = [], groups = ST.methodGroups || [];
              for (var gi=0; gi<groups.length; gi++){
                var g = groups[gi];
                var fnd = ST.scanBySignature(mdM, g);
                exact.push({ methods:g, count:fnd.length,
                             sample: fnd.slice(0,12).map(function(r){ return {class_name:r.class_name, all_direct:r.all_direct,
                                       module:(r.bindings[0]?r.bindings[0].module:'?'), attr:(r.bindings[0]?r.bindings[0].attr:'?'),
                                       methods:r.methods}; }) });
              }
              var substr = [], subs = ST.substrs || [];
              if (subs.length){
                var sr = ST.scanBySubstr(mdM, subs);
                substr = sr.slice(0,80).map(function(r){ return {class_name:r.class_name, hits:r.hits, own_method_count:r.own_method_count,
                           module:(r.bindings[0]?r.bindings[0].module:'?'), attr:(r.bindings[0]?r.bindings[0].attr:'?')}; });
              }
              // optional: dump the OWN (non-dunder) method names of named classes (identify hashed classes)
              var listcls = [], lc = ST.listClasses || [];
              for (var li=0; li<lc.length; li++){
                var lcMod = ST.DictGetStr(mdM, Memory.allocUtf8String(lc[li].module));
                if (lcMod.isNull()){ ST.clearExc(); listcls.push({module:lc[li].module, cls:lc[li].cls, error:'module not loaded'}); continue; }
                var lcCls = ST.GetAttrStr(lcMod, Memory.allocUtf8String(lc[li].cls));
                if (lcCls.isNull()){ ST.clearExc(); listcls.push({module:lc[li].module, cls:lc[li].cls, error:'class not found'}); continue; }
                var dct = ptr(0); try { dct = lcCls.add(0x108).readPointer(); } catch(e){ dct = ptr(0); }
                var keys = [];
                if (!dct.isNull()){
                  var kit2 = ST.GetIter(dct);
                  if (!kit2.isNull()){ var kk2;
                    while (!(kk2 = ST.IterNext(kit2)).isNull()){
                      var s2 = null; try { s2 = ST.AsUTF8(kk2).readCString(); } catch(e){ s2 = null; }
                      if (s2 && s2[0] !== '_') keys.push(s2);
                    }
                  }
                }
                var cn = '?'; try { cn = lcCls.add(0x18).readPointer().readCString(); } catch(e){ cn = '?'; }
                listcls.push({module:lc[li].module, cls:lc[li].cls, class_name:cn, method_count:keys.length, methods:keys.sort()});
              }
              ST.clearExc();
              try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
              send({t:'done', r:{ok:true, stage:'findmeth', exact:exact,
                                 substr_query:subs, substr_count:substr.length, substr:substr, listcls:listcls}});
            } catch(e){ send({t:'done', r:{ok:false, stage:'findmeth ex', e:String(e)}}); }
            return;
          }
          // read-only: list a loaded class's own (non-dunder) attribute names
          if (ST.mode === 'listcls') {
            try {
              var md2 = ST.sysmodules();
              var mod2 = ST.DictGetStr(md2, Memory.allocUtf8String(ST.tmod));
              if (mod2.isNull()){ send({t:'done', r:{ok:false, stage:'mod not loaded: '+ST.tmod}}); return; }
              var cls2 = ST.GetAttrStr(mod2, Memory.allocUtf8String(ST.tcls));
              if (cls2.isNull()){ ST.fin({ok:false, stage:'no class '+ST.tcls}); return; }
              var dct = ST.GetAttrStr(cls2, Memory.allocUtf8String('__dict__'));
              if (dct.isNull()){ ST.fin({ok:false, stage:'no __dict__'}); return; }
              var it2 = ST.GetIter(dct), keys = [], kk;
              while (!(kk = ST.IterNext(it2)).isNull()) {
                try { var s2 = ST.AsUTF8(kk).readCString(); if (s2 && s2[0] !== '_') keys.push(s2); } catch(e){}
              }
              try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
              send({t:'done', r:{ok:true, stage:'listcls', cls:ST.tmod+'.'+ST.tcls, methods:keys.sort()}});
            } catch(e){ send({t:'done', r:{ok:false, stage:'listcls ex', e:String(e)}}); }
            return;
          }
          // SELF-CONTAINED dispatch proof: wrap getName on the EXACT type of base.localAvatar,
          // then CALL localAvatar.getName() ourselves -> must hit our trampoline. Then revert.
          // No user action, no MRO/instance ambiguity.
          if (ST.mode === 'selftest') {
            try {
              var md3 = ST.sysmodules();
              var bi = ST.DictGetStr(md3, Memory.allocUtf8String('builtins'));
              if (bi.isNull()){ send({t:'done', r:{ok:false, stage:'no builtins'}}); return; }
              var base = ST.GetAttrStr(bi, Memory.allocUtf8String('base'));
              if (base.isNull()){ ST.fin({ok:false, stage:'no base'}); return; }
              var av = ST.GetAttrStr(base, Memory.allocUtf8String('localAvatar'));
              if (av.isNull()){
                ST.clearExc();
                av = ST.GetAttrStr(bi, Memory.allocUtf8String('localAvatar'));   // fallback: the global
              }
              if (av.isNull()){
                ST.clearExc();
                // introspect base's attributes to find the local-avatar reference by name
                // scan base.__dict__ VALUES for an object whose class looks like a Toon/Avatar
                var bd = ST.GetAttrStr(base, Memory.allocUtf8String('__dict__'));
                var hits = []; var total0 = 0;
                if (!bd.isNull()){ var it0 = ST.GetIter(bd), k0;
                  while (!(k0 = ST.IterNext(it0)).isNull()){ total0++;
                    try { var key = ST.AsUTF8(k0).readCString();
                          var val = ST.GetItem(bd, k0);                 // base.__dict__[key] = value (no descriptor)
                          if (!val.isNull()){ var tn = ST.tpname(val);
                            if (tn && /toon|avatar|distributed|local|player/i.test(tn) && hits.length < 30) hits.push({attr:key, type:tn}); } }
                    catch(e){} } }
                ST.clearExc();
                ST.fin({ok:false, stage:'no localAvatar', base_attr_count: total0, toon_like_attrs: hits});
                return;
              }
              var avType = av.add(8).readPointer();                 // ob_type = exact instance class
              var mn = Memory.allocUtf8String('getName');
              var orig = ST.GetAttrStr(avType, mn);
              if (orig.isNull()){ ST.fin({ok:false, stage:'no getName on type'}); return; }
              ST.keep.push(orig); ST.keep.push(avType); ST.keep.push(mn); ST.keep.push(av);
              ST.orig = orig;
              ST.cb = new NativeCallback(function (self, args, kwargs) {
                ST.fires = (ST.fires||0) + 1; if (ST.fires<=3) send({t:'fired', n:ST.fires});
                return ST.Call(ST.orig, args, kwargs.isNull()?ptr(0):kwargs);
              }, 'pointer', ['pointer','pointer','pointer']);
              ST.keep.push(ST.cb);
              var mnm = Memory.allocUtf8String('ttrmod_st'); ST.keep.push(mnm);
              var mdef = Memory.alloc(32); ST.keep.push(mdef);
              mdef.writePointer(mnm); mdef.add(8).writePointer(ST.cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
              var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); ST.keep.push(cfunc);
              if (cfunc.isNull()){ ST.fin({ok:false, stage:'CFuncNewEx NULL'}); return; }
              var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); ST.keep.push(im);
              if (im.isNull()){ ST.fin({ok:false, stage:'instancemethod NULL'}); return; }
              var rc = ST.SetAttrStr(avType, mn, im);               // install on the exact type
              var bound = ST.GetAttrStr(av, mn);                    // av.getName -> our im, bound to av
              var res = bound.isNull() ? ptr(0) : ST.Call(bound, ST.TupleNew(0), ptr(0));  // CALL it -> fires
              ST.SetAttrStr(avType, mn, orig);                      // revert immediately
              ST.fin({ok:(rc===0 && (ST.fires||0)>0), stage:'selftest',
                      setattr_rc:rc, fires:(ST.fires||0), res_nonnull:!res.isNull()});
            } catch(e){ ST.fin({ok:false, stage:'selftest ex', e:String(e)}); }
            return;
          }
          // MILESTONE-2 first live target: wrap-after on the street-tunnel walk. The target class
          // (LocalToon) lives under a fully vault-HASHED module name, so we DO NOT resolve it by
          // name -- we SELF-DISCOVER it by its method signature (handleTunnelIn+handleTunnelOut) with
          // the shared read-only scan, then wrap those methods on the discovered class object. A
          // TTRMOD_TMOD/TTRMOD_TCLS pair forces name-based resolution as a fallback.
          if (ST.mode === 'mod1' || ST.mode === 'modset') {
            try {
              var m = ST.mod1;
              var mods0 = ST.sysmodules();
              if (mods0.isNull()){ ST.fin({ok:false, stage:'no sys.modules'}); return; }
              var targets = [];   // [{clsPtr, module, attr, class_name, all_direct, via}]
              if (m.override && m.override.module && m.override.cls){
                // fallback: sys.modules[override.module].<override.cls>
                var mmO = ST.DictGetStr(mods0, Memory.allocUtf8String(m.override.module));
                if (mmO.isNull()){ ST.fin({ok:false, stage:'override module not loaded: '+m.override.module}); return; }
                var ccO = ST.GetAttrStr(mmO, Memory.allocUtf8String(m.override.cls));
                if (ccO.isNull()){ ST.fin({ok:false, stage:'no class '+m.override.cls+' in '+m.override.module}); return; }
                targets.push({clsPtr:ccO, module:m.override.module, attr:m.override.cls, class_name:m.override.cls, all_direct:null, via:'override'});
              } else {
                // SELF-DISCOVER by method signature (sidesteps the vault-hashed name).
                var found = ST.scanBySignature(mods0, m.methods);
                // prefer classes where ALL methods are DIRECT (the defining class -> clean revert via
                // setattr); fall back to any full match if none are all-direct.
                var direct = found.filter(function(r){ return r.all_direct; });
                var chosen = direct.length ? direct : found;
                for (var ci = 0; ci < chosen.length; ci++){
                  var r = chosen[ci];
                  targets.push({clsPtr:r.clsPtr, module:(r.bindings[0]?r.bindings[0].module:'?'),
                                attr:(r.bindings[0]?r.bindings[0].attr:'?'), class_name:r.class_name,
                                all_direct:r.all_direct, via:'signature'});
                }
              }
              if (!targets.length){ ST.fin({ok:false, stage:'no class matched signature '+m.methods.join('+')+' (walk in-world first?)'}); return; }
              ST.installed = [];
              var wired = [], anyOk = false, ti, mi;
              // discovery uses m.methods (the signature); the methods we actually WRAP are
              // m.wrapMethods (default = m.methods) -- lets us discover the interval class by a broad
              // signature but wrap only `start`.
              var wrapMethods = (m.wrapMethods && m.wrapMethods.length) ? m.wrapMethods : m.methods;
              for (ti = 0; ti < targets.length; ti++){
                var cls0 = targets[ti].clsPtr; ST.keep.push(cls0);
                for (mi = 0; mi < wrapMethods.length; mi++){
                  var meth0 = wrapMethods[mi];
                  var mn0 = Memory.allocUtf8String(meth0);
                  var orig0 = ST.GetAttrStr(cls0, mn0);
                  if (orig0.isNull()){ ST.clearExc(); wired.push({cls:targets[ti].class_name, method:meth0, ok:false, reason:'method absent'}); continue; }
                  // SAFETY: only wrap real functions. Vault-hashed class __dict__ keys include string
                  // class-attrs (e.g. Transitions.IrisModelName/FadeModelName -> vlt...); replacing one
                  // with a trampoline would corrupt it. A plain method is a 'function' object.
                  var otn0 = ST.tpname(orig0);
                  if (otn0 !== 'function'){ ST.clearExc(); wired.push({cls:targets[ti].class_name, method:meth0, ok:false, reason:'not a function ('+otn0+')'}); continue; }
                  ST.keep.push(orig0); ST.keep.push(mn0);
                  var im0 = ST.makeWrapAfter(orig0, m.spec, m.factor, meth0);
                  if (im0.isNull()){ wired.push({cls:targets[ti].class_name, method:meth0, ok:false, reason:'wrap build NULL'}); continue; }
                  var rc0 = ST.SetAttrStr(cls0, mn0, im0);
                  ST.recordInstall(cls0, mn0, orig0);   // MetaInterval.start wrap-after -> revert restores it
                  if (rc0 === 0) anyOk = true;
                  wired.push({cls:targets[ti].class_name, method:meth0, ok:(rc0===0), setattr_rc:rc0});
                }
              }
              // WRAP-AROUND CONTEXT targets (e.g. tunnelOut). Resolve each configured context
              // method's OWNING class by that method's SIGNATURE (never by the hashed class name),
              // preferring where it is defined directly, then wrap the method wrap-AROUND so ST.ctx
              // is set for the call's duration. NON-FATAL: a context method that doesn't resolve
              // (e.g. the hashed-away tunnelIn, or a class not yet in-world) is reported and skipped
              // -- it never blocks the modset install. Reverted via ST.installed like any wrap.
              var ctxList = m.context || [], ctxWired = [];
              for (var ci2 = 0; ci2 < ctxList.length; ci2++){
                var ce = ctxList[ci2];
                if (!ce || !ce.method){ continue; }
                var cFactor = (ce.factor !== undefined && ce.factor !== null) ? ce.factor : m.factor;
                var cfound = ST.scanBySignature(mods0, [ce.method]);
                var cdirect = cfound.filter(function(r){ return r.all_direct; });
                var cchosen = cdirect.length ? cdirect : cfound;
                if (!cchosen.length){
                  ctxWired.push({method:ce.method, group:ce.group, factor:cFactor, ok:false,
                                 reason:'no class matched signature (hashed away, or class not in-world yet)'});
                  continue;
                }
                for (var cj = 0; cj < cchosen.length; cj++){
                  var ccls = cchosen[cj].clsPtr; ST.keep.push(ccls);
                  var cmn = Memory.allocUtf8String(ce.method);
                  var corig = ST.GetAttrStr(ccls, cmn);
                  if (corig.isNull()){ ST.clearExc(); ctxWired.push({method:ce.method, group:ce.group, cls:cchosen[cj].class_name, ok:false, reason:'method absent'}); continue; }
                  var cotn = ST.tpname(corig);
                  if (cotn !== 'function'){ ST.clearExc(); ctxWired.push({method:ce.method, group:ce.group, cls:cchosen[cj].class_name, ok:false, reason:'not a function ('+cotn+')'}); continue; }
                  ST.keep.push(corig); ST.keep.push(cmn);
                  var cim = ST.makeCtxWrap(corig, ce.group, cFactor, ce.method);
                  if (cim.isNull()){ ctxWired.push({method:ce.method, group:ce.group, cls:cchosen[cj].class_name, ok:false, reason:'ctx wrap build NULL'}); continue; }
                  var crc = ST.SetAttrStr(ccls, cmn, cim);
                  ST.recordInstall(ccls, cmn, corig);   // context wrap-around (tunnelOut/...) -> revert restores it
                  if (crc === 0) anyOk = true;
                  ctxWired.push({method:ce.method, group:ce.group, factor:cFactor,
                                 cls:cchosen[cj].class_name, all_direct:cchosen[cj].all_direct,
                                 ok:(crc===0), setattr_rc:crc});
                }
              }
              // TUNNEL-LOCALTOON-IRIS: resolve LocalToon's OWN method SET up front (best-effort) so the
              // FIRST tunnel walk pays no scan cost. Uses the SAME signature scan as the tunnelOut context
              // (LocalToon is resolvable by 'tunnelOut'). Harmless if the toon isn't in-world yet -- the
              // per-start path re-resolves (iris-gated, so at most once per zone transition). Reported in
              // ltiris so the operator sees the class + method count that will gate the arrival scale.
              var ltInfo = {enabled: ST.ltIrisEnabled};
              if (ST.mode === 'modset' && ST.ltIrisEnabled){
                try { ST.resolveLocalToonMethods(mods0); } catch(e){ ST.clearExc(); }
                if (ST.localToonMethods){
                  ltInfo.resolved = true; ltInfo.cls = ST.localToonName;
                  ltInfo.method_count = Object.keys(ST.localToonMethods).length;
                  ltInfo.sig = ST.ltSig; ltInfo.factor = ST.ltIrisFactor; ltInfo.iris_window_ms = ST.ltIrisWindowMs;
                } else {
                  ltInfo.resolved = false; ltInfo.sig = ST.ltSig;
                  ltInfo.note = 'LocalToon not resolved at install (walk in-world first?); retries per iris-correlated start';
                }
              }
              // BATTLETRACE (READ-ONLY): resolve the battle FSM class by signature and install logging
              // wraps on setState + the d_*Done senders. Best-effort here (needs the battle module loaded
              // = you are already in a battle); otherwise the modset start hook installs it lazily on the
              // first battle-named interval. Reverted via ST.installed like any wrap.
              var btInfo = {enabled: ST.btEnabled};
              if (ST.btEnabled){
                try { var bi = ST.installBattleTrace(mods0); if (bi){ btInfo.installed = true; btInfo.cls = bi.cls; btInfo.wired = bi.wired; }
                      else { btInfo.installed = false; btInfo.note = 'battle FSM class not resolved at install (be IN a battle, or it arms lazily on the first battle interval)'; } }
                catch(e){ ST.clearExc(); }
                btInfo.methods = ST.btMethods; btInfo.sig = ST.btSig; btInfo.names = ST.btNames;
              }
              ST.fin({ok:anyOk, stage:'mod1_installed',
                      resolved_by: (m.override && m.override.module ? 'override' : 'signature-scan'),
                      targets: targets.map(function(t){ return {module:t.module, attr:t.attr, class_name:t.class_name, all_direct:t.all_direct}; }),
                      methods: m.methods, attr: m.spec.attr, factor: m.factor,
                      wired: wired, ctx_wired: ctxWired, ltiris: ltInfo, battletrace: btInfo,
                      note:'wrap-after live; walk into a street tunnel to see it fire + speed the walk'});
            } catch(e){ ST.fin({ok:false, stage:'mod1 ex', e:String(e)}); }
            return;
          }
          try {
            var mods = ST.sysmodules();
            if (mods.isNull()){ ST.fin({ok:false, stage:'no sys.modules'}); return; }
            var modName = Memory.allocUtf8String(ST.tmod);
            var mod = ST.DictGetStr(mods, modName);   // borrowed
            if (mod.isNull()){ send({t:'done', r:{ok:false, stage:'module not loaded: '+ST.tmod}}); return; }
            var clsName = Memory.allocUtf8String(ST.tcls);
            var cls = ST.GetAttrStr(mod, clsName);
            if (cls.isNull()){ ST.fin({ok:false, stage:'no class '+ST.tcls}); return; }
            var methName = Memory.allocUtf8String(ST.tmeth);
            var orig = ST.GetAttrStr(cls, methName);
            if (orig.isNull()){ ST.fin({ok:false, stage:'no method '+ST.tmeth}); return; }
            ST.orig = orig; ST.keep.push(orig);
            send({t:'stage', s:'got_target', cls:cls.toString(), orig:orig.toString()});

            // PASS-THROUGH wrapper (METH_VARARGS|METH_KEYWORDS = 0x3): fn(self, args, kwargs).
            // Installed via instancemethod so inst.method(...) -> args=(inst, *call_args).
            ST.cb = new NativeCallback(function (self, args, kwargs) {
              try { ST.fires = (ST.fires||0) + 1; if (ST.fires<=3) send({t:'fired', n:ST.fires}); } catch(e){}
              return ST.Call(ST.orig, args, kwargs.isNull()?ptr(0):kwargs);   // call original, pass result through
            }, 'pointer', ['pointer','pointer','pointer']);
            ST.keep.push(ST.cb);
            ST.mname = Memory.allocUtf8String('ttrmod_wrap'); ST.keep.push(ST.mname);
            ST.mdef = Memory.alloc(32); ST.keep.push(ST.mdef);
            ST.mdef.writePointer(ST.mname);            // ml_name
            ST.mdef.add(8).writePointer(ST.cb);        // ml_meth
            ST.mdef.add(16).writeU32(0x3);             // ml_flags = VARARGS|KEYWORDS
            ST.mdef.add(24).writePointer(ptr(0));      // ml_doc
            var cfunc = ST.CFuncNewEx(ST.mdef, ptr(0), ptr(0));
            if (cfunc.isNull()){ ST.fin({ok:false, stage:'CFuncNewEx NULL'}); return; }
            ST.keep.push(cfunc);
            var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0));   // self-binding instancemethod
            if (im.isNull()){ ST.fin({ok:false, stage:'instancemethod NULL'}); return; }
            ST.keep.push(im);
            var rc = ST.SetAttrStr(cls, methName, im);
            // keep class + method-name alive so we can REVERT before the session tears down
            // (the trampoline's native code lives in this session's memory; leaving it installed
            // past detach = a dangling call target = crash on the next invocation).
            ST.cls = cls; ST.keep.push(cls); ST.methNameStr = methName; ST.keep.push(methName);
            ST.recordInstall(cls, methName, orig);   // legacy single install -> revert restores it too
            // ST.fin clears any pending exc, detaches the INTERCEPTOR (not the session — the
            // NativeCallback stays valid while attached), and reports.
            ST.fin({ok:(rc===0), stage:'installed', setattr_rc:rc,
                    target: ST.tmod+'.'+ST.tcls+'.'+ST.tmeth,
                    note:'trampoline live; trigger '+ST.tmeth+' in-game to see it fire'});
          } catch(e){ ST.fin({ok:false, stage:'install ex', e:String(e)}); }
        }
      });
      return { ok:true };
    } catch(e){ return { ok:false, notes:['arm ex: '+e] }; }
  },
  // report fire count on demand (host polls after the user triggers the target)
  fires: function () { return ST ? (ST.fires||0) : -1; },
  // per-method count of intervals actually setPlayRate'd (identifies which hashed method is a
  // transition-starter and confirms the interval attr resolved). {} until something lands.
  appliedBy: function () { return (ST && ST.appliedBy) ? ST.appliedBy : {}; },
  // modset: how many intervals were setPlayRate'd, tallied by interval NAME and by GROUP.
  // {names:{}, groups:{}} until something scales. The report's evidence of which groups landed.
  scaledInfo: function () { return (ST) ? {names: ST.scaledNames || {}, groups: ST.scaledGroups || {}} : {}; },

  // REVERT: restore the original method (must run before session detach, on a GIL thread).
  // Re-arm a one-shot frame-eval hook that setattrs the original back, then detaches.
  revert: function () {
    try {
      // SINGLE SOURCE OF TRUTH: ST.installed holds EVERY wrap installed via ST.recordInstall --
      // the MetaInterval.start wrap-after, every context wrap-around (tunnelOut/tunnelIn/...), and
      // the legacy single install. Enumerate and restore ALL of them; skipping even one leaves a
      // dangling trampoline that crashes on the next call once the session drops.
      var items = (ST && ST.installed) ? ST.installed : null;
      if (!items || !items.length){ return { ok:false, e:'nothing installed' }; }
      ST.reverted = false;                              // allow a re-arm (host retries if a setattr fails)
      ST.rlistener = Interceptor.attach(ST.hook, {
        onEnter: function () {
          if (ST.reverted) return; ST.reverted = true;  // one-shot, main thread, GIL held
          try {
            var rcs = [], allOk = true;
            for (var i=0;i<items.length;i++){
              var rc = ST.SetAttrStr(items[i].cls, items[i].mn, items[i].orig);
              rcs.push(rc); if (rc !== 0) allOk = false;
            }
            ST.clearExc();
            // detach the frida Interceptor ONLY after every original is restored, so no wrap is ever
            // left pointing at freed agent memory. all_ok=false => the host must NOT detach.
            try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
            send({t:'reverted', rc:rcs, n:items.length, all_ok:allOk});
          } catch(e){ send({t:'reverted', err:String(e)}); }
        }
      });
      return { ok:true, n:items.length };
    } catch(e){ return { ok:false, e:String(e) }; }
  }
};
// hook address injected by init via a global (kept simple)
function rpcHook(){ return ST.hook; }
"""


# ============================ crash-safe STOP + REVERT (host side) ============================
# THE STOP PROBLEM. In persistent (modset "play") mode the host stays resident, and on stop it MUST
# revert every installed wrap BEFORE the frida session drops -- the trampolines live in the agent's
# memory and die with the session, so any wrap still installed then points at freed memory and the
# constantly-firing MetaInterval.start hook crashes the game on the very next interval start.
#
# Ctrl+C is NOT a trustworthy stop here: the compiled runner (frida/ttr-frida-runner, launched under
# sudo via frida/run-injector.sh) dies HARD on SIGINT -- the process is torn down before Python's
# KeyboardInterrupt/`except` revert path runs (observed live: the log ended mid-scaling with NO
# [reverting]/[reverted]/Ctrl+C lines and TTREngine gone). So the RELIABLE stop is a STOP FILE polled
# in the resident loop (no signal handling at all): scripts/tt-mod-stop drops it. SIGTERM is ALSO
# handled (so `kill -TERM` is safe), and Ctrl+C/KeyboardInterrupt is kept as a best-effort belt. All
# paths converge on revert_and_detach(), which restores EVERY installed wrap and detaches ONLY once
# the revert is confirmed.
#
# These helpers are module-level (not nested in main) so localtest/stoprevert_test.py can drive the
# REAL logic offline with a faithful fake agent -- no frida, no root, no live game.

# The stop file lives in the system temp dir on Windows (no /tmp); the tray already agrees on this
# default (TTRFF_STOPFILE / %TEMP%\ttrmod-stop), and scripts/tt-mod-stop.cmd does too.
DEFAULT_STOPFILE = os.path.join(tempfile.gettempdir(), "ttrmod-stop") if IS_WINDOWS else "/tmp/ttrmod-stop"


def find_engine_pids():
    """PIDs of running engine processes, via pgrep (posix) or psutil/tasklist (Windows). Raises on
    no match so callers can surface it exactly like the old pgrep failure. psutil is a hard dep of
    the tray; on Windows the injector runs under the same Python (TTRFF_INJECTOR_PYTHON)."""
    if not IS_WINDOWS:
        out = subprocess.check_output(["pgrep", "-f", "TTREngine"]).split()
        return [int(p) for p in out]
    try:
        import psutil
    except ImportError:
        # tasklist fallback: name-only match (TTREngine.exe), fine for a same-user process
        # IMAGENAME eq is an EXACT match, but the shipped Windows exe is TTREngine64.exe -- so
        # filter with a trailing wildcard (tasklist supports it) per needle, and keep the
        # substring re-check below as the real gate.
        pids = []
        for needle in ENGINE_NEEDLES:
            try:
                out = subprocess.check_output(
                    ["tasklist", "/FI", "IMAGENAME eq %s*" % needle, "/FO", "CSV", "/NH"],
                    text=True, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                continue
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2 and needle in parts[0].lower():
                    try:
                        pids.append(int(parts[1]))
                    except ValueError:
                        pass
        if not pids:
            raise RuntimeError("no engine process found via tasklist for names: %s"
                               % ",".join(ENGINE_NEEDLES))
        return sorted(set(pids))
    pids = []
    for p in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            info = p.info
            hay = " ".join(filter(None, [
                info.get("name") or "",
                info.get("exe") or "",
                " ".join(info.get("cmdline") or []),
            ])).lower()
        except Exception:
            continue
        if any(n in hay for n in ENGINE_NEEDLES):
            pids.append(p.pid)
    if not pids:
        raise RuntimeError("no engine process found for names: %s" % ",".join(ENGINE_NEEDLES))
    return pids


def engine_alive():
    """True if any engine process is running (drives the revert-confirmation alive_check)."""
    try:
        return bool(find_engine_pids())
    except Exception:
        return False


def stopfile_path():
    """The stop file the resident loop watches: $TTRMOD_STOPFILE, else the platform default
    (/tmp/ttrmod-stop on posix; %TEMP%\\ttrmod-stop on Windows -- the same file the tray and
    scripts/tt-mod-stop watch)."""
    return os.environ.get("TTRMOD_STOPFILE") or DEFAULT_STOPFILE


def clear_stopfile(stopfile):
    """Remove the stop file if present (best-effort). Called to clear a STALE file before the loop
    and to CONSUME it after a confirmed revert+detach, so a leftover never instantly stops a run."""
    try:
        if os.path.exists(stopfile):
            os.remove(stopfile)
    except Exception:
        pass


def make_stop_state():
    return {"stop": False, "reason": None}


def request_stop(stop, reason):
    """Mark that a stop was requested (idempotent; the FIRST reason sticks)."""
    if not stop["stop"]:
        stop["reason"] = reason
    stop["stop"] = True


def install_sigterm(stop, log=print):
    """Make `kill -TERM <pid>` trigger the same graceful revert as the stop file: the handler just
    sets the stop flag; the resident loop notices it within a tick. Returns the previous handler
    (so callers/tests can restore it)."""
    def _handler(signum, frame):
        request_stop(stop, "SIGTERM")
    try:
        return signal.signal(signal.SIGTERM, _handler)
    except Exception:
        return None


def wait_for_stop(box, stop, stopfile, persist, poll_s, fires_fn=None, log=print,
                  tick=0.5, now_fn=None, sleep_fn=None):
    """Resident poll loop. Returns the reason it stopped: 'stop-file', a signal reason ('SIGTERM'),
    'detached', or 'timeout' (bounded modes). The STOP FILE is checked every `tick` so stopping needs
    no working signal delivery. KeyboardInterrupt propagates to the caller (best-effort belt)."""
    import time as _time
    now_fn = now_fn or _time.time
    sleep_fn = sleep_fn or _time.sleep
    t0 = now_fn()
    last = 0
    last_beat = t0
    while True:
        if box.get("detached"):
            return "detached"
        if os.path.exists(stopfile):
            request_stop(stop, "stop-file")
            return "stop-file"
        if stop["stop"]:
            return stop["reason"] or "stop"
        sleep_fn(tick)
        f = last
        if fires_fn is not None:
            try:
                f = fires_fn()
            except Exception:
                return "detached"        # session gone -> treat as detached
        now = now_fn()
        if persist:
            if now - last_beat >= 30.0:
                log("[tramp-live] alive - fires=%d (stop with scripts/tt-mod-stop, NOT Ctrl+C)" % f)
                last_beat = now
        else:
            if f != last:
                log("[tramp-live] fires=%d" % f)
            if now - t0 >= poll_s:
                return "timeout"
        last = f


def revert_and_detach(ex, session, box, rev, target_label, alive_check=None,
                      confirm_timeout=8.0, log=print):
    """Revert ALL installed wraps, then detach ONLY once the revert is CONFIRMED (the agent's
    'reverted' message came back AND every setattr rc was 0). If it cannot confirm within the
    timeout, do NOT detach and do NOT let the process exit -- staying ATTACHED keeps the agent's
    trampolines valid (game alive), whereas exiting would drop the session with wraps still live and
    crash the game on the next interval start. Returns True if reverted+detached, False if it gave up
    because the game process is gone (trampolines then moot) or the session detached under us."""
    if alive_check is None:
        alive_check = engine_alive
    if box.get("detached"):
        return False
    if not alive_check():
        log("[tramp-live] game already gone - nothing to revert; not detaching")
        return False
    log("[tramp-live] reverting (restoring ALL installed wraps: %s) before detach..." % target_label)
    box["reverted"] = False
    box["revert_ok"] = None
    rev.clear()
    ex.revert()
    while True:
        if rev.wait(confirm_timeout):
            if box.get("revert_ok"):
                log("[tramp-live] reverted OK - all originals restored; detaching")
                try:
                    session.detach()
                except Exception:
                    pass
                return True
            # the hook fired but a setattr FAILED (a wrap may still dangle) -> re-arm and retry.
            log("[tramp-live] !! revert reported a FAILED setattr (rc=%s) - NOT detaching; retrying"
                % box.get("revert_rc"))
            if box.get("detached") or not alive_check():
                log("[tramp-live] game gone/detached while retrying - trampolines moot; stopping")
                return False
            box["reverted"] = False
            box["revert_ok"] = None
            rev.clear()
            ex.revert()
            continue
        # timed out: the one-shot revert hook is still armed (never fired -- game idle/frozen?). Do
        # NOT clear rev (nothing was set) and do NOT detach. Stay attached so no trampoline dangles.
        log("[tramp-live] !! revert not confirmed in %gs - NOT detaching. Staying ATTACHED (process "
            "alive => mods live => game alive) rather than dropping with wraps live. The game may be "
            "idle/frozen (no Python frames => the revert hook can't fire); use tt-mod-stop again once "
            "it's responsive." % confirm_timeout)
        if box.get("detached"):
            log("[tramp-live] session detached under us while waiting - trampolines moot; stopping")
            return False
        if not alive_check():
            log("[tramp-live] game process gone while waiting - trampolines moot; stopping")
            return False
        # loop: keep waiting for the still-armed hook to fire on the next frame.


def main():
    # UTF-8 + line-buffered: immediate logs even when the runner wraps/pipes stdout
    # (belt-and-suspenders with PYTHONUNBUFFERED). encoding matters on Windows, where a piped
    # stdout defaults to cp1252 and mangles the em-dashes in these messages -- the tray appends
    # its own [tray] lines to the SAME file, so both sides must agree on UTF-8.
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception: pass
    syms = load_symbols()
    missing, tuple_fn = readiness(syms)
    print("[tramp-live] symbols loaded: %d ; tuple builder: %s" % (len(syms), tuple_fn))
    if missing:
        print("[tramp-live] NOT READY — missing for milestone-1 pass-through: %s" % ", ".join(missing))
        print("[tramp-live] (these come from capi-symbols2.json — the running symbol hunt)")
        return
    if IS_WINDOWS:
        # The RE tables are macOS arm64 (May-2024 TTREngine) vmaddrs. The Windows engine is a
        # different binary (x64, different layout + per-build hashes); attaching with these tables
        # would read garbage addresses and crash the client. A Windows engine build must be
        # re-derived first (STATUS.md "Fragility") and shipped as its own per-build entry. The
        # TTRMOD_WIN_TABLE=1 escape hatch forces a run against a derived-but-unshipped table.
        gap = win_float_gap(syms)
        if gap:
            print("[tramp-live] NOT READY — the Windows table has no way to build a Python float: "
                  "no PyFloat_FromDouble symbol, and the hand-built fallback is missing %s. "
                  "setPlayRate cannot be called without one of those. NOT overridable by "
                  "TTRMOD_WIN_TABLE. See STATUS.md 'Windows per-build derivation'." % ", ".join(gap))
            return
        if os.environ.get("TTRMOD_WIN_TABLE", "") not in ("1", "true", "yes"):
            print("[tramp-live] NOT READY — a Windows per-build table is present and complete, but "
                  "has never been validated against a live client. Set TTRMOD_WIN_TABLE=1 to take "
                  "that first attach (expect to need scripts/ttdrive.py to recover if it crashes).")
            return
    import frida
    # add the frame-eval hook addr (from offsets.json) to syms passing
    off = json.load(open(os.path.join(ROOT, "offsets.json")))
    ent = off[next(k for k in off if k not in ("_comment",))]
    hook_va = ent["addrs"]["eval_frame_default"]

    # method signature for findcls / mod1 self-discovery (default = the tunnel pair). TTRMOD_METHODS
    # is a flat comma list for findcls/mod1; for findmeth it may hold ';'-separated groups. TTRMOD_SUBSTR
    # (comma list) drives findmeth's method-name substring discovery.
    raw_methods = os.environ.get("TTRMOD_METHODS", "handleTunnelIn,handleTunnelOut")
    methods = [s.strip() for s in raw_methods.replace(";", ",").split(",") if s.strip()]
    method_groups = [[s.strip() for s in grp.split(",") if s.strip()] for grp in raw_methods.split(";") if grp.strip()]
    substrs = [s.strip() for s in os.environ.get("TTRMOD_SUBSTR", "").split(",") if s.strip()]
    list_classes = []
    for pair in os.environ.get("TTRMOD_LISTCLS", "").split(","):
        pair = pair.strip()
        if "::" in pair:
            mm, cc = pair.split("::", 1); list_classes.append({"module": mm.strip(), "cls": cc.strip()})
    MOD1["methods"] = methods
    ovr_mod = os.environ.get("TTRMOD_TMOD"); ovr_cls = os.environ.get("TTRMOD_TCLS")
    MOD1["override"] = ({"module": ovr_mod, "cls": ovr_cls} if (ovr_mod and ovr_cls) else None)
    MOD1["probe_attrs"] = os.environ.get("TTRMOD_PROBE_ATTRS", "") in ("1", "true", "yes")
    if os.environ.get("TTRMOD_ATTR"):
        MOD1["spec"] = {"mode": "attr", "attr": os.environ["TTRMOD_ATTR"]}   # override the interval attr
    # GENERAL INTERVAL HOOK: discover the interval class by TTRMOD_METHODS, wrap only TTRMOD_WRAP
    # (e.g. "start"), and use the `byname` spec -- read each started interval's getName(), LOG it
    # (TTRMOD_LOGNAMES=1), and setPlayRate ONLY intervals whose name contains a TTRMOD_BYNAME substring.
    MOD1["wrapMethods"] = [s.strip() for s in os.environ.get("TTRMOD_WRAP", "").split(",") if s.strip()]
    byname = [s.strip() for s in os.environ.get("TTRMOD_BYNAME", "").split(",") if s.strip()]
    if byname or os.environ.get("TTRMOD_LOGNAMES", "") in ("1", "true", "yes"):
        MOD1["spec"] = {"mode": "byname", "subs": byname,
                        "log": os.environ.get("TTRMOD_LOGNAMES", "") in ("1", "true", "yes")}
    if os.environ.get("TTRMOD_FACTOR"):
        MOD1["factor"] = float(os.environ["TTRMOD_FACTOR"])

    # BATTLETRACE (READ-ONLY diagnosis): TTRMOD_BATTLETRACE=1 layers timestamped logging on top of the
    # (unchanged) modset run so each inter-step battle delay can be attributed to a CLIENT timer or a
    # SERVER-gated event. It installs NOTHING that changes gameplay. HASHING-PROOF: the battle class and
    # its d_*Done senders are per-build hashed, so we never name them -- we (a) resolve the battle class by
    # a signature of PRESERVED INBOUND DC field names (setState+setMembers+setMovie; DC field method names
    # are fixed by the wire contract, so they survive the obfuscator), then (b) wrap INBOUND `setState`
    # (server state + name) and OUTBOUND `sendUpdate` (the readable direct-tree sender; we log only field
    # names ending in 'Done' = the client's step-finished reports, whose NAME is the fixed DC string even
    # though d_movieDone itself is hashed), plus a start-timestamp/duration line for battle intervals.
    # All env-overridable: TTRMOD_BT_METHODS (methods to wrap), TTRMOD_BT_SIG (the preserved-name signature
    # that resolves the battle class), TTRMOD_BT_NAMES (battle interval substrings).
    bt_on = os.environ.get("TTRMOD_BATTLETRACE", "") in ("1", "true", "yes")
    bt_methods = [s.strip() for s in os.environ.get(
        "TTRMOD_BT_METHODS", "setState,sendUpdate").split(",") if s.strip()]
    bt_sig = [s.strip() for s in os.environ.get("TTRMOD_BT_SIG", "setState,setMembers,setMovie").split(",") if s.strip()]
    bt_names = [s.strip() for s in os.environ.get(
        "TTRMOD_BT_NAMES", "faceoff-battle,movie-track,movie-reward-track,to-pending").split(",") if s.strip()]
    MOD1["battletrace"] = {"enabled": bt_on, "methods": bt_methods, "sig": bt_sig, "names": bt_names}
    if bt_on:
        print("[tramp-live] BATTLETRACE ON (read-only): wrap methods=%s ; resolve battle class by sig=%s ; "
              "battle intervals=%s" % ("/".join(bt_methods), "+".join(bt_sig), ",".join(bt_names)))

    mode = os.environ.get("TTRMOD_MODE", "install")

    # MODSET (production): ONE install of the MetaInterval.start hook driven by the curated
    # name->factor table (modset.json). Reuses the mod1 code path (discover the interval class,
    # wrap `start`, wrap-after) but with the per-entry `modset` spec instead of a single factor.
    # Defaults: pin the proven-live Python MetaInterval class by NAME (override) and wrap only
    # `start`. Setting TTRMOD_TMOD+TTRMOD_TCLS re-pins a different class (e.g. after an auto-patch);
    # clearing both would fall back to the signature scan (META_INTERVAL_SIG).
    if mode == "modset":
        tbl_path = os.environ.get("TTRMOD_MODSET", os.path.join(ROOT, "modset.json"))
        entries, log_unmatched, context, spawn_context, tunnel_cfg, ltiris_cfg = load_modset(tbl_path)
        if not (ovr_mod and ovr_cls):
            MOD1["override"] = {"module": META_INTERVAL_MODULE, "cls": META_INTERVAL_CLASS}
        MOD1["methods"] = list(META_INTERVAL_SIG)   # signature fallback if the override is cleared
        if not MOD1["wrapMethods"]:
            MOD1["wrapMethods"] = ["start"]
        want_log = log_unmatched
        env_log = os.environ.get("TTRMOD_LOGNAMES", "")
        if env_log != "":
            want_log = env_log in ("1", "true", "yes")
        # TUNNEL-IDENTITY: scale the street-tunnel WALK (localAvatar.tunnelTrack) by OBJECT IDENTITY.
        # From modset.json `tunnel_identity`, with env overrides. attr pinned => skip discovery.
        tun = {
            "enabled": bool(tunnel_cfg.get("enabled", True)),
            "attr":    tunnel_cfg.get("attr"),
            "factor":  float(tunnel_cfg.get("factor", 4.0)),
            "iris_window_ms": int(tunnel_cfg.get("iris_window_ms", 200)),
        }
        if os.environ.get("TTRMOD_TUNNEL", "") in ("0", "false", "no"):
            tun["enabled"] = False
        if os.environ.get("TTRMOD_TUNNEL_ATTR"):
            tun["attr"] = os.environ["TTRMOD_TUNNEL_ATTR"]
        if os.environ.get("TTRMOD_TUNNEL_FACTOR"):
            tun["factor"] = float(os.environ["TTRMOD_TUNNEL_FACTOR"])
        if os.environ.get("TTRMOD_IRIS_WINDOW_MS"):
            tun["iris_window_ms"] = int(os.environ["TTRMOD_IRIS_WINDOW_MS"])
        # TUNNEL-LOCALTOON-IRIS: the DETERMINISTIC tunnel-ARRIVAL mechanism. Resolve LocalToon by the
        # `tunnelOut` signature, cache its own method-name SET, and in the start wrap-after scale any
        # not-yet-scaled interval whose SPAWNING co_name is in that set AND which started inside the iris
        # window (handleTunnelIn's synchronous irisIn) -- no hardcoded per-session hash. From modset.json
        # `tunnel_localtoon_iris`, with env overrides.
        lt = {
            "enabled":        bool(ltiris_cfg.get("enabled", True)),
            "factor":         float(ltiris_cfg.get("factor", 4.0)),
            "iris_window_ms": int(ltiris_cfg.get("iris_window_ms", 200)),
            "lt_signature":   list(ltiris_cfg.get("lt_signature") or ["tunnelOut"]),
        }
        if os.environ.get("TTRMOD_TUNNEL_LT", "") in ("0", "false", "no"):
            lt["enabled"] = False
        if os.environ.get("TTRMOD_TUNNEL_LT_FACTOR"):
            lt["factor"] = float(os.environ["TTRMOD_TUNNEL_LT_FACTOR"])
        if os.environ.get("TTRMOD_TUNNEL_LT_WINDOW_MS"):
            lt["iris_window_ms"] = int(os.environ["TTRMOD_TUNNEL_LT_WINDOW_MS"])
        if os.environ.get("TTRMOD_TUNNEL_LT_SIG"):
            lt["lt_signature"] = [s.strip() for s in os.environ["TTRMOD_TUNNEL_LT_SIG"].split(",") if s.strip()]
        MOD1["spec"] = {"mode": "modset", "entries": entries, "log": want_log,
                        "spawn": spawn_context, "tunnel": tun, "ltiris": lt}
        # wrap-around CONTEXT targets (resolve owning class by the method signature; wrap wrap-around).
        MOD1["context"] = context
        print("[tramp-live] modset: %d active entries; groups=%s; log_unmatched=%s; table=%s" % (
            len(entries), sorted(set(e["group"] for e in entries)), want_log, tbl_path))
        if tun["enabled"]:
            print("[tramp-live] modset tunnel-identity: localAvatar.tunnelTrack by OBJECT IDENTITY "
                  "x%g; attr=%s; iris_window=%dms" % (
                      tun["factor"], (tun["attr"] or "(auto-discover)"), tun["iris_window_ms"]))
        else:
            print("[tramp-live] modset tunnel-identity: DISABLED (TTRMOD_TUNNEL=0)")
        if lt["enabled"]:
            print("[tramp-live] modset tunnel-localtoon-iris (ARRIVAL): scale LocalToon-method-spawned, "
                  "iris-correlated walk x%g; LocalToon resolved by signature %s; iris_window=%dms" % (
                      lt["factor"], "+".join(lt["lt_signature"]), lt["iris_window_ms"]))
        else:
            print("[tramp-live] modset tunnel-localtoon-iris: DISABLED (TTRMOD_TUNNEL_LT=0)")
        if context:
            print("[tramp-live] modset context: %d wrap-around target(s) -> %s" % (
                len(context), ", ".join("%s(x%g,%s)" % (c["method"], c["factor"], c["group"]) for c in context)))
        if spawn_context:
            print("[tramp-live] modset spawn_context: %d co_name target(s) -> %s" % (
                len(spawn_context), ", ".join("%s(x%g,%s)" % (s["co_name"], s["factor"], s["group"]) for s in spawn_context)))

    pid = str(find_engine_pids()[0])
    if mode == "findcls":
        print("[tramp-live] attaching pid=%s mode=findcls methods=%s" % (pid, "+".join(methods)))
    elif mode == "findmeth":
        print("[tramp-live] attaching pid=%s mode=findmeth groups=%s substr=%s" % (
            pid, " | ".join("+".join(g) for g in method_groups), ",".join(substrs) or "(none)"))
    elif mode in ("mod1", "modset"):
        print("[tramp-live] attaching pid=%s mode=%s resolve-by=%s wrap=%s" % (
            pid, mode,
            ("override %s.%s" % (MOD1["override"]["module"], MOD1["override"]["cls"])) if MOD1["override"] else ("signature " + "+".join(MOD1["methods"])),
            "/".join(MOD1["wrapMethods"] or MOD1["methods"])))
    else:
        print("[tramp-live] attaching pid=%s target=%s.%s.%s" % (pid, T_MODULE, T_CLASS, T_METHOD))
    session = frida.attach(int(pid))
    import threading
    done = threading.Event(); rev = threading.Event(); box = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            pl = m.get("payload") or {}
            if pl.get("t") == "done": box["r"] = pl.get("r"); done.set()
            elif pl.get("t") == "stage": print("[stage]", json.dumps(pl))
            elif pl.get("t") == "fired": print("[FIRED]", json.dumps(pl))
            elif pl.get("t") == "probe": print("[PROBE]", json.dumps(pl))
            elif pl.get("t") == "applied": print("[APPLIED]", json.dumps(pl))
            elif pl.get("t") == "ivalname":
                box.setdefault("names", []).append(pl.get("name"))
                _ctx = pl.get("ctx")
                print("[IVALNAME]", pl.get("name"), ("ctx=%s" % _ctx) if _ctx else "")
            elif pl.get("t") == "spawnco":
                box.setdefault("spawncos", []).append(pl.get("co"))
                print("[SPAWNCO]", pl.get("co"), "(e.g. interval %s)" % pl.get("sample"))
            elif pl.get("t") == "tunnelattr":
                box["tunnel_attr"] = pl.get("attr")
                print("[TUNNELATTR]", pl.get("attr"),
                      ("co=%s" % pl.get("co")) if pl.get("co") else "",
                      ("(e.g. %s)" % pl.get("sample")) if pl.get("sample") else "",
                      "-- localAvatar's hashed tunnel-track attr; pin it in modset.json tunnel_identity.attr")
            elif pl.get("t") == "avatar":
                print("[avatar] localAvatar resolved (%s)" % pl.get("tp"))
            elif pl.get("t") == "ltmethods":
                print("[LTMETHODS] LocalToon resolved by signature %s -> class %s (%d own methods) "
                      "-- the deterministic tunnel-arrival gate" % (
                          "+".join(pl.get("sig") or []), pl.get("cls"), pl.get("count") or 0))
            elif pl.get("t") == "scaled":
                box.setdefault("scaled", []).append(pl.get("name"))
                _ctx = pl.get("ctx"); _co = pl.get("co"); _tun = pl.get("tunnel"); _via = pl.get("via")
                print("[SCALED]", pl.get("name"), "x", pl.get("factor"),
                      ("(%s)" % pl.get("group")) if pl.get("group") else "",
                      ("via=%s" % _via) if _via else "",
                      ("ctx=%s" % _ctx) if _ctx else "",
                      ("co=%s" % _co) if _co else "",
                      ("tunnel=%s" % _tun) if _tun else "")
            elif pl.get("t") == "btinstall":
                info = pl.get("info") or {}
                print("[BTINSTALL] battle class=%s module=%s (sig=%s, all_direct=%s):" % (
                    info.get("cls"), info.get("module"), "+".join(info.get("sig") or []), info.get("all_direct")))
                for w in info.get("wired") or []:
                    role = {"setState": "INBOUND server state", "send": "OUTBOUND done-reports"}.get(w.get("kind"), "")
                    print("            %-16s -> %s%s%s" % (
                        w.get("method"), "OK" if w.get("ok") else "FAIL",
                        (" [%s]" % role) if (w.get("ok") and role) else "",
                        "" if w.get("ok") else " (%s)" % w.get("reason")))
            elif pl.get("t") == "bt":
                # timestamped battle event. Print relative ms (to the first bt event) so gaps read at a
                # glance; keep the full ordered list for the end-of-run BATTLE TIMELINE dump.
                ms = pl.get("ms")
                if "bt_t0" not in box:
                    box["bt_t0"] = ms
                rel = (ms - box["bt_t0"]) if isinstance(ms, (int, float)) else 0
                box.setdefault("bt", []).append({"rel": rel, **pl})
                if pl.get("ev") == "m":
                    label = pl.get("label"); state = pl.get("state")
                    is_in = (pl.get("dir") == "in") or (label == "setState")
                    if is_in:
                        print("[BT] +%7dms  <- setState  state=%s   (INBOUND: server drives the FSM here)" % (rel, state))
                    else:
                        print("[BT] +%7dms  -> sendUpdate('%s')   (OUTBOUND: client reports this step done, then idles for the server)" % (rel, label))
                elif pl.get("ev") == "ival":
                    d = pl.get("dur"); r = pl.get("rate")
                    ds = ("%.3fs" % d) if isinstance(d, (int, float)) else str(d)
                    rs = ("%.2f" % r) if isinstance(r, (int, float)) else str(r)
                    print("[BT] +%7dms  ~~ ival START %-22s dur=%s rate=%s (client rate pre-mod-scale)" % (
                        rel, pl.get("name"), ds, rs))
            elif pl.get("t") == "reverted":
                print("[reverted]", json.dumps(pl))
                rcs = pl.get("rc") or []
                all_ok = pl.get("all_ok")
                if all_ok is None:
                    all_ok = (len(rcs) > 0 and all(x == 0 for x in rcs))
                box["revert_rc"] = rcs
                box["revert_ok"] = bool(pl.get("err") is None and all_ok)   # CONFIRMED only if every wrap restored
                box["reverted"] = True
                rev.set()
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    # stash hook addr into ST via init, then set ST.hook (agent reads it in rpcHook)
    init = ex.init({"image_base": hex(IMAGE_BASE), "hook_va": hook_va, "mode": mode,
                    "syms": {k: {"vmaddr": v["vmaddr"], "prologue16": v["prologue16"]} for k, v in syms.items()},
                    "instancemethod_type": INSTANCEMETHOD_TYPE, "tstate_cell": TSTATE_CELL,
                    "interp_off": INTERP_OFF, "modules_off": MODULES_OFF,
                    "frame_off": FRAME_OFF, "fcode_off": FCODE_OFF, "coname_off": CONAME_OFF,
                    "tmod": T_MODULE, "tcls": T_CLASS, "tmeth": T_METHOD, "methods": methods,
                    "method_groups": method_groups, "substrs": substrs, "list_classes": list_classes,
                    "floatv": {"type": FLOAT_TYPE, "freelist": FLOAT_FREELIST, "numfree": FLOAT_NUMFREE,
                               "malloc_fn": PYMALLOC_FN, "malloc_ctx": PYMALLOC_CTX},
                    "mod1": MOD1})
    print("[tramp-live] init:", json.dumps(init, indent=2))
    if not init.get("ok") or not init.get("verified"):
        print("[tramp-live] init failed/unverified — aborting"); session.detach(); return
    # TTRMOD_DRYRUN=1: prove a per-build table against the LIVE process without installing anything.
    # init() has already computed the ASLR slide and memcmp'd every symbol's prologue bytes at its
    # slid address, which is the part a wrong table gets wrong. Stopping here installs no trampoline,
    # so there is nothing that can dangle and crash the game on detach -- the right first step for a
    # table that has never been run (see STATUS.md "Windows per-build derivation").
    if os.environ.get("TTRMOD_DRYRUN", "") in ("1", "true", "yes"):
        print("[tramp-live] DRY RUN — table verified against the live process; installing nothing.")
        print("[tramp-live] slide=%s  symbols verified=%d" % (init.get("slide"), len(init.get("resolved") or {})))
        for note in (init.get("notes") or []):
            print("[tramp-live]   note: %s" % note)
        session.detach()
        return
    ex.arm()
    if not done.wait(8.0):
        print("[tramp-live] install hook never fired in 8s (game idle/frozen?)"); session.detach(); return
    if box.get("detached"):
        print("[tramp-live] !! DETACHED (%s) -- game crashed during install" % box["detached"]); return
    print("[tramp-live] result:", json.dumps(box.get("r"), indent=2))
    if mode in ("list", "listcls", "selftest", "findcls", "findmeth"):
        session.detach(); return   # read-only/selftest handled everything in-hook (selftest also reverted)
    if not box.get("r", {}).get("ok"):
        session.detach(); return
    # trampoline is live; poll fire count while the user triggers the target in-game.
    import time
    if mode == "modset":
        target_label = "/".join(MOD1["wrapMethods"] or MOD1["methods"])
        trigger_hint = ("trigger cosmetic animations to see [SCALED] / [IVALNAME] "
                        "(teleport via the book, open/close the book, walk a street tunnel, enter a shop)")
    elif mode == "mod1":
        target_label = "/".join(MOD1["methods"])
        trigger_hint = "WALK the toon into (or out of) any street tunnel — no mouse needed"
    else:
        target_label = T_METHOD
        trigger_hint = "trigger '%s' in-game (e.g. walk through a door for a screen wipe)" % T_METHOD
    # modset is the "play" mode: stay resident until stopped so the mods keep working while you
    # play. Test modes keep a bounded poll. TTRMOD_POLL overrides either way (a number = poll that
    # many seconds; 0 = stay resident regardless of mode).
    poll_env = os.environ.get("TTRMOD_POLL")
    if poll_env is not None:
        poll_s = float(poll_env)
    else:
        poll_s = 0.0 if mode == "modset" else 30.0
    persist = poll_s <= 0
    # graceful-stop plumbing: the stop FILE (scripts/tt-mod-stop) is the reliable stop; SIGTERM is
    # handled too; Ctrl+C is only a best-effort belt (the compiled runner dies hard on SIGINT). Clear
    # any STALE stop file first so a leftover doesn't instantly stop this run.
    stopfile = stopfile_path()
    clear_stopfile(stopfile)
    stop = make_stop_state()
    prev_sigterm = install_sigterm(stop)
    if persist:
        print("[tramp-live] %s" % trigger_hint)
        print("[tramp-live] MODS LIVE — leave this running while you play. To STOP cleanly, run "
              "`scripts/tt-mod-stop` (or `kill -TERM %d`). Do NOT rely on Ctrl+C — the runner can die "
              "before the revert runs, which would crash the game." % os.getpid())
        print("[tramp-live] (stop file: %s)" % stopfile)
    else:
        print("[tramp-live] %s. Polling %gs (or stop early with scripts/tt-mod-stop)..." % (trigger_hint, poll_s))
    try:
        reason = wait_for_stop(box, stop, stopfile, persist, poll_s, fires_fn=ex.fires)
    except KeyboardInterrupt:
        request_stop(stop, "Ctrl+C")
        reason = "Ctrl+C"
        print("\n[tramp-live] Ctrl+C — stopping (unreliable on this runner; prefer scripts/tt-mod-stop). "
              "Reverting and detaching cleanly...")
    if reason in ("stop-file", "SIGTERM"):
        print("[tramp-live] stop requested via %s — reverting mods and detaching cleanly..." % reason)
    elif reason == "detached":
        print("[tramp-live] session detached (game gone?) — skipping revert")
    try:
        ab = ex.appliedBy()
        if ab: print("[tramp-live] appliedBy (method -> #intervals scaled):", json.dumps(ab))
    except Exception:
        pass
    # BATTLE TIMELINE (read-only diagnosis): the ordered, timestamped battle events with the gap since the
    # previous event. Read the gaps like this: an OUTBOUND sendUpdate('...Done') followed by a large gap
    # then an INBOUND setState => that step is SERVER-GATED (the client finished + reported early, then
    # waited on the server) and is NOT client-reducible; a step that advances with NO intervening inbound
    # setState after its done-report => client-driven and scalable. Hand this block back for attribution.
    bt = box.get("bt") or []
    if bt:
        print("[tramp-live] ===== BATTLE TIMELINE (%d events; relMs = ms since first event) =====" % len(bt))
        prev = None
        for e in bt:
            rel = e.get("rel", 0)
            gap = "" if prev is None else "  (+%dms since prev)" % (rel - prev)
            prev = rel
            if e.get("ev") == "m":
                if (e.get("dir") == "in") or (e.get("label") == "setState"):
                    desc = "<- INBOUND  setState state=%s" % e.get("state")
                else:
                    desc = "-> OUTBOUND sendUpdate('%s') (client done -> idles for server)" % e.get("label")
            else:
                d = e.get("dur"); r = e.get("rate")
                ds = ("%.3fs" % d) if isinstance(d, (int, float)) else str(d)
                rs = ("%.2f" % r) if isinstance(r, (int, float)) else str(r)
                desc = "~~ ival    START %s dur=%s rate=%s" % (e.get("name"), ds, rs)
            print("    +%7dms  %s%s" % (rel, desc, gap))
        print("[tramp-live] ===== end BATTLE TIMELINE =====")
    if mode == "modset":
        try:
            si = ex.scaledInfo() or {}
            print("[tramp-live] modset scaled by GROUP:", json.dumps(si.get("groups", {})))
            print("[tramp-live] modset scaled by NAME :", json.dumps(si.get("names", {})))
            if box.get("tunnel_attr"):
                print("[tramp-live] tunnel walk = localAvatar.%s (discovered by object identity) -- "
                      "pin it in modset.json tunnel_identity.attr to skip discovery next run" % box["tunnel_attr"])
            if box.get("names"):
                print("[tramp-live] UNMATCHED interval names seen (%d):" % len(box["names"]))
                for nm in box["names"]:
                    print("    -", nm)
            if box.get("spawncos"):
                print("[tramp-live] DISTINCT spawning co_names of unmatched intervals (%d) -- "
                      "paste a tunnel one into modset.json spawn_context:" % len(box["spawncos"]))
                for co in box["spawncos"]:
                    print("    co_name:", co)
        except Exception:
            pass
    try:
        final_fires = ex.fires()
    except Exception:
        final_fires = -1
    alive = engine_alive()
    print("[tramp-live] final fires=%d  game_alive=%s" % (final_fires, alive))
    # MUST revert before detaching: the trampolines' native code dies with the session, so any wrap
    # still installed would crash on the next call. revert_and_detach restores EVERY installed wrap
    # (MetaInterval.start + every context wrap-around) and detaches ONLY once that is confirmed; if it
    # can't confirm it STAYS ATTACHED (game alive) rather than dropping with wraps live.
    revert_and_detach(ex, session, box, rev, target_label)
    # consume the stop file (we've reverted+detached, or given up because the game is gone) and
    # restore the previous SIGTERM handler, so a fresh run starts clean.
    clear_stopfile(stopfile)
    try:
        if prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)
    except Exception:
        pass


if __name__ == "__main__":
    main()
