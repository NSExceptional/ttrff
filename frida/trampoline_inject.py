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
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMAGE_BASE = 0x100000000

# milestone-1 target (env-overridable): a class that is always loaded and easy to trigger.
T_MODULE = os.environ.get("TTRMOD_TMOD", "direct.showbase.Transitions")
T_CLASS  = os.environ.get("TTRMOD_TCLS", "Transitions")
T_METHOD = os.environ.get("TTRMOD_TMETH", "fadeOut")

# Constants confirmed by the RE pass (capi-symbols.json _meta).
INSTANCEMETHOD_TYPE = 0x101a79c20
TSTATE_CELL         = 0x101c0acd8   # *cell = current PyThreadState
INTERP_OFF          = 0x10          # tstate -> interp
MODULES_OFF         = 0x38          # interp -> modules dict (== sys.modules)

# milestone-2 manual PyFloat builder (STATUS.md recipe; PyFloat_FromDouble is inlined away).
# Absolute vmaddrs -> slid at runtime. Layout validated offline in localtest/pyfloat_test.py
# (stock 3.8 has the IDENTICAL 24-byte layout: ob_type @ +8, ob_fval @ +0x10; only addrs differ).
FLOAT_TYPE      = 0x101aae5c8       # &PyFloat_Type
FLOAT_FREELIST  = 0x101be9588       # float free-list head
FLOAT_NUMFREE   = 0x101be9590       # int32 numfree (8 after the head, MAXFREELIST 100)
PYMALLOC_FN     = 0x101a7a668       # _PyObject allocator .malloc (fn ptr)
PYMALLOC_CTX    = 0x101a7a660       # _PyObject allocator .ctx

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
    for fn in ("capi-symbols.json", "capi-symbols2.json"):
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
    context entry (e.g. tunnelIn, whose real method name is hashed and still to be discovered)."""
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
    return entries, bool(data.get("log_unmatched", True)), context


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
        tmod: p.tmod, tcls: p.tcls, tmeth: p.tmeth,
        done:false, keep:[],
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

      // ---- milestone-2: manual PyFloat builder + generic wrap-after (payload.py port) ----
      if (p.floatv){
        ST.FloatType     = rt(p.floatv.type);
        ST.floatFreelist = rt(p.floatv.freelist);
        ST.floatNumfree  = rt(p.floatv.numfree);
        ST.mallocFnPtr   = rt(p.floatv.malloc_fn);
        ST.mallocCtxPtr  = rt(p.floatv.malloc_ctx);
        ST.Malloc = null; ST.mallocCtx = null;
      }
      ST.mod1 = p.mod1 || null;
      ST.probeAttrs = !!(ST.mod1 && ST.mod1.probe_attrs);   // mod1 first-fire __dict__ diagnostic
      // build a float by hand (STATUS.md recipe): pop the free-list head (relink via +8, numfree--),
      // else pymalloc(24); then ob_refcnt=1 @+0, ob_type=&PyFloat_Type @+8, ob_fval @+0x10.
      ST.makeFloat = function(v){
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
            // unmatched: log it once (deduped, capped) so the operator can see what's available.
            if (spec.log){
              ST.seenNames = ST.seenNames || {}; ST.nameCount = ST.nameCount || 0;
              if (ST.seenNames[nms4] === undefined && ST.nameCount < 400){ ST.seenNames[nms4] = 1; ST.nameCount++; try { send({t:'ivalname', name:nms4}); } catch(e){} }
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
                  ST.installed.push({cls:cls0, mn:mn0, orig:orig0});
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
                  ST.installed.push({cls:ccls, mn:cmn, orig:corig});
                  if (crc === 0) anyOk = true;
                  ctxWired.push({method:ce.method, group:ce.group, factor:cFactor,
                                 cls:cchosen[cj].class_name, all_direct:cchosen[cj].all_direct,
                                 ok:(crc===0), setattr_rc:crc});
                }
              }
              ST.fin({ok:anyOk, stage:'mod1_installed',
                      resolved_by: (m.override && m.override.module ? 'override' : 'signature-scan'),
                      targets: targets.map(function(t){ return {module:t.module, attr:t.attr, class_name:t.class_name, all_direct:t.all_direct}; }),
                      methods: m.methods, attr: m.spec.attr, factor: m.factor,
                      wired: wired, ctx_wired: ctxWired,
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
      // items = the mod1 multi-method list, else the single legacy install triple.
      var items = (ST && ST.installed && ST.installed.length) ? ST.installed
                : ((ST && ST.cls !== undefined) ? [{cls:ST.cls, mn:ST.methNameStr, orig:ST.orig}] : null);
      if (!items){ return { ok:false, e:'nothing installed' }; }
      ST.rlistener = Interceptor.attach(ST.hook, {
        onEnter: function () {
          if (ST.reverted) return; ST.reverted = true;
          try {
            var rcs = [];
            for (var i=0;i<items.length;i++){ rcs.push(ST.SetAttrStr(items[i].cls, items[i].mn, items[i].orig)); }
            ST.clearExc();
            try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
            send({t:'reverted', rc:rcs});
          } catch(e){ send({t:'reverted', err:String(e)}); }
        }
      });
      return { ok:true };
    } catch(e){ return { ok:false, e:String(e) }; }
  }
};
// hook address injected by init via a global (kept simple)
function rpcHook(){ return ST.hook; }
"""


def main():
    syms = load_symbols()
    missing, tuple_fn = readiness(syms)
    print("[tramp-live] symbols loaded: %d ; tuple builder: %s" % (len(syms), tuple_fn))
    if missing:
        print("[tramp-live] NOT READY — missing for milestone-1 pass-through: %s" % ", ".join(missing))
        print("[tramp-live] (these come from capi-symbols2.json — the running symbol hunt)")
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

    mode = os.environ.get("TTRMOD_MODE", "install")

    # MODSET (production): ONE install of the MetaInterval.start hook driven by the curated
    # name->factor table (modset.json). Reuses the mod1 code path (discover the interval class,
    # wrap `start`, wrap-after) but with the per-entry `modset` spec instead of a single factor.
    # Defaults: pin the proven-live Python MetaInterval class by NAME (override) and wrap only
    # `start`. Setting TTRMOD_TMOD+TTRMOD_TCLS re-pins a different class (e.g. after an auto-patch);
    # clearing both would fall back to the signature scan (META_INTERVAL_SIG).
    if mode == "modset":
        tbl_path = os.environ.get("TTRMOD_MODSET", os.path.join(ROOT, "modset.json"))
        entries, log_unmatched, context = load_modset(tbl_path)
        if not (ovr_mod and ovr_cls):
            MOD1["override"] = {"module": META_INTERVAL_MODULE, "cls": META_INTERVAL_CLASS}
        MOD1["methods"] = list(META_INTERVAL_SIG)   # signature fallback if the override is cleared
        if not MOD1["wrapMethods"]:
            MOD1["wrapMethods"] = ["start"]
        want_log = log_unmatched
        env_log = os.environ.get("TTRMOD_LOGNAMES", "")
        if env_log != "":
            want_log = env_log in ("1", "true", "yes")
        MOD1["spec"] = {"mode": "modset", "entries": entries, "log": want_log}
        # wrap-around CONTEXT targets (resolve owning class by the method signature; wrap wrap-around).
        MOD1["context"] = context
        print("[tramp-live] modset: %d active entries; groups=%s; log_unmatched=%s; table=%s" % (
            len(entries), sorted(set(e["group"] for e in entries)), want_log, tbl_path))
        if context:
            print("[tramp-live] modset context: %d wrap-around target(s) -> %s" % (
                len(context), ", ".join("%s(x%g,%s)" % (c["method"], c["factor"], c["group"]) for c in context)))

    pid = subprocess.check_output(["pgrep", "-f", "TTREngine"]).split()[0].decode()
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
            elif pl.get("t") == "scaled":
                box.setdefault("scaled", []).append(pl.get("name"))
                _ctx = pl.get("ctx")
                print("[SCALED]", pl.get("name"), "x", pl.get("factor"),
                      ("(%s)" % pl.get("group")) if pl.get("group") else "",
                      ("ctx=%s" % _ctx) if _ctx else "")
            elif pl.get("t") == "reverted": print("[reverted]", json.dumps(pl)); box["reverted"] = True; rev.set()
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
                    "tmod": T_MODULE, "tcls": T_CLASS, "tmeth": T_METHOD, "methods": methods,
                    "method_groups": method_groups, "substrs": substrs, "list_classes": list_classes,
                    "floatv": {"type": FLOAT_TYPE, "freelist": FLOAT_FREELIST, "numfree": FLOAT_NUMFREE,
                               "malloc_fn": PYMALLOC_FN, "malloc_ctx": PYMALLOC_CTX},
                    "mod1": MOD1})
    print("[tramp-live] init:", json.dumps(init, indent=2))
    if not init.get("ok") or not init.get("verified"):
        print("[tramp-live] init failed/unverified — aborting"); session.detach(); return
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
    # modset is the "play" mode: stay resident until Ctrl+C so the mods keep working
    # while you play. Test modes keep a bounded poll. TTRMOD_POLL overrides either way
    # (a number = poll that many seconds; 0 = stay resident regardless of mode).
    poll_env = os.environ.get("TTRMOD_POLL")
    if poll_env is not None:
        poll_s = float(poll_env)
    else:
        poll_s = 0.0 if mode == "modset" else 30.0
    persist = poll_s <= 0
    if persist:
        print("[tramp-live] %s" % trigger_hint)
        print("[tramp-live] MODS LIVE — leave this running while you play. Press Ctrl+C to stop and cleanly revert.")
    else:
        print("[tramp-live] %s. Polling %gs..." % (trigger_hint, poll_s))
    t = time.time(); last = 0; last_beat = t
    try:
        while not box.get("detached"):
            time.sleep(2.0)
            try: f = ex.fires()
            except Exception: break
            now = time.time()
            if persist:
                if now - last_beat >= 30.0:
                    print("[tramp-live] alive — fires=%d (Ctrl+C to stop + revert)" % f); last_beat = now
            else:
                if f != last: print("[tramp-live] fires=%d" % f)
                if now - t >= poll_s: break
            last = f
    except KeyboardInterrupt:
        print("\n[tramp-live] Ctrl+C — stopping: reverting mods and detaching cleanly...")
    try:
        ab = ex.appliedBy()
        if ab: print("[tramp-live] appliedBy (method -> #intervals scaled):", json.dumps(ab))
    except Exception:
        pass
    if mode == "modset":
        try:
            si = ex.scaledInfo() or {}
            print("[tramp-live] modset scaled by GROUP:", json.dumps(si.get("groups", {})))
            print("[tramp-live] modset scaled by NAME :", json.dumps(si.get("names", {})))
            if box.get("names"):
                print("[tramp-live] UNMATCHED interval names seen (%d):" % len(box["names"]))
                for nm in box["names"]:
                    print("    -", nm)
        except Exception:
            pass
    alive = subprocess.call(["pgrep", "-qf", "TTREngine"]) == 0
    print("[tramp-live] final fires=%d  game_alive=%s" % (last, alive))
    # MUST revert before detaching: the trampoline's native code dies with the session, so a
    # method still pointing at it would crash on the next call. The game is live (frame-eval
    # fires constantly), so the revert hook fires within ms.
    if alive and not box.get("detached"):
        print("[tramp-live] reverting (restoring original %s) before detach..." % target_label)
        ex.revert()
        if rev.wait(8.0):
            print("[tramp-live] reverted OK — original restored; safe to detach")
        else:
            print("[tramp-live] !! revert hook never fired — NOT detaching (a dangling trampoline "
                  "would crash on next %s). Session left attached; investigate." % target_label)
            return
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
