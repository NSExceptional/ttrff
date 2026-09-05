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
#   factor 5.0. The vault namespaces game modules (e.g. vlt24ab6c6d.<hash>.LocalToon), so we resolve
#   the module by exact candidates first, then by scanning sys.modules keys for a '.LocalToon' suffix.
MOD1 = {
    "modules": ["LocalToon", "toontown.toon.LocalToon"],
    "suffix":  ".LocalToon",
    "cls":     "LocalToon",
    "methods": ["handleTunnelIn", "handleTunnelOut"],
    "spec":    {"mode": "attr", "attr": "tunnelTrack"},
    "factor":  5.0,
}

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
        done:false, keep:[]
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
      // read-only module-listing helpers (present in capi-symbols2)
      if (F['PyObject_GetIter']) ST.GetIter = new NativeFunction(F['PyObject_GetIter'], 'pointer', ['pointer']);
      if (F['PyIter_Next'])      ST.IterNext = new NativeFunction(F['PyIter_Next'], 'pointer', ['pointer']);
      if (F['PyUnicode_AsUTF8']) ST.AsUTF8   = new NativeFunction(F['PyUnicode_AsUTF8'], 'pointer', ['pointer']);
      if (F['PyObject_GetItem']) ST.GetItem  = new NativeFunction(F['PyObject_GetItem'], 'pointer', ['pointer','pointer']);
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
          }
        } catch(e){ ST.clearExc(); }
        return 0;
      };
      // wrap-after NativeCallback (METH_VARARGS|KEYWORDS=0x3): call the ORIGINAL once, then (only if
      // it did not raise) discover the just-started interval and setPlayRate it; return the original
      // result. args = (inst, *call_args); inst = ob_item[0] @ tuple+0x18 (ob_size @ +0x10).
      ST.makeWrapAfter = function(orig, spec, factorVal){
        var cb = new NativeCallback(function (self, args, kwargs) {
          try { ST.fires = (ST.fires||0) + 1; if (ST.fires<=3) send({t:'fired', n:ST.fires}); } catch(e){}
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // original, exactly once
          if (result.isNull()){ return result; }              // original raised -> propagate untouched
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            if (!inst.isNull()) ST.applyAfter(inst, spec, factorVal);
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
          // MILESTONE-2 first live target: wrap-after on the street-tunnel walk (LocalToon).
          if (ST.mode === 'mod1') {
            try {
              var m = ST.mod1;
              var mods0 = ST.sysmodules();
              if (mods0.isNull()){ ST.fin({ok:false, stage:'no sys.modules'}); return; }
              // resolve the LocalToon module: exact candidate names first...
              var modObj = ptr(0), modName0 = null, ci;
              for (ci = 0; ci < m.modules.length; ci++){
                var mm0 = ST.DictGetStr(mods0, Memory.allocUtf8String(m.modules[ci]));
                if (!mm0.isNull()){ modObj = mm0; modName0 = m.modules[ci]; break; }
              }
              // ...else scan sys.modules for a key that IS or ENDS WITH '.LocalToon' (vault-hashed).
              if (modObj.isNull() && ST.GetIter && ST.IterNext && ST.AsUTF8){
                var it0 = ST.GetIter(mods0), k0;
                while (!(k0 = ST.IterNext(it0)).isNull()){
                  var s0 = null; try { s0 = ST.AsUTF8(k0).readCString(); } catch(e){ s0 = null; }
                  if (s0 && (s0 === m.cls || (s0.length >= m.suffix.length && s0.slice(-m.suffix.length) === m.suffix))){
                    var cand = ST.DictGetStr(mods0, Memory.allocUtf8String(s0));
                    if (!cand.isNull()){ modObj = cand; modName0 = s0; break; }
                  }
                }
                ST.clearExc();
              }
              if (modObj.isNull()){ ST.fin({ok:false, stage:'LocalToon module not loaded (walk in-world first)'}); return; }
              var cls0 = ST.GetAttrStr(modObj, Memory.allocUtf8String(m.cls));
              if (cls0.isNull()){ ST.fin({ok:false, stage:'no class '+m.cls+' in '+modName0}); return; }
              ST.keep.push(cls0);
              ST.installed = [];
              var wired = [], anyOk = false, mi;
              for (mi = 0; mi < m.methods.length; mi++){
                var meth0 = m.methods[mi];
                var mn0 = Memory.allocUtf8String(meth0);
                var orig0 = ST.GetAttrStr(cls0, mn0);
                if (orig0.isNull()){ ST.clearExc(); wired.push({method:meth0, ok:false, reason:'method absent'}); continue; }
                ST.keep.push(orig0); ST.keep.push(mn0);
                var im0 = ST.makeWrapAfter(orig0, m.spec, m.factor);
                if (im0.isNull()){ wired.push({method:meth0, ok:false, reason:'wrap build NULL'}); continue; }
                var rc0 = ST.SetAttrStr(cls0, mn0, im0);
                ST.installed.push({cls:cls0, mn:mn0, orig:orig0});
                if (rc0 === 0) anyOk = true;
                wired.push({method:meth0, ok:(rc0===0), setattr_rc:rc0});
              }
              ST.fin({ok:anyOk, stage:'mod1_installed', module:modName0,
                      target: m.cls+'.'+m.methods.join('/'), attr: m.spec.attr, factor: m.factor,
                      wired: wired,
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

    pid = subprocess.check_output(["pgrep", "-f", "TTREngine"]).split()[0].decode()
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
            elif pl.get("t") == "reverted": print("[reverted]", json.dumps(pl)); box["reverted"] = True; rev.set()
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    # stash hook addr into ST via init, then set ST.hook (agent reads it in rpcHook)
    mode = os.environ.get("TTRMOD_MODE", "install")
    init = ex.init({"image_base": hex(IMAGE_BASE), "hook_va": hook_va, "mode": mode,
                    "syms": {k: {"vmaddr": v["vmaddr"], "prologue16": v["prologue16"]} for k, v in syms.items()},
                    "instancemethod_type": INSTANCEMETHOD_TYPE, "tstate_cell": TSTATE_CELL,
                    "interp_off": INTERP_OFF, "modules_off": MODULES_OFF,
                    "tmod": T_MODULE, "tcls": T_CLASS, "tmeth": T_METHOD,
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
    if mode in ("list", "listcls", "selftest"):
        session.detach(); return   # listing/selftest handled everything in-hook (selftest also reverted)
    if not box.get("r", {}).get("ok"):
        session.detach(); return
    # trampoline is live; poll fire count while the user triggers the target in-game.
    import time
    if mode == "mod1":
        target_label = "%s.%s" % (MOD1["cls"], "/".join(MOD1["methods"]))
        trigger_hint = "WALK the toon into (or out of) any street tunnel — no mouse needed"
    else:
        target_label = T_METHOD
        trigger_hint = "trigger '%s' in-game (e.g. walk through a door for a screen wipe)" % T_METHOD
    print("[tramp-live] %s. Polling 30s..." % trigger_hint)
    t = time.time(); last = 0
    while time.time() - t < 30 and not box.get("detached"):
        time.sleep(2.0)
        try: f = ex.fires()
        except Exception: break
        if f != last: print("[tramp-live] fires=%d" % f); last = f
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
