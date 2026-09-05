#!/usr/bin/env python3
# localtest/wraparound_test.py -- OFFLINE validation of the WRAP-AROUND CONTEXT mechanism (the
# context-scaling upgrade to the modset general-interval hook in frida/trampoline_inject.py). It
# scales intervals by CREATION CONTEXT instead of by name, for fire-and-forget / AUTO-NAMED intervals
# that no `match` substring can safely target -- specifically the street-tunnel WALK, whose interval
# is not stored on the toon and is auto-named with a hashed class prefix (vlt8e0d5a85-<n>).
#
# The mechanism (mirrored here against a mock, exactly as modset_test.py mirrors the modset branch):
#   * makeCtxWrap(orig, group, factor): wrap a CONTEXT method (e.g. LocalToon.tunnelOut) wrap-AROUND
#     -- SET ST.ctx = {group, factor} BEFORE calling the original, RESTORE the previous value AFTER
#     in a finally (so ctx clears even if the original raises; nesting saves+restores prev).
#   * the MetaInterval.start wrap-after (applyModset): if ST.ctx is set when an interval STARTS,
#     scale THAT interval by ctx.factor and log its (finally-revealed) real name with a ctx= tag,
#     BEFORE the normal name-table path. Intervals started with no ctx go through the name table,
#     unchanged.
#
# Proves (against stock arm64 CPython 3.8, real native trampolines, mock classes):
#   A. discovery -- LocalToon's owning class is resolved by the readable `tunnelOut` SIGNATURE (the
#      hashed class name is never used), exactly one class matches;
#   (a) an interval started DURING a wrapped context method is scaled by the CONTEXT factor (4.0) and
#       its name is logged with ctx=tunnel -- even though its (hashed) name matches NO table entry;
#   (b) an interval started OUTSIDE any context is NOT ctx-scaled: it goes through the name table
#       (matching name -> table factor 5.0; non-matching -> untouched at 1.0 + logged);
#   (c) the context flag is cleared even when the wrapped method RAISES -- ST.ctx back to null, the
#       original's exception propagates (result NULL) and is the only thing on the tstate, and a free
#       interval started afterward is NOT ctx-scaled (no leaked context);
#   (d) nesting/reentrancy is safe -- an outer ctx method (tunnel 4.0) that calls an inner ctx method
#       (inner 9.0) restores the OUTER ctx on the inner's return: intervals before/after the inner
#       call scale 4.0, the inner's interval scales 9.0, and ctx is null once the outer returns;
#   E. tstate clean after every case; original always called once; result passed through.
#
#   run:  sudo -n env PYTHONPATH=/Users/tanner/Library/Python/3.13/lib/python/site-packages \
#              /opt/homebrew/bin/python3.13 localtest/wraparound_test.py
#     (root required: frida.attach to another process needs it on macOS. The DRIVER runs under a
#      frida-enabled interpreter -- 3.13 here; the injected TARGET is arm64 CPython 3.8.)

import sys, os, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")

SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyImport_GetModuleDict":    "_PyImport_GetModuleDict",
    "PyImport_AddModule":        "_PyImport_AddModule",
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyObject_SetAttrString":    "_PyObject_SetAttrString",
    "PyObject_Call":             "_PyObject_Call",
    "PyDict_GetItem":            "_PyDict_GetItem",
    "PyDict_GetItemString":      "_PyDict_GetItemString",
    "PyObject_GetIter":          "_PyObject_GetIter",
    "PyIter_Next":               "_PyIter_Next",
    "PyUnicode_AsUTF8":          "_PyUnicode_AsUTF8",
    "PyCFunction_NewEx":         "_PyCFunction_NewEx",
    "PyTuple_New":               "_PyTuple_New",
    "PyTuple_Pack":              "_PyTuple_Pack",
    "PyObject_Malloc":           "_PyObject_Malloc",
    "PyFloat_AsDouble":          "_PyFloat_AsDouble",
    "PyLong_AsLong":             "_PyLong_AsLong",
    "PyErr_Occurred":            "_PyErr_Occurred",
    "PyErr_Clear":               "_PyErr_Clear",
    "PyInstanceMethod_Type":     "_PyInstanceMethod_Type",
    "PyFloat_Type":              "_PyFloat_Type",
}

# Name table for the NON-context path. Deliberately contains NO entry that matches the hashed tunnel
# name 'vlt8e0d5a85-<n>' -- so if context scaling ever failed, the tunnel interval would fall through
# to "unmatched/logged", never scaled. teleport is 5.0 (distinct from the tunnel context's 4.0).
TABLE = [
    {"match": "teleportOut", "factor": 5.0, "group": "teleport", "prefix": False},
]


def framework_dylib(target_py):
    code = ("import sysconfig, os\n"
            "v = sysconfig.get_config_var\n"
            "print(os.path.join(v('PYTHONFRAMEWORKPREFIX'), v('PYTHONFRAMEWORK')+'.framework',\n"
            "                   'Versions', v('VERSION'), v('PYTHONFRAMEWORK')))\n")
    p = subprocess.run([target_py, "-c", code], capture_output=True, text=True)
    path = p.stdout.strip()
    if not path or not os.path.exists(path):
        raise SystemExit("no framework dylib for %s: %r\n%s" % (target_py, path, p.stderr))
    return os.path.realpath(path)


def resolve_offsets(dylib):
    out = subprocess.run(["xcrun", "dyld_info", "-exports", dylib], capture_output=True, text=True).stdout
    want = {v: k for k, v in SYMS.items()}
    offs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("0x") and parts[1] in want:
            offs[want[parts[1]]] = int(parts[0], 16)
    missing = [k for k in SYMS if k not in offs]
    if missing:
        raise SystemExit("missing exports: %s" % missing)
    return offs


# Mock Panda MetaInterval: same discriminating signature as production (start+setPlayRate+append+
# clearIntervals). getName() returns its name; start() returns a sentinel (pass-through check) and
# RESETS play_rate to the playRate arg (hence wrap-AFTER -> setPlayRate overrides it); setPlayRate
# records.  Mock LocalToon: its tunnelOut is the CONTEXT method. It constructs a fire-and-forget
# interval that is AUTO-NAMED with the real hashed prefix (vlt8e0d5a85-<n>) and NOT stored on the toon
# -- exactly why name-matching fails live. (The interval is stashed on the instance under `probe_iv`
# only so the TEST can inspect its play_rate; the ctx mechanism never reads it -- it scales whatever
# interval is passed to the wrapped start() while ctx is set.)
TARGET_PROG = r"""
import sys, types, time

def _make_metaival():
    class MetaIntervalMock:
        def __init__(self, name, sentinel=0):
            self._name = name; self._sentinel = sentinel
            self.play_rate = 1.0; self.spr_count = 0; self.started = 0
        def getName(self): return self._name
        def start(self, startT=0.0, endT=-1.0, playRate=1.0):
            self.started += 1; self.play_rate = playRate; return self._sentinel
        def setPlayRate(self, r): self.spr_count += 1; self.play_rate = float(r)
        # Python-only discriminators (absent on the C++ CInterval/CMetaInterval base):
        def append(self, ival): pass
        def clearIntervals(self, *a, **k): pass
        def extend(self, ivals): pass
    return MetaIntervalMock

_mmod = types.ModuleType("vlt1609aac2.vltinterval.vltMetaInterval")
_mmod.MetaInterval = _make_metaival()
sys.modules["vlt1609aac2.vltinterval.vltMetaInterval"] = _mmod
MI = _mmod.MetaInterval

def _make_localtoon(MI):
    class LocalToonMock:
        _ctr = 0
        def _mkname(self):                       # auto-named hashed prefix, like the real walk seq
            LocalToonMock._ctr += 1
            return "vlt8e0d5a85-%d" % LocalToonMock._ctr
        def tunnelOut(self, *a, **k):            # CONTEXT method: fire-and-forget interval, not on self
            iv = MI(self._mkname(), 811)
            self.probe_iv = iv                   # TEST-ONLY handle; ctx mechanism never reads it
            iv.start()
            return 811
        def tunnelOutRaises(self, *a, **k):      # starts an interval, THEN raises (ctx must still clear)
            iv = MI(self._mkname(), 812)
            self.probe_iv_raise = iv
            iv.start()
            raise RuntimeError("boom after starting the walk")
        def innerCtx(self, *a, **k):             # nested ctx method (its own group/factor)
            iv = MI(self._mkname(), 814)
            self._inner_iv = iv
            iv.start()
            return 814
        def outerNest(self, *a, **k):            # outer ctx; brackets a nested ctx call
            iv1 = MI(self._mkname(), 815); self._iv1 = iv1; iv1.start()   # scaled by OUTER
            self.innerCtx()                                              # inner scales its own by 9.0
            iv2 = MI(self._mkname(), 816); self._iv2 = iv2; iv2.start()   # OUTER again -> proves restore
            return 815
        # extra readable methods so tunnelOut is a realistic co-signature (isLocal etc. per STATUS):
        def isLocal(self): return True
        def getZoneId(self): return 2000
    return LocalToonMock

_lmod = types.ModuleType("vlt24ab6c6d.vlt7892fa9a.vlt725d40df")
_lmod.LocalToon = _make_localtoon(MI)
sys.modules["vlt24ab6c6d.vlt7892fa9a.vlt725d40df"] = _lmod
localtoon = _lmod.LocalToon()

# free intervals started OUTSIDE any context (scenario b + c's leak check):
free_matched   = MI("teleportOut-77", 821)      # name-table hit -> 5.0
free_unmatched = MI("someGameplaySeq-9", 822)    # no table hit, no ctx -> untouched + logged
after_raise    = MI("someGameplaySeq-after", 823)  # started after a raise -> must NOT be ctx-scaled

# decoy: start/setPlayRate but NOT the append/clearIntervals discriminators -> not the MetaInterval;
# and it has NO tunnelOut -> not the LocalToon either.
def _make_plain():
    class PlainThing:
        def start(self, *a, **k): return 1
        def setPlayRate(self, r): pass
    return PlainThing
_pmod = types.ModuleType("decoymod4")
_pmod.PlainThing = _make_plain()
sys.modules["decoymod4"] = _pmod

t = time.time()
while time.time() - t < 30:
    s = sum(i*i for i in range(300))
"""


AGENT = r"""
'use strict';
var ST = null;
function cstr(s){ return Memory.allocUtf8String(s); }
rpc.exports = {
  init: function (p) {
    var out = { ok:false, notes:[], resolved:{} };
    try {
      var mods = Process.enumerateModules(), m = null;
      for (var i=0;i<mods.length;i++){ if (mods[i].path === p.module_path){ m = mods[i]; break; } }
      if (!m){ for (var j=0;j<mods.length;j++){ if (/Python\.framework|\/Python$|libpython/i.test(mods[j].path)){ m=mods[j]; break; } } }
      if (!m){ out.notes.push('python module not found'); return out; }
      var base = m.base; out.base = base.toString();
      function at(n){ var a = base.add(ptr(p.offsets[n])); out.resolved[n]=a.toString(); return a; }
      ST = {
        base: base, done:false, keep:[], entries: p.table, logOn: true, log: [],
        scaledGroups: {}, scaledNames: [], ctxLog: [],
        ctx: null,                                        // <-- the wrap-around context flag
        frame_eval:  at('_PyEval_EvalFrameDefault'),
        GetModuleDict: new NativeFunction(at('PyImport_GetModuleDict'), 'pointer', []),
        AddModule:   new NativeFunction(at('PyImport_AddModule'),    'pointer', ['pointer']),
        GetAttrStr:  new NativeFunction(at('PyObject_GetAttrString'), 'pointer', ['pointer','pointer']),
        SetAttrStr:  new NativeFunction(at('PyObject_SetAttrString'), 'int',     ['pointer','pointer','pointer']),
        Call:        new NativeFunction(at('PyObject_Call'),          'pointer', ['pointer','pointer','pointer']),
        DictGetItem: new NativeFunction(at('PyDict_GetItem'),         'pointer', ['pointer','pointer']),
        DictGetStr:  new NativeFunction(at('PyDict_GetItemString'),   'pointer', ['pointer','pointer']),
        GetIter:     new NativeFunction(at('PyObject_GetIter'),       'pointer', ['pointer']),
        IterNext:    new NativeFunction(at('PyIter_Next'),            'pointer', ['pointer']),
        AsUTF8:      new NativeFunction(at('PyUnicode_AsUTF8'),       'pointer', ['pointer']),
        CFuncNewEx:  new NativeFunction(at('PyCFunction_NewEx'),      'pointer', ['pointer','pointer','pointer']),
        TupleNew:    new NativeFunction(at('PyTuple_New'),            'pointer', ['long']),
        TuplePack:   new NativeFunction(at('PyTuple_Pack'),           'pointer', ['long','...','pointer']),
        Malloc:      new NativeFunction(at('PyObject_Malloc'),        'pointer', ['ulong']),
        AsDouble:    new NativeFunction(at('PyFloat_AsDouble'),       'double',  ['pointer']),
        AsLong:      new NativeFunction(at('PyLong_AsLong'),          'long',    ['pointer']),
        Occurred:    new NativeFunction(at('PyErr_Occurred'),         'pointer', []),
        Clear:       new NativeFunction(at('PyErr_Clear'),            'void',    []),
        imType:      at('PyInstanceMethod_Type'),
        FloatType:   at('PyFloat_Type'),
      };
      ST.tpname = function(o){ try { return o.add(8).readPointer().add(0x18).readPointer().readCString(); } catch(e){ return '?'; } };
      ST.clearExc = function(){ try { if (!ST.Occurred().isNull()) ST.Clear(); } catch(e){} };
      ST.pack1 = function(o){ return ST.TuplePack(1, o); };
      ST.makeFloat = function(v){
        var op = ST.Malloc(0x18); if (op.isNull()) return ptr(0);
        op.writeU64(1); op.add(8).writePointer(ST.FloatType); op.add(0x10).writeDouble(v);
        return op;
      };
      ST.setPlayRate = function(iv, factorVal){
        var meth = ST.GetAttrStr(iv, cstr('setPlayRate'));
        if (meth.isNull()){ ST.clearExc(); return false; }
        var f = ST.makeFloat(factorVal); if (f.isNull()) return false;
        var r = ST.Call(meth, ST.pack1(f), ptr(0));
        if (r.isNull()){ ST.clearExc(); return false; }
        return true;
      };
      // MODSET applyAfter -- MIRRORS the spec.mode==='modset' branch in frida/trampoline_inject.py,
      // INCLUDING the new CONTEXT-scaling priority: inst IS the interval; read getName(); if ST.ctx
      // is set, scale by ctx.factor + log the name with a ctx= tag (BEFORE the name table); else the
      // FIRST matching table entry wins (unmatched -> logged, never scaled). Every miss clears tstate.
      ST.applyModset = function(inst){
        try {
          var gm2 = ST.GetAttrStr(inst, cstr('getName'));
          if (gm2.isNull()){ ST.clearExc(); return 0; }
          var nm4 = ST.Call(gm2, ST.TupleNew(0), ptr(0));
          if (nm4.isNull()){ ST.clearExc(); return 0; }
          var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
          if (nms4 === null){ ST.clearExc(); return 0; }
          if (ST.ctx){
            if (ST.ctxLog.indexOf(nms4) < 0) ST.ctxLog.push(nms4);
            var okc = ST.setPlayRate(inst, ST.ctx.factor);
            if (okc){ ST.scaledGroups[ST.ctx.group] = (ST.scaledGroups[ST.ctx.group]||0) + 1; ST.scaledNames.push(nms4); }
            ST.clearExc(); return okc ? 1 : 0;
          }
          var entries = ST.entries || [], matched = null;
          for (var mi=0; mi<entries.length; mi++){
            var en = entries[mi]; if (!en || !en.match) continue;
            var isHit = en.prefix ? (nms4.lastIndexOf(en.match, 0) === 0) : (nms4.indexOf(en.match) >= 0);
            if (isHit){ matched = en; break; }
          }
          if (matched){
            var okm = ST.setPlayRate(inst, matched.factor);
            if (okm){ ST.scaledGroups[matched.group] = (ST.scaledGroups[matched.group]||0) + 1; ST.scaledNames.push(nms4); }
            ST.clearExc(); return okm ? 1 : 0;
          }
          if (ST.logOn && ST.log.indexOf(nms4) < 0) ST.log.push(nms4);
          ST.clearExc(); return 0;
        } catch(e){ ST.clearExc(); return 0; }
      };
      // wrap-AFTER on MetaInterval.start (unchanged mechanism): call orig once, then applyModset.
      ST.makeWrapAfter = function(orig){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);
          if (result.isNull()){ return result; }
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            if (!inst.isNull()) ST.applyModset(inst);
          } catch(e){ ST.clearExc(); }
          ST.clearExc();
          return result;
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = cstr('ttrmod_wrapafter'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };
      // wrap-AROUND context wrapper -- MIRRORS ST.makeCtxWrap in frida/trampoline_inject.py: set
      // ST.ctx BEFORE the original, restore prev AFTER in a finally (clears even on raise; nesting
      // saves+restores). Result passed through (NULL => orig raised => propagate, exc left intact).
      ST.makeCtxWrap = function(orig, group, factorVal){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var prev = ST.ctx;
          ST.ctx = { group: group, factor: factorVal };
          var result;
          try {
            result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);
          } finally {
            ST.ctx = prev;
          }
          return result;
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = cstr('ttrmod_ctxwrap'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };

      // shared signature scan (verbatim shape from trampoline_inject.py) -- resolve a class by the
      // methods it defines (used here to resolve LocalToon by the readable `tunnelOut` signature).
      ST.classSignature = function(cls, methods, methCStrs){
        try {
          var className = '?'; try { className = cls.add(0x18).readPointer().readCString(); } catch(e){ className = '?'; }
          var mro = [];
          try {
            var mroTup = cls.add(0x158).readPointer();
            if (!mroTup.isNull()){ var n = mroTup.add(0x10).readS64().toNumber();
              if (n > 0 && n < 512){ for (var i=0;i<n;i++){ mro.push(mroTup.add(0x18 + 8*i).readPointer()); } } }
          } catch(e){ mro = []; }
          if (mro.length === 0) mro = [cls];
          var rec = { class_name: className, clsPtr: cls, match_count: 0, full: false, all_direct: true };
          for (var mi=0; mi<methods.length; mi++){
            var where = 'absent';
            for (var bi=0; bi<mro.length; bi++){
              var B = mro[bi]; if (B.isNull()) continue;
              var bdict = ptr(0); try { bdict = B.add(0x108).readPointer(); } catch(e){ bdict = ptr(0); }
              if (bdict.isNull()) continue;
              var hit = ST.DictGetStr(bdict, methCStrs[mi]);
              if (!hit.isNull()){ where = (bi===0)?'direct':'inherited'; break; }
            }
            if (where === 'direct'){ rec.match_count++; } else if (where === 'inherited'){ rec.match_count++; rec.all_direct = false; } else { rec.all_direct = false; }
          }
          rec.full = (rec.match_count === methods.length);
          return rec;
        } catch(e){ return null; }
      };
      ST.scanBySignature = function(md, methods){
        var byCls = {}, order = [];
        try {
          if (md.isNull()){ ST.clearExc(); return []; }
          var methCStrs = []; for (var mi=0; mi<methods.length; mi++){ methCStrs.push(cstr(methods[mi])); }
          var dictStr = cstr('__dict__');
          var mit = ST.GetIter(md); if (mit.isNull()){ ST.clearExc(); return []; }
          var mk;
          while (!(mk = ST.IterNext(mit)).isNull()){
            var modObj = ST.DictGetItem(md, mk); if (modObj.isNull()){ ST.clearExc(); continue; }
            var mdict = ST.GetAttrStr(modObj, dictStr); if (mdict.isNull()){ ST.clearExc(); continue; }
            var dit = ST.GetIter(mdict); if (dit.isNull()){ ST.clearExc(); continue; }
            var ak;
            while (!(ak = ST.IterNext(dit)).isNull()){
              var val = ST.DictGetItem(mdict, ak); if (val.isNull()){ ST.clearExc(); continue; }
              var isType = false; try { isType = (val.add(8).readPointer().add(0xab).readU8() & 0x80) !== 0; } catch(e){ isType = false; }
              if (!isType) continue;
              var clsKey = val.toString(); var rec = byCls[clsKey];
              if (rec === undefined){ rec = ST.classSignature(val, methods, methCStrs); byCls[clsKey] = rec; if (rec) order.push(clsKey); }
            }
          }
        } catch(e){}
        ST.clearExc();
        var outl = []; for (var i=0;i<order.length;i++){ var r = byCls[order[i]]; if (r && r.full) outl.push(r); }
        return outl;
      };
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },

  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function () {
          if (ST.done) return; ST.done = true;
          function L(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsLong(o); ST.clearExc(); return v.toNumber ? v.toNumber() : v; }
          function D(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsDouble(o); ST.clearExc(); return v; }
          try {
            var R = {};
            var md = ST.GetModuleDict();
            if (md.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }
            var main = ST.AddModule(cstr('__main__'));

            // A: resolve the MetaInterval mock (start+setPlayRate+append+clearIntervals) and the
            //    LocalToon mock (by the readable `tunnelOut` signature) -- by SIGNATURE, never name.
            var miFound = ST.scanBySignature(md, ['start','setPlayRate','append','clearIntervals']);
            var miNames = {}; for (var i=0;i<miFound.length;i++){ miNames[miFound[i].class_name] = miFound[i]; }
            var ltFound = ST.scanBySignature(md, ['tunnelOut']);
            var ltNames = []; for (var j=0;j<ltFound.length;j++){ ltNames.push(ltFound[j].class_name); }
            R.mi_found = Object.keys(miNames).sort();
            R.lt_found = ltNames.sort();
            R.discovery_pass = (R.mi_found.length === 1 && R.mi_found[0] === 'MetaIntervalMock' &&
                                R.lt_found.length === 1 && R.lt_found[0] === 'LocalToonMock');

            var miRec = miNames['MetaIntervalMock']; var ltRec = ltFound.length ? ltFound[0] : null;
            if (!miRec || !ltRec){ send({t:'done', r:{ok:false, stage:'discovery failed', mi:R.mi_found, lt:R.lt_found}}); return; }

            // wrap MetaInterval.start (wrap-after) once; all interval instances share it.
            var miCls = miRec.clsPtr; ST.keep.push(miCls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(miCls, mnStart); ST.keep.push(origStart);
            ST.SetAttrStr(miCls, mnStart, ST.makeWrapAfter(origStart));

            // wrap the LocalToon context methods wrap-AROUND (each with its own group/factor).
            var ltCls = ltRec.clsPtr; ST.keep.push(ltCls);
            function wrapCtx(meth, group, factor){
              var mn = cstr(meth); ST.keep.push(mn);
              var orig = ST.GetAttrStr(ltCls, mn); if (orig.isNull()){ ST.clearExc(); return null; }
              if (ST.tpname(orig) !== 'function'){ ST.clearExc(); return null; }
              ST.keep.push(orig);
              var im = ST.makeCtxWrap(orig, group, factor);
              ST.SetAttrStr(ltCls, mn, im);
              return orig;
            }
            var oTunnelOut  = wrapCtx('tunnelOut',       'tunnel', 4.0);
            var oTunnelRais = wrapCtx('tunnelOutRaises', 'tunnel', 4.0);
            var oInner      = wrapCtx('innerCtx',        'inner',  9.0);
            var oOuter      = wrapCtx('outerNest',       'tunnel', 4.0);
            R.ctx_wraps_installed = !!(oTunnelOut && oTunnelRais && oInner && oOuter);

            var localtoon = ST.GetAttrStr(main, cstr('localtoon')); ST.keep.push(localtoon);
            function callMeth(inst, meth){
              var b = ST.GetAttrStr(inst, cstr(meth));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              return res;    // caller inspects / clears
            }
            function ivalOf(instName){ return ST.GetAttrStr(localtoon, cstr(instName)); }
            function ivInfo(iv){
              return { spr_calls: L(ST.GetAttrStr(iv, cstr('spr_count'))),
                       started:   L(ST.GetAttrStr(iv, cstr('started'))),
                       play_rate: D(ST.GetAttrStr(iv, cstr('play_rate'))) };
            }

            // ---------- (b) OUTSIDE any context: name-table path only (drive first, ctx is null) ----------
            var fm = ST.GetAttrStr(main, cstr('free_matched'));
            var fu = ST.GetAttrStr(main, cstr('free_unmatched'));
            var rfm = callMeth(fm, 'start'); var rfm_l = rfm.isNull()?null:L(rfm);
            var rfu = callMeth(fu, 'start'); var rfu_l = rfu.isNull()?null:L(rfu);
            ST.clearExc();
            R.free = {
              ctx_was_null: (ST.ctx === null),
              matched:   Object.assign(ivInfo(fm),   {passed_through:(rfm_l===821)}),   // teleportOut -> table 5.0
              unmatched: Object.assign(ivInfo(fu),   {passed_through:(rfu_l===822)}),   // no hit -> untouched + logged
              tstate_clean: ST.Occurred().isNull(),
            };
            ST.clearExc();

            // ---------- (a) DURING context: tunnelOut -> the started interval is ctx-scaled + logged --------
            var rTO = callMeth(localtoon, 'tunnelOut'); var rTO_l = rTO.isNull()?null:L(rTO);
            var walkIv = ivalOf('probe_iv');
            R.tunnel = Object.assign(ivInfo(walkIv), {
              passed_through: (rTO_l === 811),
              ctx_cleared_after: (ST.ctx === null),
              tstate_clean: ST.Occurred().isNull(),
            });
            R.tunnel_name = walkIv.isNull()? null : (ST.AsUTF8(ST.GetAttrStr(walkIv, cstr('_name'))).readCString());
            ST.clearExc();

            // ---------- (c) context method RAISES: ctx still cleared, no leak, exc is the mock's -------------
            var rRaise = callMeth(localtoon, 'tunnelOutRaises');
            R.raise = {
              orig_returned_null: rRaise.isNull(),                 // orig raised -> propagated
              exc_set_after: !ST.Occurred().isNull(),              // the mock RuntimeError is on the tstate
              ctx_cleared_after_raise: (ST.ctx === null),          // <-- the key proof: cleared despite raise
            };
            var raiseIv = ivalOf('probe_iv_raise');
            R.raise.interval_scaled_before_raise = raiseIv.isNull()? null : (D(ST.GetAttrStr(raiseIv, cstr('play_rate'))) === 4.0);
            ST.clearExc();                                          // clear the mock's exception now
            // leak check: a free interval started AFTER the raise must NOT be ctx-scaled
            var ar = ST.GetAttrStr(main, cstr('after_raise'));
            callMeth(ar, 'start'); ST.clearExc();
            R.raise.after_raise_not_ctx_scaled = (D(ST.GetAttrStr(ar, cstr('play_rate'))) === 1.0 &&
                                                  L(ST.GetAttrStr(ar, cstr('spr_count'))) === 0);
            ST.clearExc();

            // ---------- (d) NESTING/reentrancy: outer(4.0) -> inner(9.0) -> outer(4.0), then ctx null --------
            var rNest = callMeth(localtoon, 'outerNest'); var rNest_l = rNest.isNull()?null:L(rNest);
            var iv1 = ivalOf('_iv1'), ivInner = ivalOf('_inner_iv'), iv2 = ivalOf('_iv2');
            R.nest = {
              passed_through: (rNest_l === 815),
              before_inner_rate: iv1.isNull()?     null : D(ST.GetAttrStr(iv1,     cstr('play_rate'))),  // 4.0 (outer)
              inner_rate:        ivInner.isNull()? null : D(ST.GetAttrStr(ivInner, cstr('play_rate'))),  // 9.0 (inner)
              after_inner_rate:  iv2.isNull()?     null : D(ST.GetAttrStr(iv2,     cstr('play_rate'))),  // 4.0 (outer restored)
              ctx_cleared_after: (ST.ctx === null),
              tstate_clean: ST.Occurred().isNull(),
            };
            ST.clearExc();

            R.scaled_groups = ST.scaledGroups;
            R.scaled_names  = ST.scaledNames.slice().sort();
            R.ctx_logged    = ST.ctxLog.slice().sort();
            R.logged_names  = ST.log.slice().sort();

            // revert every wrap
            ST.SetAttrStr(miCls, mnStart, origStart);
            if (oTunnelOut)  ST.SetAttrStr(ltCls, cstr('tunnelOut'),       oTunnelOut);
            if (oTunnelRais) ST.SetAttrStr(ltCls, cstr('tunnelOutRaises'), oTunnelRais);
            if (oInner)      ST.SetAttrStr(ltCls, cstr('innerCtx'),        oInner);
            if (oOuter)      ST.SetAttrStr(ltCls, cstr('outerNest'),       oOuter);
            ST.clearExc();

            R.ok = !!(
              R.discovery_pass && R.ctx_wraps_installed &&
              // (a) context scaling reached the fire-and-forget, hashed-named walk interval:
              R.tunnel.passed_through && R.tunnel.started === 1 && R.tunnel.spr_calls === 1 &&
              R.tunnel.play_rate === 4.0 && R.tunnel.ctx_cleared_after && R.tunnel.tstate_clean &&
              R.tunnel_name && R.tunnel_name.indexOf('vlt8e0d5a85-') === 0 &&
              R.ctx_logged.length >= 1 && R.ctx_logged.indexOf(R.tunnel_name) >= 0 &&
              R.logged_names.indexOf(R.tunnel_name) < 0 &&        // NOT in the plain unmatched log
              // (b) outside context -> name table only:
              R.free.ctx_was_null &&
              R.free.matched.passed_through && R.free.matched.spr_calls === 1 && R.free.matched.play_rate === 5.0 &&
              R.free.unmatched.passed_through && R.free.unmatched.spr_calls === 0 && R.free.unmatched.play_rate === 1.0 &&
              R.free.tstate_clean && R.logged_names.indexOf('someGameplaySeq-9') >= 0 &&
              // (c) raise -> ctx cleared, no leak:
              R.raise.orig_returned_null && R.raise.exc_set_after && R.raise.ctx_cleared_after_raise &&
              R.raise.interval_scaled_before_raise === true && R.raise.after_raise_not_ctx_scaled &&
              // (d) nesting -> save/restore:
              R.nest.passed_through && R.nest.before_inner_rate === 4.0 && R.nest.inner_rate === 9.0 &&
              R.nest.after_inner_rate === 4.0 && R.nest.ctx_cleared_after && R.nest.tstate_clean &&
              // group tally: tunnel = tunnelOut(1) + tunnelOutRaises(1, scaled before it raised) +
              // outerNest(iv1 + iv2 = 2) = 4 ; inner = innerCtx(1) ; teleport = free_matched(1) :
              R.scaled_groups.tunnel === 4 && R.scaled_groups.inner === 1 && R.scaled_groups.teleport === 1
            );
            if (!ST.Occurred().isNull()) ST.Clear();
            try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
            send({t:'done', r:R});
          } catch(e){ try{ST.Clear();}catch(_){} send({t:'done', r:{ok:false, stage:'arm ex', e:String(e)}}); }
        }
      });
      return { ok:true };
    } catch(e){ return { ok:false, notes:['arm ex: '+e] }; }
  }
};
"""


def main():
    import frida
    dylib = framework_dylib(TARGET_PY)
    offsets = resolve_offsets(dylib)
    tgt = subprocess.Popen([TARGET_PY, "-c", TARGET_PROG]); time.sleep(0.4)
    print("[wraparound] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

    done = threading.Event(); box = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            pl = m.get("payload") or {}
            if pl.get("t") == "done": box["r"] = pl.get("r"); done.set()
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()

    try:
        session = frida.attach(tgt.pid)
    except Exception as e:
        tgt.kill(); raise SystemExit("attach failed (arm64 target + root required): %s" % e)
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib, "table": TABLE})
    if not init.get("ok"):
        print("[wraparound] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[wraparound] hook never fired in 20s")
    elif box.get("detached"):
        print("[wraparound] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[wraparound] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[wraparound] target_alive=%s" % alive)
    print("[wraparound] VERDICT: %s" % (
        "PASS -- context-scaling reaches the fire-and-forget, hashed-named tunnel-walk interval "
        "(scaled by CREATION CONTEXT, name logged with ctx=tunnel); intervals outside a context go "
        "through the name table unchanged; ctx clears even when the wrapped method raises (no leak); "
        "nesting saves/restores the outer context; tstate clean throughout"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
