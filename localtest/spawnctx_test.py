#!/usr/bin/env python3
# localtest/spawnctx_test.py -- OFFLINE validation of SPAWN-CONTEXT scaling (approach 2), the
# co_name-of-the-spawning-frame upgrade to the modset general-interval hook in
# frida/trampoline_inject.py. It scales an interval by the co_name of the Python frame that CALLED
# start() -- i.e. the (usually hashed) name of the method that SPAWNED it -- for a fire-and-forget /
# AUTO-NAMED interval whose own name matches nothing and whose synchronous creator is a HASHED
# method that can't be wrapped by readable name.
#
# This is the real street-tunnel WALK shape (proven by the reference open-toontown
# toontown/toon/LocalToon.py): tunnelOut/tunnelIn only b_set... to the server; the animation runs
# LATER in the HASHED handlers handleTunnelOut/handleTunnelIn, which build an UNNAMED
# `self.tunnelTrack = Sequence(...)` (auto-named 'vlt8e0d5a85-<n>' on TTR) and immediately .start()
# it. Because start()'s wrapper is a native C trampoline (it pushes NO Python frame), tstate->frame
# at scale-time IS that handler frame, so reading tstate->frame->f_code->co_name yields the spawning
# method's name. (Approach 2 needs NO class resolution for the handler -- only the already-present
# MetaInterval.start wrap plus the frame read.)
#
# CPython 3.8 struct offsets under test (ABI-fixed; identical between TTR 3.8.17 and stock 3.8.14;
# also cross-checked via ctypes on 3.8): PyThreadState.frame +0x18 -> PyFrameObject.f_code +0x20 ->
# PyCodeObject.co_name +0x70. The one faithful deviation from the shipping path: the shipping code
# reads the current tstate from a hardcoded TTR cell address; here we get it via PyThreadState_Get()
# (a plain C call -- pushes no Python frame, so tstate->frame is unchanged). The STRUCT WALK being
# tested is byte-for-byte the shipping one.
#
# Proves (against stock arm64 CPython 3.8, real native trampolines, mock classes):
#   A. discovery -- the MetaInterval mock is resolved by signature (start+setPlayRate+append+
#      clearIntervals), exactly one class; the hashed-named LocalToon handlers need NO resolution;
#   (a) an interval started INSIDE the hashed handler vlt_handleTunnelOut (co_name in spawn_context)
#       is scaled by the spawn factor (4.0) -- even though its own auto-named 'vlt8e0d5a85-<n>' name
#       matches NO table entry -- and the co_name READ BACK is exactly "vlt_handleTunnelOut";
#   (b) the ARRIVAL handler vlt_handleTunnelIn likewise scales its interval (4.0), co_name read back
#       exactly "vlt_handleTunnelIn" -- both tunnel directions covered;
#   (c) SELECTIVITY: an interval started by a DIFFERENT method vlt_someOtherAnim (co_name NOT in
#       spawn_context) with the SAME auto-named shape is NOT scaled (play_rate stays 1.0), and its
#       co_name is surfaced in the [SPAWNCO] discovery log -- proving unrelated spawners are spared
#       and the discovery path reveals hashed co_names;
#   (d) COEXISTENCE: an interval started directly (no named spawner frame) whose NAME hits the table
#       is still scaled by NAME (teleportOut -> 5.0), not by spawn; a direct interval that hits
#       nothing is untouched (1.0) and logged;
#   E. tstate clean after every case; original always called once; result passed through.
#
#   run:  sudo -n env PYTHONPATH=/Users/tanner/Library/Python/3.13/lib/python/site-packages \
#              /opt/homebrew/bin/python3.13 localtest/spawnctx_test.py
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
    "PyThreadState_Get":         "_PyThreadState_Get",
    "PyInstanceMethod_Type":     "_PyInstanceMethod_Type",
    "PyFloat_Type":              "_PyFloat_Type",
}

# CPython 3.8 struct offsets (the thing under test). ABI-fixed for 3.8.x/64-bit.
FRAME_OFF  = 0x18   # PyThreadState.frame
FCODE_OFF  = 0x20   # PyFrameObject.f_code
CONAME_OFF = 0x70   # PyCodeObject.co_name

# Name table for the NON-spawn path. Deliberately contains NO entry that matches the hashed tunnel
# name 'vlt8e0d5a85-<n>' -- so if spawn scaling ever failed, the walk interval would fall through to
# "unmatched/logged", never scaled. teleport is 5.0 (distinct from the tunnel spawn factor 4.0).
TABLE = [
    {"match": "teleportOut", "factor": 5.0, "group": "teleport", "prefix": False},
]

# Spawn-context set: the HASHED (here: known-mock) co_names of the tunnel animators. Exact match.
SPAWN = [
    {"co_name": "vlt_handleTunnelOut", "factor": 4.0, "group": "tunnel"},
    {"co_name": "vlt_handleTunnelIn",  "factor": 4.0, "group": "tunnel"},
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


# Mock Panda MetaInterval: discriminating signature (start+setPlayRate+append+clearIntervals).
# getName() returns its name; start() returns a sentinel (pass-through check) and RESETS play_rate to
# the playRate arg (hence wrap-AFTER -> setPlayRate overrides it); setPlayRate records.
# Mock LocalToon: HASHED-named animator methods (mirror TTR, where handleTunnelOut/In are hashed).
# Each builds a fire-and-forget interval AUTO-NAMED with the real hashed prefix ('vlt8e0d5a85-<n>')
# and NOT reachable by any name -- exactly why name-matching fails live -- then .start()s it. (The
# per-call test handles _probe_* exist only so the TEST can inspect each interval; the spawn
# mechanism never reads them -- it reads the CALLING FRAME's co_name.)
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
        # HASHED animators: build UNNAMED self.tunnelTrack and start it synchronously (co_name path).
        def vlt_handleTunnelOut(self, *a, **k):  # DEPARTURE -- co_name IS in spawn_context
            self.tunnelTrack = MI(self._mkname(), 901)
            self._probe_out = self.tunnelTrack
            self.tunnelTrack.start()
            return 901
        def vlt_handleTunnelIn(self, *a, **k):   # ARRIVAL -- co_name IS in spawn_context
            self.tunnelTrack = MI(self._mkname(), 902)
            self._probe_in = self.tunnelTrack
            self.tunnelTrack.start()
            return 902
        def vlt_someOtherAnim(self, *a, **k):    # DIFFERENT method -- co_name NOT in spawn_context
            self.otherTrack = MI(self._mkname(), 903)
            self._probe_other = self.otherTrack
            self.otherTrack.start()
            return 903
    return LocalToonMock

_lmod = types.ModuleType("vlt24ab6c6d.vlt7892fa9a.vlt725d40df")
_lmod.LocalToon = _make_localtoon(MI)
sys.modules["vlt24ab6c6d.vlt7892fa9a.vlt725d40df"] = _lmod
localtoon = _lmod.LocalToon()

# free intervals started DIRECTLY (no named spawner frame) -> the NAME path, not spawn:
free_matched   = MI("teleportOut-77", 921)       # name table hit -> 5.0
free_unmatched = MI("someGameplaySeq-9", 922)     # no name hit, no named spawner -> untouched + logged

# decoy: start/setPlayRate but NOT the append/clearIntervals discriminators -> not the MetaInterval.
def _make_plain():
    class PlainThing:
        def start(self, *a, **k): return 1
        def setPlayRate(self, r): pass
    return PlainThing
_pmod = types.ModuleType("decoymod5")
_pmod.PlainThing = _make_plain()
sys.modules["decoymod5"] = _pmod

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
        base: base, done:false, keep:[], entries: p.table, spawn: p.spawn, logOn: true,
        log: [], spawnLog: [], scaledGroups: {}, scaledNames: [], spawnScaled: [], coByName: {},
        ctx: null,
        frame_off: p.frame_off, fcode_off: p.fcode_off, coname_off: p.coname_off,
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
        ThreadStateGet: new NativeFunction(at('PyThreadState_Get'),   'pointer', []),
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
      // co_name of the CURRENT Python frame -- MIRRORS ST.spawnCoName in frida/trampoline_inject.py.
      // Only the tstate acquisition differs (PyThreadState_Get() here vs the hardcoded TTR cell); the
      // struct walk (frame +0x18 -> f_code +0x20 -> co_name +0x70) is byte-for-byte identical.
      ST.spawnCoName = function(){
        try {
          if (!ST.AsUTF8) return null;
          var t = ST.ThreadStateGet(); if (t.isNull()) return null;
          var fr = t.add(ST.frame_off).readPointer(); if (fr.isNull()) return null;
          var code = fr.add(ST.fcode_off).readPointer(); if (code.isNull()) return null;
          var nameObj = code.add(ST.coname_off).readPointer(); if (nameObj.isNull()) return null;
          var s = null; try { s = ST.AsUTF8(nameObj).readCString(); } catch(e){ s = null; }
          if (s === null) ST.clearExc();
          return s;
        } catch(e){ ST.clearExc(); return null; }
      };
      // MODSET applyAfter -- MIRRORS the spec.mode==='modset' branch in frida/trampoline_inject.py,
      // INCLUDING the new SPAWN-CONTEXT priority: inst IS the interval; read getName(); (ctx null in
      // this test); then read the spawning frame's co_name and, if it EXACTLY matches a spawn entry,
      // scale by that factor; else the FIRST matching NAME entry wins; else log the name AND the
      // (deduped-by-co_name) spawning co_name. Every miss clears the tstate.
      ST.applyModset = function(inst){
        try {
          var gm2 = ST.GetAttrStr(inst, cstr('getName'));
          if (gm2.isNull()){ ST.clearExc(); return 0; }
          var nm4 = ST.Call(gm2, ST.TupleNew(0), ptr(0));
          if (nm4.isNull()){ ST.clearExc(); return 0; }
          var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
          if (nms4 === null){ ST.clearExc(); return 0; }
          if (ST.ctx){ /* covered by wraparound_test; null here */ }
          var spawnList = ST.spawn || [];
          var coName = (spawnList.length || ST.logOn) ? ST.spawnCoName() : null;
          if (coName !== null) ST.coByName[nms4] = coName;    // record co_name observed (read-correctness)
          if (spawnList.length && coName !== null){
            var smatch = null;
            for (var sp=0; sp<spawnList.length; sp++){ if (spawnList[sp] && spawnList[sp].co_name === coName){ smatch = spawnList[sp]; break; } }
            if (smatch){
              var oks = ST.setPlayRate(inst, smatch.factor);
              if (oks){ ST.scaledGroups[smatch.group] = (ST.scaledGroups[smatch.group]||0) + 1; ST.scaledNames.push(nms4);
                        ST.spawnScaled.push({name:nms4, co:coName, factor:smatch.factor}); }
              ST.clearExc(); return oks ? 1 : 0;
            }
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
          if (ST.logOn){
            if (ST.log.indexOf(nms4) < 0) ST.log.push(nms4);
            if (coName !== null && ST.spawnLog.indexOf(coName) < 0) ST.spawnLog.push(coName);
          }
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

      // shared signature scan (verbatim shape from trampoline_inject.py) -- resolve MetaInterval.
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

            // A: resolve the MetaInterval mock by signature (start+setPlayRate+append+clearIntervals).
            var miFound = ST.scanBySignature(md, ['start','setPlayRate','append','clearIntervals']);
            var miNames = {}; for (var i=0;i<miFound.length;i++){ miNames[miFound[i].class_name] = miFound[i]; }
            R.mi_found = Object.keys(miNames).sort();
            R.discovery_pass = (R.mi_found.length === 1 && R.mi_found[0] === 'MetaIntervalMock');
            var miRec = miNames['MetaIntervalMock'];
            if (!miRec){ send({t:'done', r:{ok:false, stage:'MetaIntervalMock not discovered', found:R.mi_found}}); return; }

            // wrap MetaInterval.start (wrap-after) once; all interval instances share it.
            var miCls = miRec.clsPtr; ST.keep.push(miCls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(miCls, mnStart); ST.keep.push(origStart);
            ST.SetAttrStr(miCls, mnStart, ST.makeWrapAfter(origStart));

            var localtoon = ST.GetAttrStr(main, cstr('localtoon')); ST.keep.push(localtoon);
            function callMeth(inst, meth){
              var b = ST.GetAttrStr(inst, cstr(meth));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              return res;
            }
            function ivInfo(iv){
              return { spr_calls: L(ST.GetAttrStr(iv, cstr('spr_count'))),
                       started:   L(ST.GetAttrStr(iv, cstr('started'))),
                       play_rate: D(ST.GetAttrStr(iv, cstr('play_rate'))),
                       name:      iv.isNull()? null : ST.AsUTF8(ST.GetAttrStr(iv, cstr('_name'))).readCString() };
            }

            // (a) DEPARTURE: vlt_handleTunnelOut -> its interval scaled by SPAWN co_name (4.0)
            var rOut = callMeth(localtoon, 'vlt_handleTunnelOut'); var rOut_l = rOut.isNull()?null:L(rOut);
            var ivOut = ST.GetAttrStr(localtoon, cstr('_probe_out'));
            R.out = Object.assign(ivInfo(ivOut), { passed_through:(rOut_l===901), tstate_clean:ST.Occurred().isNull() });
            R.out.co = R.out.name ? (ST.coByName[R.out.name] || null) : null;
            ST.clearExc();

            // (b) ARRIVAL: vlt_handleTunnelIn -> its interval scaled by SPAWN co_name (4.0)
            var rIn = callMeth(localtoon, 'vlt_handleTunnelIn'); var rIn_l = rIn.isNull()?null:L(rIn);
            var ivIn = ST.GetAttrStr(localtoon, cstr('_probe_in'));
            R.in_ = Object.assign(ivInfo(ivIn), { passed_through:(rIn_l===902), tstate_clean:ST.Occurred().isNull() });
            R.in_.co = R.in_.name ? (ST.coByName[R.in_.name] || null) : null;
            ST.clearExc();

            // (c) SELECTIVITY: vlt_someOtherAnim (co_name NOT in spawn set) -> NOT scaled + logged
            var rOth = callMeth(localtoon, 'vlt_someOtherAnim'); var rOth_l = rOth.isNull()?null:L(rOth);
            var ivOth = ST.GetAttrStr(localtoon, cstr('_probe_other'));
            R.other = Object.assign(ivInfo(ivOth), { passed_through:(rOth_l===903), tstate_clean:ST.Occurred().isNull() });
            R.other.co = R.other.name ? (ST.coByName[R.other.name] || null) : null;
            ST.clearExc();

            // (d) COEXISTENCE: direct starts -> NAME path (teleportOut 5.0) / unmatched untouched+logged
            var fm = ST.GetAttrStr(main, cstr('free_matched'));
            var fu = ST.GetAttrStr(main, cstr('free_unmatched'));
            var rfm = callMeth(fm, 'start'); var rfm_l = rfm.isNull()?null:L(rfm);
            var rfu = callMeth(fu, 'start'); var rfu_l = rfu.isNull()?null:L(rfu);
            ST.clearExc();
            R.free = {
              matched:   Object.assign(ivInfo(fm), { passed_through:(rfm_l===921) }),
              unmatched: Object.assign(ivInfo(fu), { passed_through:(rfu_l===922) }),
              tstate_clean: ST.Occurred().isNull(),
            };
            ST.clearExc();

            R.scaled_groups = ST.scaledGroups;
            R.scaled_names  = ST.scaledNames.slice().sort();
            R.spawn_scaled  = ST.spawnScaled.slice();
            R.spawn_logged  = ST.spawnLog.slice().sort();
            R.logged_names  = ST.log.slice().sort();

            ST.SetAttrStr(miCls, mnStart, origStart);   // revert
            ST.clearExc();

            var spawnCos = R.spawn_scaled.map(function(x){ return x.co; }).sort();
            var spawnFactorsOk = R.spawn_scaled.every(function(x){ return x.factor === 4.0; });

            R.ok = !!(
              R.discovery_pass &&
              // (a) departure scaled by spawn co_name, co_name read back correctly:
              R.out.passed_through && R.out.started === 1 && R.out.spr_calls === 1 && R.out.play_rate === 4.0 &&
              R.out.tstate_clean && R.out.co === 'vlt_handleTunnelOut' &&
              R.out.name && R.out.name.indexOf('vlt8e0d5a85-') === 0 &&
              // (b) arrival scaled by spawn co_name, co_name read back correctly:
              R.in_.passed_through && R.in_.started === 1 && R.in_.spr_calls === 1 && R.in_.play_rate === 4.0 &&
              R.in_.tstate_clean && R.in_.co === 'vlt_handleTunnelIn' &&
              R.in_.name && R.in_.name.indexOf('vlt8e0d5a85-') === 0 &&
              // (c) unrelated spawner NOT scaled, co_name surfaced for discovery:
              R.other.passed_through && R.other.started === 1 && R.other.spr_calls === 0 && R.other.play_rate === 1.0 &&
              R.other.tstate_clean && R.other.co === 'vlt_someOtherAnim' &&
              R.spawn_logged.indexOf('vlt_someOtherAnim') >= 0 &&
              // (d) name path still works alongside spawn; direct unmatched untouched+logged:
              R.free.matched.passed_through && R.free.matched.spr_calls === 1 && R.free.matched.play_rate === 5.0 &&
              R.free.unmatched.passed_through && R.free.unmatched.spr_calls === 0 && R.free.unmatched.play_rate === 1.0 &&
              R.free.tstate_clean && R.logged_names.indexOf('someGameplaySeq-9') >= 0 &&
              // exactly the two tunnel handlers spawn-scaled, both 4.0; group tally: tunnel 2 + teleport 1:
              R.spawn_scaled.length === 2 && spawnFactorsOk &&
              spawnCos.length === 2 && spawnCos[0] === 'vlt_handleTunnelIn' && spawnCos[1] === 'vlt_handleTunnelOut' &&
              R.scaled_groups.tunnel === 2 && R.scaled_groups.teleport === 1
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
    print("[spawnctx] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib,
                    "table": TABLE, "spawn": SPAWN,
                    "frame_off": hex(FRAME_OFF), "fcode_off": hex(FCODE_OFF), "coname_off": hex(CONAME_OFF)})
    if not init.get("ok"):
        print("[spawnctx] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[spawnctx] hook never fired in 20s")
    elif box.get("detached"):
        print("[spawnctx] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[spawnctx] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[spawnctx] target_alive=%s" % alive)
    print("[spawnctx] VERDICT: %s" % (
        "PASS -- spawn-context scaling reaches the fire-and-forget, auto-named tunnel-walk interval "
        "via the co_name of the (hashed) spawning handler (both directions), reads the co_name back "
        "correctly, SPARES an interval spawned by a different method (surfacing its co_name for "
        "discovery), coexists with the name table, and is tstate-clean throughout"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
