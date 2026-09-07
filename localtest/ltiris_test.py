#!/usr/bin/env python3
# localtest/ltiris_test.py -- OFFLINE validation of the DETERMINISTIC tunnel-ARRIVAL mechanism
# (tunnel_localtoon_iris) added to frida/trampoline_inject.py's modset branch. This is the fix for the
# street-tunnel ARRIVAL walk, which no hardcoded co_name could catch: the arrival handler is the HASHED
# handleTunnelIn, and the post-iris co_names differ every session (the playground is full of OTHER
# players' animations -- MMO noise). The DETERMINISTIC signal used instead:
#
#   LocalToon resolves reliably by the `tunnelOut` method SIGNATURE (unique -> class vlt725d40df) even
#   though its module/class name is hashed. handleTunnelIn is a METHOD OF THAT CLASS, and it calls
#   base.transitions.irisIn synchronously right before starting the walk Sequence. So: an interval whose
#   SPAWNING-FRAME co_name is a member of LocalToon's OWN method set AND which started inside the iris
#   window is the local toon's tunnel walk -- regardless of the per-session hash (the whole method set is
#   re-derived live each session, so whatever hash handleTunnelIn got THIS session is in the set).
#
# The mechanism is DOUBLY-GATED (LocalToon-method membership AND iris correlation) so it can NEVER scale
# MMO-noise walks (spawned by OTHER classes -> co_name not in the set) or non-tunnel LocalToon animations
# (emotes etc. -> no iris). It reaches an interval only after the name table + context did NOT scale it,
# so teleport (name-matched) and the ctx-scaled departure return first -> no double-scale.
#
# This drives the SAME logic (mirrored faithfully) against stock arm64 CPython 3.8, real native
# trampolines, and mock classes. The spawning-frame co_name is read exactly as the shipping ST.spawnCoName
# (tstate->frame +0x18 -> f_code +0x20 -> co_name +0x70); the one faithful deviation is the tstate
# acquisition (PyThreadState_Get() here vs the hardcoded TTR cell -- a plain C call pushes no Python
# frame, so tstate->frame is unchanged). Proves:
#   A. LocalToon resolves by ['tunnelOut'] to EXACTLY one class; its OWN method set contains the hashed
#      arrival handler (vlt_handleTunnelIn) + the other LocalToon methods, and NOT the non-LocalToon
#      method (otherWalk) -- dunders filtered out;
#   B. ARRIVAL: vlt_handleTunnelIn stamps an iris then starts an UNNAMED walk Sequence -> the walk is
#      scaled x4 (tunnel) via=localtoon-method, co read back == the hashed handler name; the iris itself
#      is scaled by NAME (transitions);
#   C. DECOY (no iris): a LocalToon method (vlt_someEmote, co IN the set) that starts a Sequence with NO
#      iris is NOT scaled (iris gate) -- proving the mechanism needs the iris, not just LocalToon-ness;
#   D. DECOY (not LocalToon): an iris-correlated interval spawned by a NON-LocalToon method (otherWalk,
#      co NOT in the set) is NOT scaled (membership gate) and its name is logged;
#   E. DECOY (teleport): teleport self.track (NAMED teleportOut-<id>), even started by a LocalToon method
#      WITH an iris, is scaled as TELEPORT (name factor 5.0), NEVER as tunnel -- name table wins first;
#   F. NO DOUBLE-SCALE: the DEPARTURE walk started while a ctx wrap-around (tunnelOut) is on the stack is
#      scaled ONCE by the CONTEXT (tunnel), and the lt-iris path does NOT also scale it (ctx returns
#      first) -- even though it is iris-correlated AND spawned by a LocalToon method (both would match);
#   G. JUNK-SAFE: getName() raising / returning a non-string passes through, is not scaled, tstate clean;
#   H. tstate clean after every case; original start() called once each; REVERT via the production
#      ST.installed enumeration (recordInstall/revertAll) restores start + the ctx wrap -> none remain.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/ltiris_test.py frida/run-injector.sh
#     (or: sudo -n env PYTHONPATH=<frida-site-packages> /path/to/arm64-frida-python localtest/ltiris_test.py)

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

# CPython 3.8 struct offsets (the thing spawnCoName reads). ABI-fixed for 3.8.x/64-bit.
FRAME_OFF  = 0x18   # PyThreadState.frame
FCODE_OFF  = 0x20   # PyFrameObject.f_code
CONAME_OFF = 0x70   # PyCodeObject.co_name

# Name table. teleport 5.0 is DELIBERATELY distinct from the lt-iris/tunnel factor 4.0 so a teleport hit
# is unambiguously the NAME path (teleport), not tunnel. irisTask -> transitions (also stamps the window).
# NOTHING matches the hashed auto-name 'vlt8e0d5a85-<n>', so an un-scaled walk would fall through to
# "unmatched/logged" -- never silently mis-scaled.
TABLE = [
    {"match": "teleportOut", "factor": 5.0, "group": "teleport",    "prefix": False},
    {"match": "irisTask",    "factor": 3.0, "group": "transitions", "prefix": False},
]

LT_SIG = ["tunnelOut"]     # the readable, UNIQUE signature that resolves LocalToon (never its hash)
LT_FACTOR = 4.0
IRIS_WINDOW_MS = 200
CTX_FACTOR = 4.0           # the tunnelOut context (departure) factor


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


# Mock Panda MetaInterval: discriminating signature (start+setPlayRate+append+clearIntervals). getName()
# returns its name (or misbehaves for junk); start() returns a sentinel (pass-through check) and RESETS
# play_rate to the playRate arg (hence wrap-AFTER -> setPlayRate overrides it); setPlayRate records.
#
# Mock LocalToon: resolvable by the readable `tunnelOut` signature (its module/class names are hashed,
# like TTR). Its animator handlers are HASHED-named (mirror TTR, where handleTunnelIn/Out are hashed).
# Each handler builds an UNNAMED, auto-named ('vlt8e0d5a85-<n>') fire-and-forget Sequence -- unreachable
# by name -- and .start()s it FROM WITHIN its own frame, so the wrap-after reads the handler's co_name as
# the spawning frame. The ARRIVAL handler stamps an iris (irisTask) synchronously right before the walk.
#
# Mock OtherClass: NOT a LocalToon (no tunnelOut -> not in the method set). Its otherWalk is iris-
# correlated but its co_name is not a LocalToon method -> must be spared (membership gate).
TARGET_PROG = r"""
import sys, types, time

def _make_metaival():
    class MetaIntervalMock:
        def __init__(self, name, sentinel=0, junk=None):
            self._name = name; self._sentinel = sentinel; self._junk = junk
            self.play_rate = 1.0; self.spr_count = 0; self.started = 0
        def getName(self):
            if self._junk == 'raise': raise RuntimeError('boom in getName')
            if self._junk == 'nonstr': return 12345          # non-string -> AsUTF8 must fail-safe
            return self._name
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

# intervals (module globals, fetched by the agent). The walks are UNNAMED (hashed auto-name), like the
# real self.tunnelTrack Sequence; iris is the screen iris; teleport is the NAMED teleport self.track.
iris          = MI("irisTask", 800)
teleport      = MI("teleportOut-112139724", 801)   # teleport self.track -- NAME-matched, never tunnel
walk_arrival  = MI("vlt8e0d5a85-23", 803)           # ARRIVAL walk (hashed auto-name) -> lt-iris scales
walk_emote    = MI("vlt8e0d5a85-50", 804)           # LocalToon method, NO iris -> must NOT scale
walk_other    = MI("vlt8e0d5a85-77", 805)           # NON-LocalToon, iris-correlated -> must NOT scale
walk_depart   = MI("vlt8e0d5a85-88", 806)           # DEPARTURE walk -> ctx scales (no double via lt-iris)
junk_raise    = MI("jr", 808, junk='raise')
junk_nonstr   = MI("jn", 809, junk='nonstr')

def _make_localtoon(MI):
    class LocalToonMock:
        # `tunnelOut` = the readable, UNIQUE signature the agent resolves LocalToon by (never the hash).
        # It only b_set...s to the server in TTR (no interval); here it is just the signature marker.
        def tunnelOut(self, *a, **k): return 999
        # HASHED arrival handler (handleTunnelIn analog): iris FIRST (base.transitions.irisIn), THEN start
        # the walk -- both synchronous in THIS frame, so the walk's spawning co_name is this method's.
        def vlt_handleTunnelIn(self, *a, **k):
            iris.start()                # stamps the iris window (name 'irisTask')
            walk_arrival.start()        # UNNAMED walk -> scaled by lt-iris (iris-correlated + LocalToon)
            return 803
        # a LocalToon method (co IN the set) that starts an interval with NO iris -> must be spared.
        def vlt_someEmote(self, *a, **k):
            walk_emote.start()
            return 804
        # a LocalToon method that irises then starts the NAMED teleport track -> teleport wins (name).
        def vlt_teleportInto(self, *a, **k):
            iris.start()
            teleport.start()
            return 801
        # the DEPARTURE handler (handleTunnelOut analog): starts the walk while the tunnelOut ctx wrap is
        # on the stack (the agent wraps this method wrap-around) -> ctx scales the walk. NB the real
        # handleTunnelOut's irisOut is DELAYED (fires at the walk's END, per the reference), so it does NOT
        # iris synchronously here; the test stamps the iris window externally so the walk is ALSO
        # iris-correlated + LocalToon-spawned (i.e. lt-iris WOULD match) -> proving ctx wins with no double.
        def vlt_handleTunnelOut(self, *a, **k):
            walk_depart.start()
            return 806
    return LocalToonMock

_lmod = types.ModuleType("vlt24ab6c6d.vlt7892fa9a.vlt725d40df")
_lmod.LocalToon = _make_localtoon(MI)
sys.modules["vlt24ab6c6d.vlt7892fa9a.vlt725d40df"] = _lmod
localtoon = _lmod.LocalToon()

def _make_other(MI):
    class OtherClassMock:            # NOT a LocalToon (no tunnelOut) -> otherWalk co_name not in the set
        def otherWalk(self, *a, **k):
            iris.start()             # iris-correlated...
            walk_other.start()       # ...but spawned by a NON-LocalToon method -> must NOT scale
            return 805
    return OtherClassMock

_omod = types.ModuleType("vlt24ab6c6d.vltsomeone.vltOther")
_omod.OtherClass = _make_other(MI)
sys.modules["vlt24ab6c6d.vltsomeone.vltOther"] = _omod
other = _omod.OtherClass()

# decoy: start/setPlayRate but NOT the append/clearIntervals discriminators -> not the MetaInterval.
def _make_plain():
    class PlainThing:
        def start(self, *a, **k): return 1
        def setPlayRate(self, r): pass
    return PlainThing
_pmod = types.ModuleType("decoymod_lt")
_pmod.PlainThing = _make_plain()
sys.modules["decoymod_lt"] = _pmod

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
        base: base, done:false, keep:[], installed:[], entries: p.table, logOn: true, log: [],
        scaledGroups: {}, scaledNames: [], scaledVia: [], coByName: {},
        ctx: null,
        // lt-iris config (mirrors the shipping spec.ltiris). localToonMethods starts NULL (resolved once).
        ltIrisEnabled: true, ltIrisFactor: p.lt_factor, ltIrisWindowMs: p.iris_window_ms,
        ltSig: p.lt_sig, localToonMethods: null, localToonName: null,
        ctxFactor: p.ctx_factor,
        lastIrisMs: 0,
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
      // MIRROR production ST.installed enumeration: recordInstall stashes every wrap, revertAll restores
      // every original (start wrap-after + the ctx wrap-around) -- the single source of truth on stop.
      ST.recordInstall = function(cls, mn, orig){ ST.installed.push({cls:cls, mn:mn, orig:orig}); };
      ST.revertAll = function(){
        var rcs = [], allOk = true;
        for (var i=0;i<ST.installed.length;i++){
          var it = ST.installed[i];
          var rc = ST.SetAttrStr(it.cls, it.mn, it.orig); rcs.push(rc); if (rc !== 0) allOk = false;
        }
        ST.clearExc();
        return { rc: rcs, all_ok: allOk, n: ST.installed.length };
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
      ST.isIrisName = function(nm){ return !!(nm && nm.toLowerCase().indexOf('iris') >= 0); };

      // ---- LOCALTOON METHOD SET (mirrors ST.resolveLocalToonMethods) ----
      // Resolve LocalToon by the ltSig signature; cache its OWN tp_dict method-name SET (non-underscore).
      // The set includes the HASHED handlers because a `def NAME`'s co_name == its class-attr key.
      ST.resolveLocalToonMethods = function(md){
        try {
          if (ST.localToonMethods) return ST.localToonMethods;
          md = md || ST.GetModuleDict(); if (md.isNull()){ ST.clearExc(); return null; }
          var found = ST.scanBySignature(md, ST.ltSig);
          if (!found || !found.length){ ST.clearExc(); return null; }
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
              if (nm && nm[0] !== '_'){ set[nm] = true; cnt++; }
            }
          }
          ST.clearExc();
          if (cnt === 0) return null;
          ST.localToonMethods = set; ST.localToonName = rec.class_name;
          return set;
        } catch(e){ ST.clearExc(); return null; }
      };
      ST.tryTunnelLtIris = function(inst, nm, coName, md){
        try {
          if (!ST.ltIrisEnabled) return false;
          if ((Date.now() - (ST.lastIrisMs||0)) > ST.ltIrisWindowMs) return false;   // gate (1): iris
          if (coName === null || coName === undefined) return false;
          if (!ST.localToonMethods){ ST.resolveLocalToonMethods(md); }
          if (!ST.localToonMethods) return false;
          if (ST.localToonMethods[coName] !== true) return false;                    // gate (2): membership
          var ok = ST.setPlayRate(inst, ST.ltIrisFactor);
          if (ok){ ST.scaledGroups['tunnel'] = (ST.scaledGroups['tunnel']||0) + 1; ST.scaledNames.push(nm);
                   ST.scaledVia.push({name:nm, via:'localtoon-method', co:coName, factor:ST.ltIrisFactor}); }
          ST.clearExc(); return ok;
        } catch(e){ ST.clearExc(); return false; }
      };

      // applyModset -- MIRRORS the modset branch ORDER in trampoline_inject.py:
      // getName -> iris stamp -> ctx -> name table -> lt-iris -> unmatched log. (spawn_context omitted:
      // retired for the tunnel + covered by spawnctx_test; tunnel_identity omitted: covered by
      // tunnelident_test. This test targets the lt-iris arrival path.)
      ST.applyModset = function(inst){
        try {
          var gm2 = ST.GetAttrStr(inst, cstr('getName'));
          if (gm2.isNull()){ ST.clearExc(); return 0; }
          var nm4 = ST.Call(gm2, ST.TupleNew(0), ptr(0));
          if (nm4.isNull()){ ST.clearExc(); return 0; }
          var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
          if (nms4 === null){ ST.clearExc(); return 0; }
          if (ST.isIrisName(nms4)) ST.lastIrisMs = Date.now();               // (0) iris stamp
          var coName = ST.spawnCoName();                                     // read once per start
          if (coName !== null) ST.coByName[nms4] = coName;
          if (ST.ctx){                                                       // (1) CONTEXT scaling wins
            var okc = ST.setPlayRate(inst, ST.ctx.factor);
            if (okc){ ST.scaledGroups[ST.ctx.group] = (ST.scaledGroups[ST.ctx.group]||0) + 1;
                      ST.scaledNames.push(nms4); ST.scaledVia.push({name:nms4, via:'ctx', co:coName, factor:ST.ctx.factor}); }
            ST.clearExc(); return okc ? 1 : 0;
          }
          var entries = ST.entries || [], matched = null;                    // (3) NAME table
          for (var mi=0; mi<entries.length; mi++){
            var en = entries[mi]; if (!en || !en.match) continue;
            var isHit = en.prefix ? (nms4.lastIndexOf(en.match, 0) === 0) : (nms4.indexOf(en.match) >= 0);
            if (isHit){ matched = en; break; }
          }
          if (matched){
            var okm = ST.setPlayRate(inst, matched.factor);
            if (okm){ ST.scaledGroups[matched.group] = (ST.scaledGroups[matched.group]||0) + 1;
                      ST.scaledNames.push(nms4); ST.scaledVia.push({name:nms4, via:'name', co:coName, factor:matched.factor}); }
            ST.clearExc(); return okm ? 1 : 0;
          }
          if (ST.ltIrisEnabled){                                             // (4.5) DETERMINISTIC ARRIVAL
            if (ST.tryTunnelLtIris(inst, nms4, coName, null)){ ST.clearExc(); return 1; }
          }
          if (ST.logOn && ST.log.indexOf(nms4) < 0) ST.log.push(nms4);       // (5) unmatched log
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
      // wrap-AROUND context wrapper (mirrors ST.makeCtxWrap): SET ST.ctx before the original, restore
      // prev AFTER in a finally (clears even on raise). Used to install the tunnelOut DEPARTURE ctx.
      ST.makeCtxWrap = function(orig, group, factorVal){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var prev = ST.ctx;
          ST.ctx = { group: group, factor: factorVal };
          var result;
          try { result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs); }
          finally { ST.ctx = prev; }
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

      // shared signature scan (verbatim shape from trampoline_inject.py) -- resolve MetaInterval + LocalToon.
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

            // A: resolve the MetaInterval mock by signature; wrap its start() (wrap-after), record install.
            var miFound = ST.scanBySignature(md, ['start','setPlayRate','append','clearIntervals']);
            var miNames = {}; for (var i=0;i<miFound.length;i++){ miNames[miFound[i].class_name] = miFound[i]; }
            R.mi_found = Object.keys(miNames).sort();
            var miRec = miNames['MetaIntervalMock'];
            if (!miRec){ send({t:'done', r:{ok:false, stage:'MetaIntervalMock not discovered', found:R.mi_found}}); return; }
            var miCls = miRec.clsPtr; ST.keep.push(miCls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(miCls, mnStart); ST.keep.push(origStart);
            ST.SetAttrStr(miCls, mnStart, ST.makeWrapAfter(origStart));
            ST.recordInstall(miCls, mnStart, origStart);          // the MetaInterval.start wrap-after

            // A: resolve LocalToon by ['tunnelOut'] and cache its OWN method SET.
            var ltSet = ST.resolveLocalToonMethods(md);
            R.lt_resolved = !!ltSet;
            R.lt_class = ST.localToonName;
            R.lt_has_arrival = !!(ltSet && ltSet['vlt_handleTunnelIn']);
            R.lt_has_emote   = !!(ltSet && ltSet['vlt_someEmote']);
            R.lt_has_depart  = !!(ltSet && ltSet['vlt_handleTunnelOut']);
            R.lt_has_tunnelOut = !!(ltSet && ltSet['tunnelOut']);
            R.lt_has_otherWalk = !!(ltSet && ltSet['otherWalk']);       // must be FALSE (not a LocalToon method)
            R.lt_has_dunder    = !!(ltSet && ltSet['__init__']);        // must be FALSE (dunders filtered)
            R.lt_method_count  = ltSet ? Object.keys(ltSet).length : 0;

            // install the tunnelOut-style DEPARTURE ctx wrap on vlt_handleTunnelOut (mirrors the shipping
            // `context` tunnelOut wrap-around: sets ST.ctx around the call so the walk it starts is
            // ctx-scaled). Records the install so revert restores it too.
            var ltMod = ST.DictGetStr(md, cstr('vlt24ab6c6d.vlt7892fa9a.vlt725d40df'));
            var ltCls = ltMod.isNull()? ptr(0) : ST.GetAttrStr(ltMod, cstr('LocalToon'));
            ST.keep.push(ltCls);
            var mnDepart = cstr('vlt_handleTunnelOut'); ST.keep.push(mnDepart);
            var origDepart = ST.GetAttrStr(ltCls, mnDepart); ST.keep.push(origDepart);
            ST.SetAttrStr(ltCls, mnDepart, ST.makeCtxWrap(origDepart, 'tunnel', ST.ctxFactor));
            ST.recordInstall(ltCls, mnDepart, origDepart);        // the tunnelOut-style ctx wrap-around
            R.ctx_wrap_installed = true;

            var localtoon = ST.GetAttrStr(main, cstr('localtoon')); ST.keep.push(localtoon);
            var other     = ST.GetAttrStr(main, cstr('other'));     ST.keep.push(other);
            function callMeth(inst, meth){
              var b = ST.GetAttrStr(inst, cstr(meth));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              return res;
            }
            function G(n){ return ST.GetAttrStr(main, cstr(n)); }
            function ivInfo(iv){
              return { spr_calls: L(ST.GetAttrStr(iv, cstr('spr_count'))),
                       started:   L(ST.GetAttrStr(iv, cstr('started'))),
                       play_rate: D(ST.GetAttrStr(iv, cstr('play_rate'))),
                       name:      iv.isNull()? null : ST.AsUTF8(ST.GetAttrStr(iv, cstr('_name'))).readCString() };
            }
            function viaOf(nm){ for (var i=0;i<ST.scaledVia.length;i++){ if (ST.scaledVia[i].name === nm) return ST.scaledVia[i]; } return null; }

            var walk_arrival = G('walk_arrival'), walk_emote = G('walk_emote'), walk_other = G('walk_other'),
                walk_depart = G('walk_depart'), teleport = G('teleport'),
                junk_raise = G('junk_raise'), junk_nonstr = G('junk_nonstr');
            ST.keep.push(walk_arrival); ST.keep.push(walk_emote); ST.keep.push(walk_other);
            ST.keep.push(walk_depart); ST.keep.push(teleport);

            // B. ARRIVAL: vlt_handleTunnelIn irises then starts the walk -> lt-iris scales it x4 (tunnel).
            ST.lastIrisMs = 0;
            var rIn = callMeth(localtoon, 'vlt_handleTunnelIn'); var rIn_l = rIn.isNull()?null:L(rIn);
            R.arrival = Object.assign(ivInfo(walk_arrival), { passed_through:(rIn_l===803), tstate_clean:ST.Occurred().isNull() });
            R.arrival.via = viaOf(R.arrival.name); R.arrival.co = ST.coByName[R.arrival.name] || null;
            ST.clearExc();

            // C. DECOY (no iris): vlt_someEmote (co IN set) with NO iris -> must NOT scale.
            ST.lastIrisMs = 0;
            var rEm = callMeth(localtoon, 'vlt_someEmote'); var rEm_l = rEm.isNull()?null:L(rEm);
            R.emote = Object.assign(ivInfo(walk_emote), { passed_through:(rEm_l===804), tstate_clean:ST.Occurred().isNull() });
            ST.clearExc();

            // D. DECOY (not LocalToon): other.otherWalk irises then starts -> iris-correlated but co NOT in
            //    the LocalToon set -> must NOT scale.
            ST.lastIrisMs = 0;
            var rOt = callMeth(other, 'otherWalk'); var rOt_l = rOt.isNull()?null:L(rOt);
            R.other_walk = Object.assign(ivInfo(walk_other), { passed_through:(rOt_l===805), tstate_clean:ST.Occurred().isNull() });
            R.other_walk.co = ST.coByName[R.other_walk.name] || null;
            ST.clearExc();

            // E. DECOY (teleport): vlt_teleportInto irises then starts the NAMED teleport track -> teleport
            //    (name 5.0), NEVER tunnel, even though it is LocalToon-spawned + iris-correlated.
            ST.lastIrisMs = 0;
            var rTp = callMeth(localtoon, 'vlt_teleportInto'); var rTp_l = rTp.isNull()?null:L(rTp);
            R.teleport = Object.assign(ivInfo(teleport), { passed_through:(rTp_l===801), tstate_clean:ST.Occurred().isNull() });
            R.teleport.via = viaOf(R.teleport.name);
            ST.clearExc();

            // F. NO DOUBLE-SCALE: vlt_handleTunnelOut is ctx-wrapped (tunnelOut departure). Stamp the iris
            //    window externally so the walk is ALSO iris-correlated + LocalToon-spawned (lt-iris WOULD
            //    match) -> proving ctx scales it ONCE and lt-iris does NOT also scale it (ctx returns first).
            ST.lastIrisMs = Date.now();
            var rDe = callMeth(localtoon, 'vlt_handleTunnelOut'); var rDe_l = rDe.isNull()?null:L(rDe);
            R.depart = Object.assign(ivInfo(walk_depart), { passed_through:(rDe_l===806), tstate_clean:ST.Occurred().isNull() });
            R.depart.via = viaOf(R.depart.name);
            ST.clearExc();

            // G. JUNK-SAFE: start junk intervals directly (an iris recent so they'd reach lt-iris if named).
            ST.lastIrisMs = Date.now();
            var rjr = callMeth(junk_raise, 'start'); var rjr_l = rjr.isNull()?null:L(rjr);
            var rjn = callMeth(junk_nonstr, 'start'); var rjn_l = rjn.isNull()?null:L(rjn);
            R.junk_raise  = Object.assign(ivInfo(junk_raise),  { passed_through:(rjr_l===808), tstate_clean:ST.Occurred().isNull() });
            R.junk_nonstr = Object.assign(ivInfo(junk_nonstr), { passed_through:(rjn_l===809), tstate_clean:ST.Occurred().isNull() });
            ST.clearExc();

            R.scaled_groups = ST.scaledGroups;
            R.scaled_names  = ST.scaledNames.slice().sort();
            R.scaled_via    = ST.scaledVia.slice();
            R.logged_names  = ST.log.slice().sort();

            // H. REVERT via the production ST.installed enumeration; read back -> none remain.
            var revr = ST.revertAll();
            R.revert_rc = revr.rc; R.revert_all_ok = revr.all_ok; R.revert_installed_count = revr.n;
            var remaining = [];
            for (var ri=0; ri<ST.installed.length; ri++){
              var it2 = ST.installed[ri];
              var cur = ST.GetAttrStr(it2.cls, it2.mn); ST.clearExc();
              if (!cur.equals(it2.orig)) remaining.push(ri);
            }
            R.revert_all_restored = (remaining.length === 0);
            R.tstate_clean_after_revert = ST.Occurred().isNull();
            ST.clearExc();

            // count the lt-iris scales (via localtoon-method) and ctx scales.
            var ltViaCount = ST.scaledVia.filter(function(x){ return x.via === 'localtoon-method'; }).length;
            var ctxViaCount = ST.scaledVia.filter(function(x){ return x.via === 'ctx'; }).length;

            function scaledAs(o, f, via){ return o.passed_through && o.started === 1 && o.spr_calls === 1 && o.play_rate === f && o.tstate_clean && o.via && o.via.via === via; }
            function untouched(o){ return o.passed_through && o.started === 1 && o.spr_calls === 0 && o.play_rate === 1.0 && o.tstate_clean; }

            R.ok = !!(
              R.mi_found.length >= 1 &&
              // A: LocalToon resolved; set has the LocalToon methods incl. the hashed arrival handler,
              //    excludes the non-LocalToon method + dunders:
              R.lt_resolved && R.lt_class === 'LocalToonMock' &&
              R.lt_has_arrival && R.lt_has_emote && R.lt_has_depart && R.lt_has_tunnelOut &&
              (R.lt_has_otherWalk === false) && (R.lt_has_dunder === false) &&
              // B: ARRIVAL walk scaled x4 via localtoon-method, co read back == the hashed handler:
              scaledAs(R.arrival, ST.ltIrisFactor, 'localtoon-method') &&
              R.arrival.co === 'vlt_handleTunnelIn' && R.arrival.name.indexOf('vlt8e0d5a85-') === 0 &&
              // C: no-iris LocalToon interval untouched (iris gate):
              untouched(R.emote) &&
              // D: non-LocalToon iris-correlated interval untouched (membership gate) + logged:
              untouched(R.other_walk) && R.other_walk.co === 'otherWalk' &&
              R.logged_names.indexOf('vlt8e0d5a85-77') >= 0 &&
              // E: teleport scaled as TELEPORT (name 5.0), never tunnel:
              scaledAs(R.teleport, 5.0, 'name') &&
              // F: departure scaled ONCE via ctx (tunnel), NOT double via lt-iris:
              scaledAs(R.depart, ST.ctxFactor, 'ctx') &&
              // G: junk-safe, untouched:
              untouched(R.junk_raise) && untouched(R.junk_nonstr) &&
              // exactly ONE lt-iris scale (the arrival) and ONE ctx scale (the departure):
              ltViaCount === 1 && ctxViaCount === 1 &&
              // group tally: tunnel = arrival(lt-iris) + departure(ctx) = 2; teleport = 1;
              // transitions = the 3 iris starts (arrival + otherWalk + teleportInto; departure has none):
              R.scaled_groups.tunnel === 2 && R.scaled_groups.teleport === 1 &&
              R.scaled_groups.transitions === 3 &&
              // emote's un-iris'd walk is the only other unmatched-logged name besides other_walk:
              R.logged_names.indexOf('vlt8e0d5a85-50') >= 0 &&
              // revert restored BOTH installed wraps (start + ctx) -> none remain:
              R.revert_installed_count === 2 && R.revert_all_ok === true && R.revert_all_restored === true &&
              R.tstate_clean_after_revert
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
    print("[ltiris] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
                    "table": TABLE, "lt_sig": LT_SIG, "lt_factor": LT_FACTOR,
                    "iris_window_ms": IRIS_WINDOW_MS, "ctx_factor": CTX_FACTOR,
                    "frame_off": hex(FRAME_OFF), "fcode_off": hex(FCODE_OFF), "coname_off": hex(CONAME_OFF)})
    if not init.get("ok"):
        print("[ltiris] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[ltiris] hook never fired in 20s")
    elif box.get("detached"):
        print("[ltiris] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[ltiris] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[ltiris] target_alive=%s" % alive)
    print("[ltiris] VERDICT: %s" % (
        "PASS -- the tunnel ARRIVAL is caught DETERMINISTICALLY: the walk spawned by the (hashed) "
        "handleTunnelIn -- a member of LocalToon's live-resolved method set -- inside the iris window is "
        "scaled x4 (tunnel) via=localtoon-method; a no-iris LocalToon interval, an iris-correlated "
        "NON-LocalToon interval, and the NAMED teleport track are all spared/handled correctly; the "
        "ctx-scaled departure is not double-scaled; junk-safe; tstate clean; reverts via ST.installed"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
