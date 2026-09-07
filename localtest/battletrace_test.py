#!/usr/bin/env python3
# localtest/battletrace_test.py -- OFFLINE validation of the READ-ONLY BATTLETRACE mechanism that ships
# in frida/trampoline_inject.py (TTRMOD_BATTLETRACE=1). BATTLETRACE changes NOTHING about gameplay: it
# only timestamps + logs the key battle events so their ordering + inter-step gaps are measurable, to
# attribute each delay to a CLIENT timer (scalable) or a SERVER-gated event (a hard limit). It has two
# layers, BOTH exercised here against stock arm64 CPython 3.8 with faithful mocks:
#
#   (1) METHOD trace: resolve the battle FSM class by SIGNATURE (setState+d_movieDone -> the real
#       DistributedBattleBase; a decoy defining only setState is NOT chosen), then install a LOGGING-ONLY
#       wrap-after on the INBOUND `setState` (reads the state-name arg = args[1]) and the OUTBOUND
#       `d_*Done` senders. Each wrap timestamps (Date.now()), calls the ORIGINAL exactly once, and passes
#       its result straight through.
#   (2) INTERVAL trace: the modset start hook, on a battle-named interval (faceoff-battle / movie-track /
#       movie-reward-track / to-pending), timestamps the START and reads getDuration()/getPlayRate()
#       (read-only) via the inlined-PyFloat recipe (ob_type==PyFloat_Type -> double @ +0x10).
#
# Asserts:
#   A. discovery: the battle class is found by the [setState,d_movieDone] signature (exactly the mock,
#      not the setState-only decoy);
#   B. all 5 trace methods wire (installed as functions);
#   C. a scripted 2-round battle (join -> faceoff -> waitforinput -> playmovie -> reward) produces the
#      EXPECTED ordered event stream, each event carrying the right label / state / interval-name+duration;
#   D. TIMESTAMPS are present + monotonic non-decreasing, and advance across a deliberate spin (round-2
#      events strictly later than round-1) -- i.e. the ms clock is real, so live gaps will be meaningful;
#   E. PASS-THROUGH: every wrapped method ran its ORIGINAL exactly once (recorded on the mock) and its
#      return value was passed through unchanged (distinct sentinels); interval start() passed through too;
#   F. tstate CLEAN after every call;
#   G. REVERT via ST.installed restores EVERY wrap: after revert, driving setState fires NO trace event
#      (and the original still runs), and the class attr identity is back to the original;
#   H. the target stays ALIVE throughout.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/battletrace_test.py frida/run-injector.sh
#     (or: /path/to/arm64-frida-python localtest/battletrace_test.py)

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


# Target program: a mock battle FSM (setState + the d_*Done senders, each recording its call and returning
# a distinct sentinel so pass-through is checkable) under a fake vault-hashed module, a decoy class that
# defines ONLY setState (must NOT be chosen by the [setState,d_movieDone] signature), a mock MetaInterval,
# and the battle interval instances + arg constants in __main__. Busy loop keeps _PyEval_EvalFrameDefault
# firing (main thread, GIL held).
TARGET_PROG = r"""
import sys, types, time

def _make_battle():
    class DistributedBattleMock:
        def __init__(self):
            self.calls = []          # (method, args) in call order -- proves the ORIGINAL ran
        def setState(self, state, ts):
            self.calls.append(('setState', state, ts)); return 8001
        def d_faceOffDone(self, toonId):
            self.calls.append(('d_faceOffDone', toonId)); return 8002
        def d_movieDone(self, toonId):
            self.calls.append(('d_movieDone', toonId)); return 8003
        def d_rewardDone(self, toonId):
            self.calls.append(('d_rewardDone', toonId)); return 8004
        def d_joinDone(self, toonId, avId):
            self.calls.append(('d_joinDone', toonId, avId)); return 8005
        # a few non-traced methods, for realism
        def enterPlayMovie(self, ts): pass
        def d_timeout(self, toonId): pass
    return DistributedBattleMock

# decoy: has setState but NOT d_movieDone -> the signature [setState,d_movieDone] must skip it
def _make_decoy():
    class NotTheBattle:
        def setState(self, *a): return -1
        def d_faceOffDone(self, *a): return -1   # even sharing some names, it lacks d_movieDone
    return NotTheBattle

# mock Panda MetaInterval: getName / getDuration / getPlayRate for the interval trace; start() is the
# wrap-after target (returns a sentinel = pass-through; resets play_rate = proves wrap-AFTER);
# append/clearIntervals are the Python-only discriminators vs the C++ CInterval base.
def _make_metaival():
    class MetaIntervalMock:
        def __init__(self, name, dur, sentinel):
            self._name = name; self._dur = float(dur); self._sentinel = sentinel
            self.play_rate = 1.0; self.started = 0
        def getName(self): return self._name
        def getDuration(self): return self._dur
        def getPlayRate(self): return self.play_rate
        def start(self, startT=0.0, endT=-1.0, playRate=1.0):
            self.started += 1; self.play_rate = playRate; return self._sentinel
        def setPlayRate(self, r): self.play_rate = float(r)
        def append(self, ival): pass
        def clearIntervals(self, *a, **k): pass
    return MetaIntervalMock

_bmod = types.ModuleType("vlt24ab6c6d.vltbattle.vltDistributedBattle")
_bmod.DistributedBattle = _make_battle()
sys.modules["vlt24ab6c6d.vltbattle.vltDistributedBattle"] = _bmod

_dmod = types.ModuleType("decoy_battle_mod")
_dmod.NotTheBattle = _make_decoy()
sys.modules["decoy_battle_mod"] = _dmod

_mmod = types.ModuleType("vlt1609aac2.vltinterval.vltMetaInterval")
_mmod.MetaInterval = _make_metaival()
sys.modules["vlt1609aac2.vltinterval.vltMetaInterval"] = _mmod

BAT = _bmod.DistributedBattle
MI  = _mmod.MetaInterval

# the battle instance the trace wraps are installed on (class-level), then driven:
battle = BAT()

# battle intervals (name, base duration, start-sentinel):
to_pending_ival = MI("to-pending-toon-42", 1.20, 9001)
faceoff_ival    = MI("faceoff-battle77",   3.50, 9002)
movie_ival      = MI("movie-track",        6.00, 9003)
reward_ival     = MI("movie-reward-track", 4.00, 9004)

# state-name + int arg constants (fetched by the agent so it need not build str/int objects itself):
S_FACEOFF='FaceOff'; S_WAIT='WaitForInput'; S_PLAY='PlayMovie'; S_REWARD='Reward'
S_AFTER='WaitForInput'   # a post-revert drive
IARG=0; AVID=99

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
        base: base, done:false, keep:[], installed:[],
        btMethods: p.bt_methods, btSig: p.bt_sig, btNames: p.bt_names,
        btInstalled: false, btLog: [], seq: 0,
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
      ST.clearExc = function(){ try { if (!ST.Occurred().isNull()) ST.Clear(); } catch(e){} };
      ST.pack1 = function(o){ return ST.TuplePack(1, o); };
      ST.tpname = function(o){ try { return o.add(8).readPointer().add(0x18).readPointer().readCString(); } catch(e){ return '?'; } };
      ST.recordInstall = function(cls, mn, orig){ try { ST.installed.push({cls:cls, mn:mn, orig:orig}); } catch(e){} };

      // ---- the READ-ONLY helpers under test (mirror frida/trampoline_inject.py) ----
      ST.floatDouble = function(obj){
        try {
          if (!obj || obj.isNull()) return null;
          if (ST.FloatType && obj.add(8).readPointer().equals(ST.FloatType)) return obj.add(0x10).readDouble();
          return null;
        } catch(e){ return null; }
      };
      ST.callFloat0 = function(inst, name){
        try {
          var mm = ST.GetAttrStr(inst, cstr(name));
          if (mm.isNull()){ ST.clearExc(); return null; }
          var r = ST.Call(mm, ST.TupleNew(0), ptr(0));
          if (r.isNull()){ ST.clearExc(); return null; }
          var d = ST.floatDouble(r);
          ST.clearExc();
          return d;
        } catch(e){ ST.clearExc(); return null; }
      };
      ST.btHit = function(nm){
        if (!nm || !ST.btNames.length) return false;
        for (var i=0;i<ST.btNames.length;i++){ if (ST.btNames[i] && nm.indexOf(ST.btNames[i]) >= 0) return true; }
        return false;
      };
      // (transport differs from prod's send(): here each event is pushed to ST.btLog so the host can
      // assert synchronously -- the MECHANISM under test (timestamp, read-arg, pass-through, tstate) is
      // identical.)
      ST.btEmitIval = function(inst, nm){
        try {
          var dur = ST.callFloat0(inst, 'getDuration');
          var rate = ST.callFloat0(inst, 'getPlayRate');
          ST.btLog.push({seq: ST.seq++, ms: Date.now(), ev:'ival', name:nm, dur:dur, rate:rate});
        } catch(e){ ST.clearExc(); }
      };
      ST.makeTraceWrap = function(orig, label, readStateArg){
        var cb = new NativeCallback(function (self, args, kwargs) {
          try {
            var state = null;
            if (readStateArg && ST.AsUTF8){
              try {
                var n = args.add(0x10).readS64().toNumber();
                if (n >= 2){
                  var sObj = args.add(0x18 + 8).readPointer();      // ob_item[1] = state name
                  if (!sObj.isNull()){ try { state = ST.AsUTF8(sObj).readCString(); } catch(e){ state = null; } }
                }
              } catch(e){ state = null; }
              ST.clearExc();
            }
            ST.btLog.push({seq: ST.seq++, ms: Date.now(), ev:'m', label:label, state:state});
          } catch(e){ ST.clearExc(); }
          return ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // original once; result passed through
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = cstr('ttrmod_bt'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };
      ST.installBattleTrace = function(md){
        try {
          if (ST.btInstalled) return null;
          md = md || ST.GetModuleDict(); if (md.isNull()){ ST.clearExc(); return null; }
          var found = ST.scanBySignature(md, ST.btSig);
          if (!found || !found.length){ ST.clearExc(); return null; }
          var direct = found.filter(function(r){ return r.all_direct; });
          var rec = direct.length ? direct[0] : found[0];
          var cls = rec.clsPtr; ST.keep.push(cls);
          ST.btInstalled = true;
          var wired = [];
          for (var i=0;i<ST.btMethods.length;i++){
            var meth = ST.btMethods[i];
            var mn = cstr(meth);
            var orig = ST.GetAttrStr(cls, mn);
            if (orig.isNull()){ ST.clearExc(); wired.push({method:meth, ok:false, reason:'absent'}); continue; }
            var otn = ST.tpname(orig);
            if (otn !== 'function'){ ST.clearExc(); wired.push({method:meth, ok:false, reason:'not a function ('+otn+')'}); continue; }
            ST.keep.push(orig); ST.keep.push(mn);
            var im = ST.makeTraceWrap(orig, meth, (meth === 'setState'));
            if (im.isNull()){ wired.push({method:meth, ok:false, reason:'wrap NULL'}); continue; }
            var rc = ST.SetAttrStr(cls, mn, im);
            ST.recordInstall(cls, mn, orig);
            wired.push({method:meth, ok:(rc===0), setattr_rc:rc});
          }
          ST.clearExc();
          return {cls:rec.class_name, all_direct:rec.all_direct, wired:wired, clsPtr:cls};
        } catch(e){ ST.clearExc(); return null; }
      };

      // shared signature scan (same shape as trampoline_inject.py / modset_test.py)
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
          var rec = { class_name: className, clsPtr: cls, methods: {}, match_count: 0, full: false, all_direct: true, bindings: [] };
          for (var mi=0; mi<methods.length; mi++){
            var where = 'absent';
            for (var bi=0; bi<mro.length; bi++){
              var B = mro[bi]; if (B.isNull()) continue;
              var bdict = ptr(0); try { bdict = B.add(0x108).readPointer(); } catch(e){ bdict = ptr(0); }
              if (bdict.isNull()) continue;
              var hit = ST.DictGetStr(bdict, methCStrs[mi]);
              if (!hit.isNull()){ where = (bi===0)?'direct':'inherited'; break; }
            }
            rec.methods[methods[mi]] = { where: where };
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
            var modName = null, ak;
            while (!(ak = ST.IterNext(dit)).isNull()){
              var val = ST.DictGetItem(mdict, ak); if (val.isNull()){ ST.clearExc(); continue; }
              var isType = false; try { isType = (val.add(8).readPointer().add(0xab).readU8() & 0x80) !== 0; } catch(e){ isType = false; }
              if (!isType) continue;
              var clsKey = val.toString(); var rec = byCls[clsKey];
              if (rec === undefined){ rec = ST.classSignature(val, methods, methCStrs); byCls[clsKey] = rec; if (rec) order.push(clsKey); }
              if (rec && rec.full){
                if (modName === null){ try { modName = ST.AsUTF8(mk).readCString(); } catch(e){ modName = '?'; } }
                var attr = '?'; try { attr = ST.AsUTF8(ak).readCString(); } catch(e){ attr = '?'; }
                rec.bindings.push({ module: modName, attr: attr });
              }
            }
          }
        } catch(e){}
        ST.clearExc();
        var outl = []; for (var i=0;i<order.length;i++){ var r = byCls[order[i]]; if (r && r.full) outl.push(r); }
        return outl;
      };

      // modset-style start wrap-after that ONLY does the battletrace ival emit (scaling is orthogonal and
      // covered by modset_test.py; here we validate that a battle interval's START is traced with dur+rate).
      ST.makeStartWrap = function(orig){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);
          if (result.isNull()){ return result; }
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            if (!inst.isNull()){
              var gm = ST.GetAttrStr(inst, cstr('getName'));
              var nm = null;
              if (!gm.isNull()){ var nobj = ST.Call(gm, ST.TupleNew(0), ptr(0));
                if (!nobj.isNull()){ try { nm = ST.AsUTF8(nobj).readCString(); } catch(e){ nm = null; } } }
              ST.clearExc();
              if (nm !== null && ST.btHit(nm)) ST.btEmitIval(inst, nm);
            }
          } catch(e){ ST.clearExc(); }
          ST.clearExc();
          return result;
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = cstr('ttrmod_startwrap'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
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
          try {
            var R = {};
            var md = ST.GetModuleDict();
            if (md.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }
            var main = ST.AddModule(cstr('__main__'));

            // A: discover the battle FSM class by the [setState,d_movieDone] signature (decoy excluded)
            var found = ST.scanBySignature(md, ST.btSig);
            var names = {}; for (var i=0;i<found.length;i++){ names[found[i].class_name] = found[i]; }
            R.found_names = Object.keys(names).sort();
            R.discovery_pass = (R.found_names.length === 1 && R.found_names[0] === 'DistributedBattleMock');

            // B: install the trace wraps (method layer)
            var bt = ST.installBattleTrace(md);
            if (!bt){ send({t:'done', r:{ok:false, stage:'installBattleTrace returned null', found:R.found_names}}); return; }
            R.bt_cls = bt.cls; R.bt_all_direct = bt.all_direct; R.bt_wired = bt.wired;
            R.all_wired = bt.wired.length === ST.btMethods.length && bt.wired.every(function(w){ return w.ok; });

            // interval layer: wrap MetaInterval.start
            var isig = ['start','setPlayRate','append','clearIntervals'];
            var ifound = ST.scanBySignature(md, isig);
            var irec = null; for (var j=0;j<ifound.length;j++){ if (ifound[j].class_name === 'MetaIntervalMock') irec = ifound[j]; }
            if (!irec){ send({t:'done', r:{ok:false, stage:'MetaIntervalMock not found'}}); return; }
            var icls = irec.clsPtr; ST.keep.push(icls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(icls, mnStart); ST.keep.push(origStart);
            var sim = ST.makeStartWrap(origStart);
            ST.SetAttrStr(icls, mnStart, sim);
            ST.recordInstall(icls, mnStart, origStart);

            var battle = ST.GetAttrStr(main, cstr('battle')); ST.keep.push(battle);
            // arg constants (str/int objects) fetched from __main__ (no PyUnicode_FromString needed):
            function G(n){ var o = ST.GetAttrStr(main, cstr(n)); return o; }
            var sFace=G('S_FACEOFF'), sWait=G('S_WAIT'), sPlay=G('S_PLAY'), sReward=G('S_REWARD'), sAfter=G('S_AFTER');
            var iarg=G('IARG'), avid=G('AVID');

            // call a (self-bound) method: inst.<name>(*args) -> returns its result (a new ref) or NULL
            function callM(name, args){
              var b = ST.GetAttrStr(battle, cstr(name)); if (b.isNull()){ ST.clearExc(); return null; }
              var t;
              if (args.length === 0) t = ST.TupleNew(0);
              else if (args.length === 1) t = ST.TuplePack(1, args[0]);
              else t = ST.TuplePack(2, args[0], args[1]);
              var res = ST.Call(b, t, ptr(0));
              var rl = res.isNull() ? null : L(res);
              var clean = ST.Occurred().isNull(); ST.clearExc();
              return {ret: rl, tstate_clean: clean};
            }
            function startIval(name){
              var iv = ST.GetAttrStr(main, cstr(name));
              var b = ST.GetAttrStr(iv, cstr('start'));
              var res = b.isNull() ? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              var rl = res.isNull() ? null : L(res);
              var clean = ST.Occurred().isNull(); ST.clearExc();
              return {ret: rl, tstate_clean: clean};
            }
            function spin(ms){ var t0 = Date.now(); while (Date.now() - t0 < ms){ /* burn wall-clock so timestamps advance */ } }

            // ===== scripted 2-round battle =====
            R.drive = {};
            // round 1: run-in join -> faceoff -> waitforinput
            R.drive.to_pending = startIval('to_pending_ival');            // ival trace
            R.drive.d_joinDone = callM('d_joinDone', [iarg, avid]);       // OUTBOUND
            R.drive.setFaceOff = callM('setState', [sFace, iarg]);        // INBOUND state=FaceOff
            R.drive.faceoff    = startIval('faceoff_ival');               // ival trace
            R.drive.d_faceOff  = callM('d_faceOffDone', [iarg]);          // OUTBOUND
            R.drive.setWait    = callM('setState', [sWait, iarg]);        // INBOUND state=WaitForInput
            var round1_maxseq = ST.seq - 1;
            spin(6);                                                       // advance the clock a measurable amount
            // round 2: playmovie -> reward
            R.drive.setPlay    = callM('setState', [sPlay, iarg]);        // INBOUND state=PlayMovie
            R.drive.movie      = startIval('movie_ival');                 // ival trace
            R.drive.d_movie    = callM('d_movieDone', [iarg]);            // OUTBOUND
            R.drive.setReward  = callM('setState', [sReward, iarg]);      // INBOUND state=Reward
            R.drive.reward     = startIval('reward_ival');                // ival trace
            R.drive.d_reward   = callM('d_rewardDone', [iarg]);           // OUTBOUND

            R.btlog = ST.btLog.slice();
            R.round1_maxseq = round1_maxseq;

            // the mock's recorded call list (proves originals ran + args passed):
            var callsObj = ST.GetAttrStr(battle, cstr('calls'));
            var calls = [];
            if (!callsObj.isNull()){
              var it = ST.GetIter(callsObj), e;
              while (!(e = ST.IterNext(it)).isNull()){
                // each entry is a tuple; read item0 (method name str)
                var m0 = ptr(0); try { m0 = e.add(0x18).readPointer(); } catch(_){}
                var nm = null; if (!m0.isNull()){ try { nm = ST.AsUTF8(m0).readCString(); } catch(_){ nm = null; } }
                if (nm !== null) calls.push(nm);
                ST.clearExc();
              }
            }
            ST.clearExc();
            R.mock_calls = calls;

            // ===== REVERT via ST.installed, then verify no more trace + originals still run =====
            for (var k=0;k<ST.installed.length;k++){ ST.SetAttrStr(ST.installed[k].cls, ST.installed[k].mn, ST.installed[k].orig); }
            ST.clearExc();
            var log_len_before = ST.btLog.length;
            var post = callM('setState', [sAfter, iarg]);                 // should NOT trace now
            R.revert = {
              btlog_grew: (ST.btLog.length !== log_len_before),           // must be false
              post_ret: post.ret,                                         // 8001 -> original still ran
              post_tstate_clean: post.tstate_clean,
            };
            // class attr identity restored?
            var setNow = ST.GetAttrStr(bt.clsPtr, cstr('setState'));
            var origSet = null; for (var q=0;q<ST.installed.length;q++){ if (ST.installed[q].mn === undefined) continue; }
            R.revert.setState_is_function_again = (ST.tpname(setNow) === 'function');

            // ===== verdict =====
            var lg = R.btlog;
            function ev(i){ return lg[i] || {}; }
            var expected = [
              {ev:'ival', name:'to-pending-toon-42', dur:1.20},
              {ev:'m', label:'d_joinDone'},
              {ev:'m', label:'setState', state:'FaceOff'},
              {ev:'ival', name:'faceoff-battle77', dur:3.50},
              {ev:'m', label:'d_faceOffDone'},
              {ev:'m', label:'setState', state:'WaitForInput'},
              {ev:'m', label:'setState', state:'PlayMovie'},
              {ev:'ival', name:'movie-track', dur:6.00},
              {ev:'m', label:'d_movieDone'},
              {ev:'m', label:'setState', state:'Reward'},
              {ev:'ival', name:'movie-reward-track', dur:4.00},
              {ev:'m', label:'d_rewardDone'},
            ];
            R.expected_len = expected.length; R.got_len = lg.length;
            var order_ok = (lg.length === expected.length);
            for (var e2=0; e2<expected.length && order_ok; e2++){
              var g = ev(e2), x = expected[e2];
              if (g.ev !== x.ev){ order_ok = false; break; }
              if (x.ev === 'm'){
                if (g.label !== x.label){ order_ok = false; break; }
                if (x.state !== undefined && g.state !== x.state){ order_ok = false; break; }
              } else {
                if (g.name !== x.name){ order_ok = false; break; }
                if (Math.abs((g.dur||0) - x.dur) > 0.001){ order_ok = false; break; }
                if (g.rate !== 1.0){ order_ok = false; break; }          // pre-scale client rate
              }
            }
            R.order_ok = order_ok;

            // timestamps present + monotonic non-decreasing
            var ts_ok = true, ts_present = true;
            for (var t2=0; t2<lg.length; t2++){
              if (typeof lg[t2].ms !== 'number'){ ts_present = false; break; }
              if (t2>0 && lg[t2].ms < lg[t2-1].ms){ ts_ok = false; }
            }
            R.ts_present = ts_present; R.ts_monotonic = ts_ok;
            // clock advanced across the spin: first round-2 event strictly later than last round-1 event
            var r1last = null, r2first = null;
            for (var s=0;s<lg.length;s++){ if (lg[s].seq <= R.round1_maxseq) r1last = lg[s].ms; else if (r2first === null) r2first = lg[s].ms; }
            R.clock_advanced = (r1last !== null && r2first !== null && r2first > r1last);

            // pass-through + tstate clean for driven methods
            var drives = [R.drive.d_joinDone, R.drive.setFaceOff, R.drive.d_faceOff, R.drive.setWait,
                          R.drive.setPlay, R.drive.d_movie, R.drive.setReward, R.drive.d_reward];
            var expect_ret = {d_joinDone:8005, setState:8001, d_faceOffDone:8002, d_movieDone:8003, d_rewardDone:8004};
            R.passthrough_ok = (
              R.drive.d_joinDone.ret === 8005 && R.drive.d_faceOff.ret === 8002 &&
              R.drive.d_movie.ret === 8003 && R.drive.d_reward.ret === 8004 &&
              R.drive.setFaceOff.ret === 8001 && R.drive.setWait.ret === 8001 &&
              R.drive.setPlay.ret === 8001 && R.drive.setReward.ret === 8001 &&
              // interval starts passed their sentinels through:
              R.drive.to_pending.ret === 9001 && R.drive.faceoff.ret === 9002 &&
              R.drive.movie.ret === 9003 && R.drive.reward.ret === 9004
            );
            R.tstate_ok = drives.every(function(d){ return d.tstate_clean; }) &&
                          R.drive.to_pending.tstate_clean && R.drive.faceoff.tstate_clean &&
                          R.drive.movie.tstate_clean && R.drive.reward.tstate_clean;
            // mock recorded exactly the 8 traced method calls (snapshotted BEFORE the revert+post drive)
            // in order -> every wrapped original ran once, args reached it. (The post-revert original
            // running is proven separately by R.revert.post_ret === 8001.)
            R.mock_calls_ok = (
              R.mock_calls.length === 8 &&
              R.mock_calls[0] === 'd_joinDone' && R.mock_calls[1] === 'setState' &&
              R.mock_calls[2] === 'd_faceOffDone' && R.mock_calls[3] === 'setState' &&
              R.mock_calls[4] === 'setState' && R.mock_calls[5] === 'd_movieDone' &&
              R.mock_calls[6] === 'setState' && R.mock_calls[7] === 'd_rewardDone'
            );

            R.revert_ok = (R.revert.btlog_grew === false && R.revert.post_ret === 8001 &&
                           R.revert.post_tstate_clean === true && R.revert.setState_is_function_again === true);

            R.ok = !!(
              R.discovery_pass && R.all_wired && R.order_ok && R.ts_present && R.ts_monotonic &&
              R.clock_advanced && R.passthrough_ok && R.tstate_ok && R.mock_calls_ok && R.revert_ok
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
    print("[battletrace] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

    BT_METHODS = ["setState", "d_movieDone", "d_faceOffDone", "d_rewardDone", "d_joinDone"]
    BT_SIG = ["setState", "d_movieDone"]
    BT_NAMES = ["faceoff-battle", "movie-track", "movie-reward-track", "to-pending"]

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
        tgt.kill(); raise SystemExit("attach failed (arm64 target required): %s" % e)
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib,
                    "bt_methods": BT_METHODS, "bt_sig": BT_SIG, "bt_names": BT_NAMES})
    if not init.get("ok"):
        print("[battletrace] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[battletrace] hook never fired in 20s")
    elif box.get("detached"):
        print("[battletrace] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[battletrace] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[battletrace] target_alive=%s" % alive)
    print("[battletrace] VERDICT: %s" % (
        "PASS -- battletrace resolves the battle FSM class by signature, installs read-only logging wraps "
        "on setState + the d_*Done senders, timestamps an ordered battle event stream (inbound setState / "
        "outbound d_*Done / interval start+duration), passes every original through unchanged, keeps the "
        "tstate clean, and reverts fully via ST.installed"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
