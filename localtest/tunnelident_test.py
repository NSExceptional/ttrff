#!/usr/bin/env python3
# localtest/tunnelident_test.py -- OFFLINE validation of the TUNNEL-WALK-BY-OBJECT-IDENTITY logic (the
# fix in frida/trampoline_inject.py's modset branch for the street-tunnel walk). The street-tunnel walk
# interval is localAvatar.tunnelTrack -- an UNNAMED Sequence (auto-named vlt8e0d5a85-<n>) built + started
# by the HASHED handlers handleTunnelOut/handleTunnelIn and stored under a HASHED attr. It matches NO
# name-table entry and its spawn co_name is hashed, so the mod identifies it by OBJECT IDENTITY: in the
# MetaInterval.start wrap-after the starting interval IS localAvatar.<tunnelAttr>. The (hashed) attr is
# auto-discovered on the first IRIS-CORRELATED walk (handleTunnelIn calls base.transitions.irisIn right
# before start(), so an irisTask fires in the same handler/frame window) then PINNED so every later walk
# (both directions) scales by identity alone.
#
# This test drives the SAME logic (mirrored faithfully) against stock arm64 CPython 3.8 with a mock
# localAvatar + mock MetaInterval, asserting:
#   A. an avatar-owned UNNAMED interval that starts with NO iris is NOT scaled and does NOT pin an attr
#      (the iris gate prevents false positives on ordinary toon intervals);
#   B. an irisTask start is scaled by NAME (transitions) and STAMPS the iris window (not treated as tunnel);
#   C. a NON-avatar-owned unnamed interval that starts WITH the iris recent is NOT discovered (ownership
#      gate: it is not a value in localAvatar's dict);
#   D. the ARRIVAL tunnel track (avatar.<HASHED attr>, unnamed) started right after an iris is DISCOVERED
#      by identity -> the discovered attr is EXACTLY the hashed attr (not 'track'/'someIval'/...), a
#      [TUNNELATTR] event fires, and it is scaled by the TUNNEL factor (4.0), group 'tunnel';
#   E. the DEPARTURE tunnel track (same hashed attr, reassigned) started with NO iris is still scaled via
#      the FAST PATH (pinned attr identity) -- proving both directions / subsequent walks scale with no
#      second round;
#   F. the teleport self.track (avatar-owned but NAMED teleportOut-<id>, under a DIFFERENT attr) is scaled
#      by NAME (teleport), NEVER by tunnel identity, and never repins the tunnel attr;
#   G. a config-PINNED attr (tunnel_identity.attr / TTRMOD_TUNNEL_ATTR) scales its interval via the fast
#      path with NO iris and NO discovery;
#   H. JUNK-SAFE: getName() raising / returning a non-string passes through, is not scaled, tstate clean;
#   I. tstate clean after every case; original start() called once each; revert restores it.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/tunnelident_test.py frida/run-injector.sh
#     (or: /path/to/arm64-frida-python localtest/tunnelident_test.py)

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

# name->factor table (enough to route the named decoys: iris + teleport). Deliberately contains a
# literal "tunnel" NAME entry to prove the walk is NOT caught by it (its name is the hashed vlt8e0d5a85).
TABLE = [
    {"match": "teleportOut", "factor": 4.0, "group": "teleport",    "prefix": False},
    {"match": "teleportIn",  "factor": 4.0, "group": "teleport",    "prefix": False},
    {"match": "irisTask",    "factor": 3.0, "group": "transitions", "prefix": False},
    {"match": "openBook",    "factor": 3.0, "group": "book",        "prefix": False},
    {"match": "tunnel",      "factor": 4.0, "group": "tunnel",      "prefix": False},
]

# the mod does NOT know this name -- it must DISCOVER it by identity. A hashed stand-in for tunnelTrack.
HASHED_ATTR = "vlt9c1e77a3"
# a DIFFERENT hashed attr, pre-pinned from config for the config-pin sub-test (assertion G).
PINNED_ATTR = "vlt00pinned0"
TUNNEL_FACTOR = 4.0


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


# Mock localAvatar + mock Panda MetaInterval. getName() returns the name (or misbehaves for junk); start()
# returns a sentinel (pass-through check) and RESETS play_rate (hence wrap-AFTER); setPlayRate records.
# append/clearIntervals are the Python-only discriminators for the signature scan. The avatar's stable
# decoys (teleport self.track under 'track', an ordinary interval under 'someIval', the config-pin
# interval under PINNED_ATTR, a non-interval attr) are pre-populated; the agent reassigns the HASHED
# tunnel attr per tunnel drive (mirroring self.tunnelTrack = Sequence(...); .start()).
TARGET_PROG = r"""
import sys, types, time, builtins

def _make_metaival():
    class MetaIntervalMock:
        def __init__(self, name, sentinel, junk=None):
            self._name = name; self._sentinel = sentinel; self._junk = junk
            self.play_rate = 1.0; self.spr_count = 0; self.started = 0
        def getName(self):
            if self._junk == 'raise': raise RuntimeError('boom in getName')
            if self._junk == 'nonstr': return 12345          # non-string -> AsUTF8 must fail-safe
            return self._name
        def start(self, startT=0.0, endT=-1.0, playRate=1.0):
            self.started += 1; self.play_rate = playRate; return self._sentinel
        def setPlayRate(self, r): self.spr_count += 1; self.play_rate = float(r)
        def append(self, ival): pass
        def clearIntervals(self, *a, **k): pass
        def extend(self, ivals): pass
    return MetaIntervalMock

_mmod = types.ModuleType("vlt1609aac2.vltinterval.vltMetaInterval")
_mmod.MetaInterval = _make_metaival()
sys.modules["vlt1609aac2.vltinterval.vltMetaInterval"] = _mmod
MI = _mmod.MetaInterval

# the local toon (a plain object with a normal instance __dict__)
class LocalToonMock:
    pass
localAvatar = LocalToonMock()

# intervals (globals in __main__, fetched by the agent):
iris          = MI("irisTask", 800)                 # name-matched (transitions); stamps the iris window
teleport      = MI("teleportOut-112139724", 801)    # name-matched (teleport); avatar-owned decoy (self.track)
tunnel_out    = MI("vlt8e0d5a85-17", 802)           # DEPARTURE walk (hashed auto-name); fast-path, no iris
tunnel_in     = MI("vlt8e0d5a85-23", 803)           # ARRIVAL walk (hashed auto-name); iris-correlated discovery
noniris_ival  = MI("vlt8e0d5a85-99", 804)           # avatar-owned UNNAMED interval, NO iris -> must NOT scale
unrelated     = MI("stareAt-ToonEyes-5", 805)       # NOT avatar-owned, unnamed-unknown -> must NOT scale
config_pin    = MI("vltPREPIN-1", 810)              # config-pinned attr fast-path (assertion G)
junk_raise    = MI("jr", 808, junk='raise')
junk_nonstr   = MI("jn", 809, junk='nonstr')

# stable decoys on the avatar (the agent reassigns only the HASHED tunnel attr per tunnel drive):
localAvatar.track      = teleport        # teleport self.track (a DIFFERENT attr than the tunnel track)
localAvatar.someIval   = noniris_ival    # an ordinary avatar-owned interval (no iris -> not the tunnel)
setattr(localAvatar, "%s", config_pin)   # PINNED_ATTR -> config_pin (config-pin sub-test)
localAvatar.someState  = 42              # a non-interval attr (scan must skip it)

# base.localAvatar -- resolved by the agent exactly like the live mod (builtins.base.localAvatar)
builtins.base = types.SimpleNamespace(localAvatar=localAvatar)

t = time.time()
while time.time() - t < 30:
    s = sum(i*i for i in range(300))
""" % (PINNED_ATTR,)


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
        scaledGroups: {}, scaledNames: [],
        // tunnel-identity config (mirrors the shipping spec.tunnel). tunnelAttr STARTS NULL (discovery
        // mode); cfgPinnedAttr is applied manually in the config-pin sub-test (assertion G).
        tunnelEnabled: true, tunnelAttr: null, tunnelFactor: p.tunnel_factor,
        cfgHashedAttr: p.hashed_attr, cfgPinnedAttr: p.pinned_attr,
        irisWindowMs: p.iris_window_ms, lastIrisMs: 0, localAvatar: null, localAvatarDict: null,
        tunnelAttrLog: [],
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

      // ---- TUNNEL-IDENTITY helpers (mirror frida/trampoline_inject.py) ----
      // resolve + cache builtins.base.localAvatar and its instance __dict__ (stable identity).
      ST.resolveLocalAvatar = function(){
        try {
          if (ST.localAvatar && !ST.localAvatar.isNull()) return ST.localAvatar;
          var md = ST.GetModuleDict(); if (md.isNull()) return ptr(0);
          var bi = ST.DictGetStr(md, cstr('builtins'));            // borrowed
          if (bi.isNull()){ ST.clearExc(); return ptr(0); }
          var b = ST.GetAttrStr(bi, cstr('base'));
          var av = ptr(0);
          if (!b.isNull()){ av = ST.GetAttrStr(b, cstr('localAvatar')); if (av.isNull()) ST.clearExc(); }
          else { ST.clearExc(); }
          if (av.isNull()){ av = ST.GetAttrStr(bi, cstr('localAvatar')); if (av.isNull()){ ST.clearExc(); return ptr(0); } }
          ST.localAvatar = av; ST.keep.push(av);
          var d = ST.GetAttrStr(av, cstr('__dict__'));
          if (!d.isNull()){ ST.localAvatarDict = d; ST.keep.push(d); } else { ST.clearExc(); ST.localAvatarDict = null; }
          return av;
        } catch(e){ ST.clearExc(); return ptr(0); }
      };
      ST.isIrisName = function(nm){ return !!(nm && nm.toLowerCase().indexOf('iris') >= 0); };
      ST.scaleTunnel = function(inst, nm, why){
        var ok = ST.setPlayRate(inst, ST.tunnelFactor);
        if (ok){ ST.scaledGroups['tunnel'] = (ST.scaledGroups['tunnel']||0) + 1; ST.scaledNames.push(nm); }
        ST.clearExc(); return ok;
      };
      ST.tunnelFastPath = function(inst, nm){
        try {
          if (!ST.tunnelAttr) return false;
          var av = ST.resolveLocalAvatar(); if (av.isNull()) return false;
          var d = ST.localAvatarDict; if (!d || d.isNull()) return false;
          var v = ST.DictGetStr(d, cstr(ST.tunnelAttr));           // borrowed
          if (v.isNull()){ ST.clearExc(); return false; }
          if (!v.equals(inst)) return false;
          return ST.scaleTunnel(inst, nm, 'pinned');
        } catch(e){ ST.clearExc(); return false; }
      };
      ST.tunnelDiscover = function(inst, nm){
        try {
          if ((Date.now() - (ST.lastIrisMs||0)) > ST.irisWindowMs) return false;   // not iris-correlated
          var av = ST.resolveLocalAvatar(); if (av.isNull()) return false;
          var d = ST.localAvatarDict; if (!d || d.isNull()) return false;
          var it = ST.GetIter(d); if (it.isNull()){ ST.clearExc(); return false; }
          var k, foundKey = null;
          while (!(k = ST.IterNext(it)).isNull()){
            var v = ST.DictGetItem(d, k);                          // borrowed value
            if (!v.isNull() && v.equals(inst)){ try { foundKey = ST.AsUTF8(k).readCString(); } catch(e){ foundKey = null; } break; }
          }
          ST.clearExc();
          if (foundKey === null) return false;
          ST.tunnelAttr = foundKey;                                // PIN
          ST.tunnelAttrLog.push(foundKey);
          return ST.scaleTunnel(inst, nm, 'discovered');
        } catch(e){ ST.clearExc(); return false; }
      };

      // applyModset -- mirrors the modset branch ORDER in trampoline_inject.py:
      // iris stamp -> tunnel fast path -> name table -> tunnel discovery -> unmatched log.
      ST.applyModset = function(inst){
        try {
          var gm2 = ST.GetAttrStr(inst, cstr('getName'));
          if (gm2.isNull()){ ST.clearExc(); return null; }
          var nm4 = ST.Call(gm2, ST.TupleNew(0), ptr(0));
          if (nm4.isNull()){ ST.clearExc(); return null; }
          var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
          if (nms4 === null){ ST.clearExc(); return null; }
          if (ST.tunnelEnabled){
            if (ST.isIrisName(nms4)) ST.lastIrisMs = Date.now();
            if (ST.tunnelFastPath(inst, nms4)){ ST.clearExc(); return 'tunnel'; }
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
            ST.clearExc(); return matched.group;
          }
          if (ST.tunnelEnabled && !ST.tunnelAttr){
            if (ST.tunnelDiscover(inst, nms4)){ ST.clearExc(); return 'tunnel'; }
          }
          if (ST.logOn && ST.log.indexOf(nms4) < 0) ST.log.push(nms4);
          ST.clearExc(); return null;
        } catch(e){ ST.clearExc(); return null; }
      };
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

      // signature scan (verbatim shape from trampoline_inject.py / modset_test.py)
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

            // discover the Python MetaInterval by start+setPlayRate+append+clearIntervals and wrap start()
            var sig = ['start','setPlayRate','append','clearIntervals'];
            var found = ST.scanBySignature(md, sig);
            var names = {}; for (var i=0;i<found.length;i++){ names[found[i].class_name] = found[i]; }
            R.found_names = Object.keys(names).sort();
            var trec = names['MetaIntervalMock'];
            if (!trec){ send({t:'done', r:{ok:false, stage:'MetaIntervalMock not discovered', found:R.found_names}}); return; }
            var cls = trec.clsPtr; ST.keep.push(cls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(cls, mnStart); ST.keep.push(origStart);
            var im = ST.makeWrapAfter(origStart);
            ST.SetAttrStr(cls, mnStart, im);

            var av = ST.resolveLocalAvatar();
            R.avatar_resolved = !av.isNull();

            // fetch interval globals once
            function G(n){ return ST.GetAttrStr(main, cstr(n)); }
            var iris = G('iris'), teleport = G('teleport'), tunnel_out = G('tunnel_out'),
                tunnel_in = G('tunnel_in'), noniris = G('noniris_ival'), unrelated = G('unrelated'),
                config_pin = G('config_pin'), junk_raise = G('junk_raise'), junk_nonstr = G('junk_nonstr');
            ST.keep.push(iris); ST.keep.push(teleport); ST.keep.push(tunnel_out); ST.keep.push(tunnel_in);
            ST.keep.push(noniris); ST.keep.push(unrelated); ST.keep.push(config_pin);

            function startIt(inst){
              var b = ST.GetAttrStr(inst, cstr('start'));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              return res;
            }
            function snap(inst, expectSentinel, res){
              var out = {
                passed_through: (!res.isNull() && L(res) === expectSentinel),
                started_once: (L(ST.GetAttrStr(inst, cstr('started'))) === 1),
                setPlayRate_calls: L(ST.GetAttrStr(inst, cstr('spr_count'))),
                play_rate: D(ST.GetAttrStr(inst, cstr('play_rate'))),
                tstate_clean: ST.Occurred().isNull(),
              };
              ST.clearExc();
              return out;
            }
            // reassign av.<attr> = inst (mirror: self.tunnelTrack = Sequence(...))
            function assign(attr, inst){ ST.SetAttrStr(av, cstr(attr), inst); ST.clearExc(); }

            // A. avatar-owned UNNAMED interval, NO iris -> not scaled, no pin (iris gate)
            ST.lastIrisMs = 0;
            R.A_noniris = snap(noniris, 804, startIt(noniris));
            R.A_attr_after = ST.tunnelAttr;                  // must still be null

            // B. iris start -> scaled by NAME (transitions); stamps the iris window
            R.B_iris = snap(iris, 800, startIt(iris));

            // C. NON-avatar-owned unnamed interval, iris recent -> not discovered (ownership gate)
            ST.lastIrisMs = Date.now();                      // iris IS recent -> isolate the ownership gate
            R.C_unrelated = snap(unrelated, 805, startIt(unrelated));
            R.C_attr_after = ST.tunnelAttr;                  // must still be null

            // D. ARRIVAL walk: iris fires in the same handler (handleTunnelIn's synchronous irisIn), then
            // assign the hashed attr + start -> DISCOVER by identity. (Set the stamp directly rather than
            // re-starting the iris interval, so the transitions group is not double-counted.)
            ST.lastIrisMs = Date.now();
            assign(ST.cfgHashedAttr, tunnel_in);             // self.tunnelTrack = Sequence(...)
            R.D_tunnel_in = snap(tunnel_in, 803, startIt(tunnel_in));
            R.D_discovered_attr = ST.tunnelAttr;             // must == HASHED_ATTR

            // E. DEPARTURE walk: reassign same hashed attr, NO iris -> FAST PATH (pinned identity)
            ST.lastIrisMs = 0;
            assign(ST.cfgHashedAttr, tunnel_out);
            R.E_tunnel_out = snap(tunnel_out, 802, startIt(tunnel_out));

            // F. teleport self.track (avatar-owned but NAMED, different attr) -> scaled by NAME, not tunnel
            ST.lastIrisMs = 0;
            R.F_teleport = snap(teleport, 801, startIt(teleport));
            R.F_attr_after = ST.tunnelAttr;                  // must still be HASHED_ATTR (not 'track')

            // G. config-PINNED attr -> fast path, no iris, no discovery
            ST.tunnelAttr = ST.cfgPinnedAttr;                // simulate tunnel_identity.attr / TTRMOD_TUNNEL_ATTR
            ST.lastIrisMs = 0;
            R.G_config_pin = snap(config_pin, 810, startIt(config_pin));

            // H. junk-safe
            R.H_junk_raise  = snap(junk_raise, 808, startIt(junk_raise));
            R.H_junk_nonstr = snap(junk_nonstr, 809, startIt(junk_nonstr));

            R.scaled_groups = ST.scaledGroups;
            R.scaled_names  = ST.scaledNames.slice().sort();
            R.logged_names  = ST.log.slice().sort();
            R.tunnelattr_log = ST.tunnelAttrLog.slice();

            ST.SetAttrStr(cls, mnStart, origStart);          // revert
            R.tstate_clean_after_revert = ST.Occurred().isNull();
            ST.clearExc();

            function scaledAs(o, f){ return o.passed_through && o.started_once && o.setPlayRate_calls === 1 && o.play_rate === f && o.tstate_clean; }
            function untouched(o){ return o.passed_through && o.started_once && o.setPlayRate_calls === 0 && o.play_rate === 1.0 && o.tstate_clean; }

            R.ok = !!(
              R.avatar_resolved &&
              // A: avatar-owned but no iris -> untouched, no pin
              untouched(R.A_noniris) && (R.A_attr_after === null) &&
              // B: iris scaled by name (transitions 3.0)
              scaledAs(R.B_iris, 3.0) &&
              // C: not avatar-owned -> untouched, still no pin
              untouched(R.C_unrelated) && (R.C_attr_after === null) &&
              // D: arrival discovered by identity -> scaled tunnel 4.0, attr == HASHED_ATTR
              scaledAs(R.D_tunnel_in, ST.tunnelFactor) && (R.D_discovered_attr === ST.cfgHashedAttr) &&
              // E: departure via fast path -> scaled tunnel 4.0 (no iris)
              scaledAs(R.E_tunnel_out, ST.tunnelFactor) &&
              // F: teleport scaled by NAME (teleport 4.0), tunnel attr unchanged
              scaledAs(R.F_teleport, 4.0) && (R.F_attr_after === ST.cfgHashedAttr) &&
              // G: config-pinned fast path -> scaled tunnel 4.0
              scaledAs(R.G_config_pin, ST.tunnelFactor) &&
              // H: junk untouched + clean
              untouched(R.H_junk_raise) && untouched(R.H_junk_nonstr) &&
              // groups: tunnel = D+E+G = 3; teleport = 1 (F); transitions = 1 (B); NO teleport-as-tunnel
              R.scaled_groups.tunnel === 3 && R.scaled_groups.teleport === 1 &&
              R.scaled_groups.transitions === 1 &&
              // exactly one attr discovered, and it is the hashed tunnel attr (never 'track'/'someIval')
              R.tunnelattr_log.length === 1 && R.tunnelattr_log[0] === ST.cfgHashedAttr &&
              // unmatched log = the two decoys that reached it (noniris + unrelated); junk never logged
              R.logged_names.indexOf('vlt8e0d5a85-99') >= 0 &&
              R.logged_names.indexOf('stareAt-ToonEyes-5') >= 0 &&
              R.logged_names.length === 2 &&
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
    print("[tunnelident] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
                    "table": TABLE, "hashed_attr": HASHED_ATTR, "pinned_attr": PINNED_ATTR,
                    "tunnel_factor": TUNNEL_FACTOR, "iris_window_ms": 200})
    if not init.get("ok"):
        print("[tunnelident] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[tunnelident] hook never fired in 20s")
    elif box.get("detached"):
        print("[tunnelident] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[tunnelident] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[tunnelident] target_alive=%s" % alive)
    print("[tunnelident] VERDICT: %s" % (
        "PASS -- the street-tunnel walk is identified by OBJECT IDENTITY (localAvatar.tunnelTrack): "
        "discovered on the iris-correlated arrival (attr auto-found + [TUNNELATTR]), scaled x4 tunnel in "
        "BOTH directions (arrival by discovery, departure by the pinned fast path), config-pin works with "
        "no iris; the teleport self.track scales by NAME only (never as tunnel) and an avatar-owned "
        "no-iris interval + a non-avatar interval are left untouched; junk-safe; tstate clean; reverted"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
