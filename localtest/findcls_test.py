#!/usr/bin/env python3
# localtest/findcls_test.py -- OFFLINE validation of the "find class by method signature" scan
# (the robust replacement for resolving a vault-HASHED target class by module/name). The engine
# loads LocalToon under a fully hashed module key (vlt24ab6c6d.<hash>.<hash>), so name-based
# resolution fails. Instead we locate the target CLASS by the METHODS it defines.
#
# The scan (ST.scanBySignature / ST.classSignature -- byte-for-byte the same code that ships in
# frida/trampoline_inject.py) is PURE READ-ONLY C-API:
#   - iterate sys.modules; for each module, iterate its __dict__;
#   - for each value that IS a type (PyType_Check: Py_TYPE(v).tp_flags TYPE_SUBCLASS bit,
#     byte @ tp+0xab bit7), walk the type's MRO (tp_mro @ +0x158) and, per requested method,
#     record whether it is defined DIRECTLY on the class (MRO[0]) or INHERITED (and from which
#     base). Membership is tested against each base's tp_dict (@ +0x108) via PyDict_GetItemString.
#   - report every class where ALL requested methods are present: (possibly hashed) module key,
#     the attribute name it's bound to, the class __name__ (tp_name @ +0x18), direct-vs-inherited
#     per method, and the match count. Deduped by class pointer (a class re-exported under several
#     module keys is ONE record with multiple bindings).
#
# We cannot run this against the live binary, so we build the EQUIVALENT on a stock arm64 CPython
# 3.8 we own (identical PyTypeObject layout: tp_dict +0x108, tp_mro +0x158, tp_flags byte +0xab,
# ob_type +8 -- only absolute addresses differ). We register a real target class under a
# hashed-looking sys.modules key plus decoys (only one of the methods / none), inheritance and
# mixed-inheritance cases, an attr-name != __name__ divergence case, and a junk module full of
# non-type values (ints, functions, str, bytes, a module, a list). We assert the scan finds EXACTLY
# the classes that define ALL requested methods, attributes them correctly, and never
# false-positives or crashes on the junk.
#
# We also validate the mod1 self-discovery -> wrap path end-to-end: use the scan to FIND the class,
# install the wrap-after trampoline on its two methods, call one, and confirm original-once +
# result-passed-through + setPlayRate(5.0) on the HIT class, and a clean tstate (no leaked
# exception) on a MISS class whose method never sets the interval attr.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/findcls_test.py frida/run-injector.sh
#   (or:  /opt/homebrew/bin/python3.13 localtest/findcls_test.py   if frida is on the PATH python)

import sys, os, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")

SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyImport_GetModuleDict":    "_PyImport_GetModuleDict",   # -> borrowed sys.modules
    "PyImport_AddModule":        "_PyImport_AddModule",       # -> __main__ (for the instance)
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyObject_SetAttrString":    "_PyObject_SetAttrString",
    "PyObject_Call":             "_PyObject_Call",
    "PyDict_GetItem":            "_PyDict_GetItem",           # borrowed by key object
    "PyDict_GetItemString":      "_PyDict_GetItemString",     # borrowed by C string
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
    "PyInstanceMethod_Type":     "_PyInstanceMethod_Type",    # DATA
    "PyFloat_Type":              "_PyFloat_Type",             # DATA
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


# Mocks live in the target's __main__. Target classes are built inside factories and registered ONLY
# in purpose-built sys.modules entries, so we control the exact module key + attribute name and don't
# pollute __main__ (except the `localtoon`/`notrack` INSTANCES used for the wrap-call test).
TARGET_PROG = r"""
import sys, types, time

class MockInterval:
    def __init__(self, tag=""):
        self.tag = tag
        self.spr_count = 0
        self.last_rate = 0.0
    def setPlayRate(self, f):
        self.spr_count += 1
        self.last_rate = float(f)

# ---- the REAL target: both methods DIRECT, starts a `tunnelTrack` interval (the HIT case) --------
def _make_localtoon():
    class LocalToon:
        in_count = 0
        out_count = 0
        def handleTunnelIn(self, *a, **k):
            LocalToon.in_count += 1
            self.tunnelTrack = MockInterval("tunnel-in")
            return 111
        def handleTunnelOut(self, *a, **k):
            LocalToon.out_count += 1
            self.tunnelTrack = MockInterval("tunnel-out")
            return 222
    return LocalToon

# HASHED-looking module key, exactly like the vault (vlt24ab6c6d.<hash>.<hash>).
_hashed = types.ModuleType("vlt24ab6c6d.vlt5e2c0e32.vltb0b0b0b0")
_hashed.LocalToon = _make_localtoon()
sys.modules["vlt24ab6c6d.vlt5e2c0e32.vltb0b0b0b0"] = _hashed
localtoon = _hashed.LocalToon()      # instance in __main__ for the wrap-call HIT test

# ---- a MISS target: both methods DIRECT but the method NEVER sets the interval attr -------------
def _make_notrack():
    class NoTrackToon:
        seen = 0
        def handleTunnelIn(self, *a, **k):
            NoTrackToon.seen += 1
            return 333               # note: never sets self.tunnelTrack
        def handleTunnelOut(self, *a, **k):
            NoTrackToon.seen += 1
            return 444
    return NoTrackToon
_ntmod = types.ModuleType("vlt24ab6c6d.vltdeadbeef.vltnotrack")
_ntmod.NoTrackToon = _make_notrack()
sys.modules["vlt24ab6c6d.vltdeadbeef.vltnotrack"] = _ntmod
notrack = _ntmod.NoTrackToon()       # instance in __main__ for the wrap-call MISS test

# ---- attr-name != __name__ divergence: bound as `TheToon`, __name__ is `TunnelDoorMock` ---------
def _make_door():
    class TunnelDoorMock:
        def handleTunnelIn(self, *a, **k): return 1
        def handleTunnelOut(self, *a, **k): return 2
    return TunnelDoorMock
_dmod = types.ModuleType("vlt_beef.door")
_dmod.TheToon = _make_door()         # attribute name deliberately != class __name__
sys.modules["vlt_beef.door"] = _dmod

# ---- inheritance: InheritsBoth inherits BOTH methods from TunnelBase ------------------------------
def _make_inh():
    class TunnelBase:
        def handleTunnelIn(self, *a, **k): return 1
        def handleTunnelOut(self, *a, **k): return 2
    class InheritsBoth(TunnelBase):
        pass
    return TunnelBase, InheritsBoth
_imod = types.ModuleType("vlt_beef.inh")
_imod.TunnelBase, _imod.InheritsBoth = _make_inh()
sys.modules["vlt_beef.inh"] = _imod

# ---- mixed: HalfDerived defines In DIRECTLY, inherits Out from HalfBase ---------------------------
def _make_mixed():
    class HalfBase:
        def handleTunnelOut(self, *a, **k): return 2      # only Out -> HalfBase is NOT a full match
    class HalfDerived(HalfBase):
        def handleTunnelIn(self, *a, **k): return 1       # In direct, Out inherited
    return HalfBase, HalfDerived
_mmod = types.ModuleType("mixmod")
_mmod.HalfBase, _mmod.HalfDerived = _make_mixed()
sys.modules["mixmod"] = _mmod

# ---- decoys: ONLY one of the two methods -> must NOT be a full match ------------------------------
def _make_onlyin():
    class OnlyIn:
        def handleTunnelIn(self, *a, **k): return 1
    return OnlyIn
def _make_onlyout():
    class OnlyOut:
        def handleTunnelOut(self, *a, **k): return 2
    return OnlyOut
def _make_neither():
    class Neither:
        def foo(self, *a, **k): return 0
    return Neither
_dec = types.ModuleType("decoymod")
_dec.OnlyIn = _make_onlyin()
_dec.OnlyOut = _make_onlyout()
_dec.Neither = _make_neither()
sys.modules["decoymod"] = _dec

# ---- junk module: __dict__ full of NON-type values -> must be skipped, must not crash ------------
_junk = types.ModuleType("junkmod")
_junk.an_int = 42
_junk.a_func = lambda: 1
_junk.a_str = "hello"
_junk.a_bytes = b"xyz"
_junk.a_list = [1, 2, 3]
_junk.a_dict = {"k": "v"}
_junk.a_module = sys
_junk.a_none = None
_junk.a_neither_type = _make_neither()   # a type, but with no target methods
sys.modules["junkmod"] = _junk

t = time.time()
while time.time() - t < 30:
    s = sum(i*i for i in range(300))   # busy: forces C->Python frame-evals so the hook fires
"""


# The AGENT below carries the SHARED scan helpers (ST.classSignature / ST.scanBySignature) VERBATIM
# from frida/trampoline_inject.py, plus the wrap-after machinery from wrapafter_test.py. Everything
# runs deterministically from inside the frame-eval hook (once), GIL held, main thread.
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
        base: base, done:false, keep:[],
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
      ST.pack1 = function(o){ return ST.TuplePack(1, o); };   // increfs o (does not steal), like wrapafter_test
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
      ST.applyAfter = function(inst, spec, factorVal){
        try {
          if (spec.mode === 'attr'){
            var iv = ST.GetAttrStr(inst, cstr(spec.attr));
            if (iv.isNull()){ ST.clearExc(); return 0; }
            return ST.setPlayRate(iv, factorVal) ? 1 : 0;
          }
        } catch(e){ ST.clearExc(); }
        return 0;
      };
      ST.makeWrapAfter = function(orig, spec, factorVal){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);
          if (result.isNull()){ return result; }
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            if (!inst.isNull()) ST.applyAfter(inst, spec, factorVal);
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

      // ===================== SHARED with frida/trampoline_inject.py (verbatim) =====================
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

      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },

  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function () {
          if (ST.done) return; ST.done = true;                 // once, main thread, GIL held
          function serial(list){
            return list.map(function(r){
              return { class_name:r.class_name, cls_ptr:r.clsPtr.toString(), match_count:r.match_count,
                       all_direct:r.all_direct, methods:r.methods, bindings:r.bindings };
            });
          }
          function L(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsLong(o); ST.clearExc(); return v.toNumber ? v.toNumber() : v; }
          function D(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsDouble(o); ST.clearExc(); return v; }
          try {
            var R = {};
            var md = ST.GetModuleDict();                       // borrowed sys.modules
            if (md.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }

            // ---------- scenario A: scan for BOTH methods ----------
            var both = ST.scanBySignature(md, ['handleTunnelIn','handleTunnelOut']);
            R.both = serial(both);
            var names = {}; for (var i=0;i<both.length;i++){ names[both[i].class_name] = both[i]; }
            R.both_names = Object.keys(names).sort();

            // mod1's EXACT selection filter: prefer the classes where ALL methods are DIRECT (defining
            // classes -> clean revert). Confirm it keeps LocalToon/NoTrackToon and drops the
            // inherited-only / mixed classes.
            var directSel = both.filter(function(r){ return r.all_direct; });
            R.direct_names = directSel.map(function(r){ return r.class_name; }).sort();
            R.selection_pass = (R.direct_names.indexOf('LocalToon') >= 0 && R.direct_names.indexOf('NoTrackToon') >= 0 &&
                                R.direct_names.indexOf('TunnelDoorMock') >= 0 && R.direct_names.indexOf('TunnelBase') >= 0 &&
                                R.direct_names.indexOf('InheritsBoth') < 0 && R.direct_names.indexOf('HalfDerived') < 0);

            // ---------- scenario B (widen): scan for just handleTunnelIn ----------
            var one = ST.scanBySignature(md, ['handleTunnelIn']);
            var onenames = {}; for (var j=0;j<one.length;j++){ onenames[one[j].class_name] = true; }
            R.one_names = Object.keys(onenames).sort();

            // ---------- scenario D (discovery): substring scan over method names ----------
            var sub = ST.scanBySubstr(md, ['unnel']);
            var subnames = {}; for (var q=0;q<sub.length;q++){ subnames[sub[q].class_name] = sub[q]; }
            R.substr_names = Object.keys(subnames).sort();
            R.substr_localtoon_hits = subnames['LocalToon'] ? subnames['LocalToon'].hits.slice().sort() : null;
            R.substr_pass = !!(subnames['LocalToon'] &&
                               subnames['LocalToon'].hits.indexOf('handleTunnelIn') >= 0 &&
                               subnames['LocalToon'].hits.indexOf('handleTunnelOut') >= 0 &&
                               subnames['OnlyIn'] && subnames['OnlyOut'] && subnames['HalfBase'] &&
                               R.substr_names.indexOf('InheritsBoth') < 0 &&   // own-dict only: inherited not re-reported
                               R.substr_names.indexOf('Neither') < 0);

            // ---------- scenario C: self-discover -> wrap (HIT = LocalToon, MISS = NoTrackToon) ----------
            var main = ST.AddModule(cstr('__main__'));
            function wrapAndCall(clsRec, instName){
              var cls = clsRec.clsPtr;
              var origs = {};
              var mnames = Object.keys(clsRec.methods);
              for (var a=0;a<mnames.length;a++){
                var mn = cstr(mnames[a]); ST.keep.push(mn);
                var orig = ST.GetAttrStr(cls, mn); if (orig.isNull()){ ST.clearExc(); continue; }
                ST.keep.push(orig); origs[mnames[a]] = {mn:mn, orig:orig};
                var im = ST.makeWrapAfter(orig, {mode:'attr', attr:'tunnelTrack'}, 5.0);
                if (!im.isNull()) ST.SetAttrStr(cls, mn, im);
              }
              var inst = ST.GetAttrStr(main, cstr(instName));
              var boundIn = inst.isNull()? ptr(0) : ST.GetAttrStr(inst, cstr('handleTunnelIn'));
              var res = boundIn.isNull()? ptr(0) : ST.Call(boundIn, ST.TupleNew(0), ptr(0));
              var res_long = res.isNull()? null : L(res);
              var exc_after = ST.Occurred().isNull();           // MUST be clean after our wrapper returns
              // revert
              for (var b=0;b<mnames.length;b++){ var e = origs[mnames[b]]; if (e) ST.SetAttrStr(cls, e.mn, e.orig); }
              ST.clearExc();
              return { inst:inst, res_long:res_long, exc_after_clean:exc_after };
            }

            var hit = wrapAndCall(names['LocalToon'], 'localtoon');
            var lt = hit.inst;
            var in_count = L(ST.GetAttrStr(lt, cstr('in_count')));
            var track = ST.GetAttrStr(lt, cstr('tunnelTrack'));
            R.hit = { found: !!names['LocalToon'],
                      orig_called_once: (in_count === 1),
                      result_passed_through: (hit.res_long === 111),
                      setPlayRate_calls: track.isNull()? null : L(ST.GetAttrStr(track, cstr('spr_count'))),
                      setPlayRate_factor: track.isNull()? null : D(ST.GetAttrStr(track, cstr('last_rate'))),
                      tstate_clean_after: hit.exc_after_clean };
            ST.clearExc();

            var miss = wrapAndCall(names['NoTrackToon'], 'notrack');
            var nt = miss.inst;
            R.miss = { found: !!names['NoTrackToon'],
                       orig_called_once: (L(ST.GetAttrStr(nt, cstr('seen'))) === 1),
                       result_passed_through: (miss.res_long === 333),
                       no_track_attr: ST.GetAttrStr(nt, cstr('tunnelTrack')).isNull(),
                       tstate_clean_after: miss.exc_after_clean };
            ST.clearExc();

            // ---------- verdicts ----------
            var EXP = ['HalfDerived','InheritsBoth','LocalToon','NoTrackToon','TunnelBase','TunnelDoorMock'];
            R.scenarioA_pass = (JSON.stringify(R.both_names) === JSON.stringify(EXP));
            var lt_ok = names['LocalToon'] && names['LocalToon'].all_direct &&
                        names['LocalToon'].methods.handleTunnelIn.where === 'direct' &&
                        names['LocalToon'].methods.handleTunnelOut.where === 'direct' &&
                        names['LocalToon'].bindings.some(function(b){ return /vlt24ab6c6d/.test(b.module) && b.attr === 'LocalToon'; });
            var door = names['TunnelDoorMock'];
            var door_ok = door && door.bindings.some(function(b){ return b.module === 'vlt_beef.door' && b.attr === 'TheToon'; }) &&
                          door.class_name === 'TunnelDoorMock';   // attr 'TheToon' != __name__ 'TunnelDoorMock'
            var inh = names['InheritsBoth'];
            var inh_ok = inh && inh.methods.handleTunnelIn.where === 'inherited' && inh.methods.handleTunnelIn.base === 'TunnelBase' &&
                         inh.methods.handleTunnelOut.where === 'inherited' && inh.methods.handleTunnelOut.base === 'TunnelBase';
            var half = names['HalfDerived'];
            var half_ok = half && half.methods.handleTunnelIn.where === 'direct' &&
                          half.methods.handleTunnelOut.where === 'inherited' && half.methods.handleTunnelOut.base === 'HalfBase';
            var no_fp = (R.both_names.indexOf('OnlyIn') < 0 && R.both_names.indexOf('OnlyOut') < 0 &&
                         R.both_names.indexOf('Neither') < 0 && R.both_names.indexOf('HalfBase') < 0);
            R.attribution_pass = !!(lt_ok && door_ok && inh_ok && half_ok && no_fp);
            R.scenarioB_pass = (R.one_names.indexOf('OnlyIn') >= 0 && R.one_names.indexOf('OnlyOut') < 0 &&
                                R.one_names.indexOf('Neither') < 0);
            R.hit_pass = !!(R.hit.found && R.hit.orig_called_once && R.hit.result_passed_through &&
                            R.hit.setPlayRate_calls === 1 && R.hit.setPlayRate_factor === 5.0 && R.hit.tstate_clean_after);
            R.miss_pass = !!(R.miss.found && R.miss.orig_called_once && R.miss.result_passed_through &&
                             R.miss.no_track_attr && R.miss.tstate_clean_after);
            R.ok = !!(R.scenarioA_pass && R.attribution_pass && R.scenarioB_pass &&
                      R.selection_pass && R.substr_pass && R.hit_pass && R.miss_pass);

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
    print("[findcls] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib})
    if not init.get("ok"):
        print("[findcls] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[findcls] hook never fired in 20s")
    elif box.get("detached"):
        print("[findcls] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[findcls] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[findcls] target_alive=%s" % alive)
    print("[findcls] VERDICT: %s" % (
        "PASS -- scan finds EXACTLY the classes defining all requested methods (direct+inherited "
        "attributed correctly, attr!=__name__ handled), no false-positives, junk-safe; widen surfaces "
        "single-method decoys; self-discover->wrap HIT (orig-once + setPlayRate(5.0) pass-through) and "
        "MISS (clean tstate) both pass"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
