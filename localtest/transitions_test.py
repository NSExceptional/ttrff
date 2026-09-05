#!/usr/bin/env python3
# localtest/transitions_test.py -- OFFLINE validation of the SCREEN-TRANSITIONS mod exactly as it
# will run live (env-driven mod1: self-discover the Transitions class by its transition-method
# signature, wrap those methods with the wrap-after trampoline, and setPlayRate the interval the
# method just started + stored on `self`).
#
# This mirrors direct.showbase.Transitions (the real Panda3D source TTR is built on):
#   - irisIn/irisOut/fadeIn/fadeOut, for t != 0, do `self.transitionIval = <Sequence>; ...start()`;
#     so AFTER the method returns, `self.transitionIval` is the running interval -> wrap-after
#     getattr(self,'transitionIval').setPlayRate(f) scales it on the fly (the proven pattern).
#   - the t == 0 fast paths (and letterbox, which uses a DIFFERENT attr `letterboxIval`) leave
#     `self.transitionIval` as its prior value (None here) -> getattr returns None -> setPlayRate
#     on None misses cleanly with the tstate exception CLEARED (no live-crash leak).
#
# We cannot run against the live engine, so we build the equivalent on a stock arm64 CPython 3.8 we
# own (identical PyTypeObject layout). The AGENT carries the SAME scanBySignature/classSignature +
# wrap-after helpers that ship in frida/trampoline_inject.py. We assert:
#   A. self-discovery by ['irisIn','irisOut','fadeIn','fadeOut'] finds EXACTLY the Transitions class
#      (all_direct), not the letterbox-only decoy nor the no-iris decoy;
#   B. wrapping all four + calling irisOut() -> orig once, result passed through, setPlayRate(5.0)
#      once on self.transitionIval; and calling fadeOut() likewise scales its (new) transitionIval;
#   C. the instant/None path (transitionIval is None) -> orig once, result passed through, NOTHING
#      scaled, and the tstate is clean afterward (the exact discipline that avoids a live crash).
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/transitions_test.py frida/run-injector.sh

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


# The Transitions mock mirrors direct.showbase.Transitions: transition methods store+start the
# running interval on self.transitionIval; letterbox uses self.letterboxIval; the instant path
# leaves transitionIval None. Registered under a hashed-looking module key like the vault does.
TARGET_PROG = r"""
import sys, types, time

class MockInterval:                       # stands in for the started Sequence/LerpInterval
    def __init__(self, tag=""):
        self.tag = tag
        self.spr_count = 0
        self.last_rate = 0.0
        self.started = False
    def start(self, *a, **k):
        self.started = True               # Panda resets playRate to 1.0 here (hence wrap-AFTER)
    def setPlayRate(self, f):
        self.spr_count += 1
        self.last_rate = float(f)

def _make_transitions():
    class Transitions:
        iris_out_count = 0
        fade_out_count = 0
        instant_count = 0
        def __init__(self):
            self.transitionIval = None
            self.letterboxIval = None
        def irisIn(self, t=0.5, *a, **k):
            self.transitionIval = MockInterval("iris-in"); self.transitionIval.start(); return 11
        def irisOut(self, t=0.5, *a, **k):
            Transitions.iris_out_count += 1
            self.transitionIval = MockInterval("iris-out"); self.transitionIval.start(); return 22
        def fadeIn(self, t=0.5, *a, **k):
            self.transitionIval = MockInterval("fade-in"); self.transitionIval.start(); return 33
        def fadeOut(self, t=0.5, *a, **k):
            Transitions.fade_out_count += 1
            self.transitionIval = MockInterval("fade-out"); self.transitionIval.start(); return 44
        # the t == 0 fast path mirrors noTransitions(): transitionIval -> None -> must be a clean no-op
        def irisOutInstant(self, *a, **k):
            Transitions.instant_count += 1
            self.transitionIval = None
            return 55
        # decoy readable siblings that must not confuse discovery
        def noFade(self, *a, **k): return None
        def noIris(self, *a, **k): return None
        def noTransitions(self, *a, **k): return None
    return Transitions

_tmod = types.ModuleType("vlt1609aac2.vltshowbase.vltTransitions")
_tmod.Transitions = _make_transitions()
sys.modules["vlt1609aac2.vltshowbase.vltTransitions"] = _tmod
transitions = _tmod.Transitions()          # the singleton, like base.transitions

# decoy: letterbox-only (different method set) must NOT match the iris/fade signature
def _make_lb():
    class LetterboxOnly:
        def letterboxOn(self, t=0.25, *a, **k):
            self.letterboxIval = MockInterval("lb-on"); self.letterboxIval.start(); return 1
        def letterboxOff(self, t=0.25, *a, **k):
            self.letterboxIval = MockInterval("lb-off"); self.letterboxIval.start(); return 2
    return LetterboxOnly
_lmod = types.ModuleType("vlt1609aac2.vltlb")
_lmod.LetterboxOnly = _make_lb()
sys.modules["vlt1609aac2.vltlb"] = _lmod

# decoy: defines fadeIn/fadeOut but NOT iris -> not a full 4-method match
def _make_partial():
    class PartialFader:
        def fadeIn(self, *a, **k): return 1
        def fadeOut(self, *a, **k): return 2
    return PartialFader
_pmod = types.ModuleType("decoymod")
_pmod.PartialFader = _make_partial()
sys.modules["decoymod"] = _pmod

t = time.time()
while time.time() - t < 30:
    s = sum(i*i for i in range(300))       # busy: forces C->Python frame-evals so the hook fires
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
      // attr-mode _apply_after (the transitions spec): getattr(self, attr).setPlayRate(f).
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
            if (!inst.isNull()) ST.lastApplied = ST.applyAfter(inst, spec, factorVal);
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
              var hit = ST.DictGetStr(bdict, methCStrs[mi]);
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
      ST.scanBySignature = function(md, methods){
        var byCls = {}, order = [];
        try {
          if (md.isNull() || !(ST.GetIter && ST.IterNext && ST.AsUTF8 && ST.DictGetStr && ST.DictGetItem && ST.GetAttrStr)){ ST.clearExc(); return []; }
          var methCStrs = []; for (var mi=0; mi<methods.length; mi++){ methCStrs.push(Memory.allocUtf8String(methods[mi])); }
          var dictStr = Memory.allocUtf8String('__dict__');
          var mit = ST.GetIter(md); if (mit.isNull()){ ST.clearExc(); return []; }
          var mk;
          while (!(mk = ST.IterNext(mit)).isNull()){
            var modObj = ST.DictGetItem(md, mk);
            if (modObj.isNull()){ ST.clearExc(); continue; }
            var mdict = ST.GetAttrStr(modObj, dictStr);
            if (mdict.isNull()){ ST.clearExc(); continue; }
            var dit = ST.GetIter(mdict); if (dit.isNull()){ ST.clearExc(); continue; }
            var modName = null, ak;
            while (!(ak = ST.IterNext(dit)).isNull()){
              var val = ST.DictGetItem(mdict, ak);
              if (val.isNull()){ ST.clearExc(); continue; }
              var isType = false;
              try { isType = (val.add(8).readPointer().add(0xab).readU8() & 0x80) !== 0; } catch(e){ isType = false; }
              if (!isType) continue;
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
        } catch(e){ }
        ST.clearExc();
        var outl = [];
        for (var i=0;i<order.length;i++){ var r = byCls[order[i]]; if (r && r.full) outl.push(r); }
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
          function L(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsLong(o); ST.clearExc(); return v.toNumber ? v.toNumber() : v; }
          function D(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsDouble(o); ST.clearExc(); return v; }
          try {
            var R = {};
            var md = ST.GetModuleDict();
            if (md.isNull()){ send({t:'done', r:{ok:false, stage:'no sys.modules'}}); return; }
            var main = ST.AddModule(cstr('__main__'));

            // ---------- A: self-discover the Transitions class by the 4-method signature ----------
            var methods = ['irisIn','irisOut','fadeIn','fadeOut'];
            var found = ST.scanBySignature(md, methods);
            var names = {}; for (var i=0;i<found.length;i++){ names[found[i].class_name] = found[i]; }
            R.found_names = Object.keys(names).sort();
            var direct = found.filter(function(r){ return r.all_direct; });
            R.direct_names = direct.map(function(r){ return r.class_name; }).sort();
            var trec = names['Transitions'];
            R.discovery_pass = !!(trec && trec.all_direct &&
                                  trec.methods.irisIn.where === 'direct' && trec.methods.irisOut.where === 'direct' &&
                                  trec.methods.fadeIn.where === 'direct' && trec.methods.fadeOut.where === 'direct' &&
                                  trec.bindings.some(function(b){ return /vltTransitions/.test(b.module) && b.attr === 'Transitions'; }) &&
                                  R.found_names.length === 1 && R.found_names[0] === 'Transitions');

            // install the wrap-after on ALL FOUR discovered methods (attr='transitionIval', x5.0),
            // exactly as mod1 does; keep origs to revert.
            var cls = trec.clsPtr; ST.keep.push(cls);
            var origs = {};
            for (var a=0;a<methods.length;a++){
              var mn = cstr(methods[a]); ST.keep.push(mn);
              var orig = ST.GetAttrStr(cls, mn); if (orig.isNull()){ ST.clearExc(); continue; }
              ST.keep.push(orig); origs[methods[a]] = {mn:mn, orig:orig};
              var im = ST.makeWrapAfter(orig, {mode:'attr', attr:'transitionIval'}, 5.0);
              if (!im.isNull()) ST.SetAttrStr(cls, mn, im);
            }
            var inst = ST.GetAttrStr(main, cstr('transitions'));

            function callNoArg(meth){
              var bound = ST.GetAttrStr(inst, cstr(meth));
              var res = bound.isNull()? ptr(0) : ST.Call(bound, ST.TupleNew(0), ptr(0));
              var rl = res.isNull()? null : L(res);
              return rl;
            }

            // ---------- B: irisOut() -> transitionIval scaled x5.0 ----------
            ST.lastApplied = null;
            var io_res = callNoArg('irisOut');
            var iv1 = ST.GetAttrStr(inst, cstr('transitionIval'));
            R.irisOut = { orig_called_once: (L(ST.GetAttrStr(cls, cstr('iris_out_count'))) === 1),
                          result_passed_through: (io_res === 22),
                          setPlayRate_calls: iv1.isNull()? null : L(ST.GetAttrStr(iv1, cstr('spr_count'))),
                          setPlayRate_factor: iv1.isNull()? null : D(ST.GetAttrStr(iv1, cstr('last_rate'))),
                          applied: ST.lastApplied,
                          tstate_clean_after: ST.Occurred().isNull() };
            ST.clearExc();

            // ---------- B2: fadeOut() -> its (new) transitionIval scaled x5.0 ----------
            ST.lastApplied = null;
            var fo_res = callNoArg('fadeOut');
            var iv2 = ST.GetAttrStr(inst, cstr('transitionIval'));
            R.fadeOut = { orig_called_once: (L(ST.GetAttrStr(cls, cstr('fade_out_count'))) === 1),
                          result_passed_through: (fo_res === 44),
                          interval_tag: iv2.isNull()? null : (function(){ var t = ST.GetAttrStr(iv2, cstr('tag')); return t.isNull()? null : ST.AsUTF8(t).readCString(); })(),
                          setPlayRate_calls: iv2.isNull()? null : L(ST.GetAttrStr(iv2, cstr('spr_count'))),
                          setPlayRate_factor: iv2.isNull()? null : D(ST.GetAttrStr(iv2, cstr('last_rate'))),
                          tstate_clean_after: ST.Occurred().isNull() };
            ST.clearExc();

            // ---------- C: the instant/None path -> clean no-op ----------
            // irisOutInstant() sets self.transitionIval = None (like the real noTransitions()), so the
            // wrap-after getattr(self,'transitionIval') sees None -> setPlayRate(None) misses -> the
            // tstate exception MUST be cleared (the exact discipline that prevents a live crash).
            var mnI = cstr('irisOutInstant'); ST.keep.push(mnI);
            var origI = ST.GetAttrStr(cls, mnI);
            if (!origI.isNull()){
              ST.keep.push(origI);
              var imI = ST.makeWrapAfter(origI, {mode:'attr', attr:'transitionIval'}, 5.0);
              if (!imI.isNull()) ST.SetAttrStr(cls, mnI, imI);
            }
            ST.lastApplied = null;
            var inst_res = callNoArg('irisOutInstant');
            var ivN = ST.GetAttrStr(inst, cstr('transitionIval'));   // the None singleton (non-NULL)
            // None has no spr_count/setPlayRate; a clean getattr of a missing attr on None must clear.
            var noneHasSpr = !ST.GetAttrStr(ivN, cstr('spr_count')).isNull(); ST.clearExc();
            R.instant = { orig_called_once: (L(ST.GetAttrStr(cls, cstr('instant_count'))) === 1),
                          result_passed_through: (inst_res === 55),
                          transitionIval_is_none: !noneHasSpr,
                          applied_zero: (ST.lastApplied === 0),
                          tstate_clean_after: ST.Occurred().isNull() };
            if (!origI.isNull()) ST.SetAttrStr(cls, mnI, origI);
            ST.clearExc();

            // revert the four
            for (var b=0;b<methods.length;b++){ var e = origs[methods[b]]; if (e) ST.SetAttrStr(cls, e.mn, e.orig); }
            ST.clearExc();

            R.ok = !!(R.discovery_pass &&
                      R.irisOut.orig_called_once && R.irisOut.result_passed_through &&
                      R.irisOut.setPlayRate_calls === 1 && R.irisOut.setPlayRate_factor === 5.0 &&
                      R.irisOut.tstate_clean_after &&
                      R.fadeOut.orig_called_once && R.fadeOut.result_passed_through &&
                      R.fadeOut.setPlayRate_calls === 1 && R.fadeOut.setPlayRate_factor === 5.0 &&
                      R.fadeOut.interval_tag === 'fade-out' && R.fadeOut.tstate_clean_after &&
                      R.instant.orig_called_once && R.instant.result_passed_through &&
                      R.instant.transitionIval_is_none && R.instant.applied_zero &&
                      R.instant.tstate_clean_after);
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
    print("[transitions] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
        print("[transitions] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[transitions] hook never fired in 20s")
    elif box.get("detached"):
        print("[transitions] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[transitions] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[transitions] target_alive=%s" % alive)
    print("[transitions] VERDICT: %s" % (
        "PASS -- self-discovers the Transitions class by irisIn/irisOut/fadeIn/fadeOut, wraps all "
        "four, setPlayRate(5.0) lands on self.transitionIval for iris AND fade, and the None/instant "
        "path is a clean no-op with the tstate exception cleared"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
