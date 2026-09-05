#!/usr/bin/env python3
# localtest/ivalname_test.py -- OFFLINE validation of the GENERAL INTERVAL HOOK (the fallback the
# mission calls for when a transition/animation interval is fire-and-forget, not stored on an
# instance). In Panda3D, Sequence/Parallel are `MetaInterval` and every .start() dispatches to the
# Python MetaInterval.start(); the toon-tunnel walk and screen fades are such Sequences. So we:
#   - self-discover the Python MetaInterval class by a signature only IT has
#     (start+setPlayRate+append+addSequence -- the C++ CInterval/CMetaInterval lack the Python
#     list-builder methods);
#   - wrap ONLY `start` (not the whole signature) via the decoupled wrapMethods;
#   - in the wrap-after, `self` IS the interval: read getName(), LOG it (discovery), and
#     setPlayRate(self, factor) ON-THE-FLY *only* when the name contains a target substring, so we
#     never globally rescale every interval in the game.
#
# We validate on stock arm64 CPython 3.8 with the SAME byname logic that ships in
# frida/trampoline_inject.py. Asserts:
#   A. discovery finds EXACTLY the MetaInterval mock (not a decoy plain class);
#   B. start() of a "tunnel"-named interval -> original ran (pass-through), name logged, and
#      setPlayRate(5.0) applied exactly once (name matched);
#   C. start() of a non-matching-named interval -> original ran, name logged, NOT scaled;
#   D. tstate clean after each.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/ivalname_test.py frida/run-injector.sh

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


# Mock Panda MetaInterval: a started interval that records its play rate; getName() returns its name;
# start() returns a sentinel (pass-through check). The append/addSequence methods are the Python-only
# discriminators that distinguish the Python MetaInterval from the C++ base classes.
TARGET_PROG = r"""
import sys, types, time

def _make_metaival():
    class MetaIntervalMock:
        def __init__(self, name, sentinel):
            self._name = name
            self._sentinel = sentinel
            self.play_rate = 1.0
            self.spr_count = 0
            self.started = 0
        def getName(self): return self._name
        def start(self, startT=0.0, endT=-1.0, playRate=1.0):
            self.started += 1
            self.play_rate = playRate            # Panda start() resets play rate (hence wrap-AFTER)
            return self._sentinel
        def setPlayRate(self, r):
            self.spr_count += 1
            self.play_rate = float(r)
        # Python-only discriminators (absent on the C++ CInterval/CMetaInterval):
        def append(self, ival): pass
        def addSequence(self, *a, **k): pass
        def extend(self, ivals): pass
    return MetaIntervalMock

_mmod = types.ModuleType("vlt1609aac2.vltinterval.vltMetaInterval")
_mmod.MetaInterval = _make_metaival()
sys.modules["vlt1609aac2.vltinterval.vltMetaInterval"] = _mmod

MI = _mmod.MetaInterval
tunnel_ival = MI("tunnel-walk-Mr.Beanwhip", 777)   # name matches sub 'tunnel' -> must be scaled
other_ival  = MI("gui-fade-blah", 888)             # no match -> must NOT be scaled

# decoy: a plain class that also has start/setPlayRate but NOT append/addSequence -> not discovered
def _make_plain():
    class PlainThing:
        def start(self, *a, **k): return 1
        def setPlayRate(self, r): pass
    return PlainThing
_pmod = types.ModuleType("decoymod2")
_pmod.PlainThing = _make_plain()
sys.modules["decoymod2"] = _pmod

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
      // byname applyAfter -- copied from frida/trampoline_inject.py: inst IS the interval; read
      // getName(), log, scale iff name matches a substring.
      ST.log = [];
      ST.applyAfter = function(inst, spec, factorVal){
        try {
          if (spec.mode === 'byname'){
            var gm = ST.GetAttrStr(inst, cstr('getName'));
            if (gm.isNull()){ ST.clearExc(); return 0; }
            var nm3 = ST.Call(gm, ST.TupleNew(0), ptr(0));
            if (nm3.isNull()){ ST.clearExc(); return 0; }
            var nms = null; try { nms = ST.AsUTF8(nm3).readCString(); } catch(e){ nms = null; }
            if (nms === null){ ST.clearExc(); return 0; }
            if (spec.log && ST.log.indexOf(nms) < 0) ST.log.push(nms);
            var subs = spec.subs || [], hit = false;
            for (var si=0; si<subs.length; si++){ if (subs[si] && nms.indexOf(subs[si]) >= 0){ hit = true; break; } }
            if (hit){ var ok = ST.setPlayRate(inst, factorVal); ST.clearExc(); return ok ? 1 : 0; }
            ST.clearExc(); return 0;
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

      // shared signature scan (verbatim shape from trampoline_inject.py)
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

            // A: discover the Python MetaInterval by start+setPlayRate+append+addSequence
            var sig = ['start','setPlayRate','append','addSequence'];
            var found = ST.scanBySignature(md, sig);
            var names = {}; for (var i=0;i<found.length;i++){ names[found[i].class_name] = found[i]; }
            R.found_names = Object.keys(names).sort();
            R.discovery_pass = (R.found_names.length === 1 && R.found_names[0] === 'MetaIntervalMock');

            var trec = names['MetaIntervalMock'];
            var cls = trec.clsPtr; ST.keep.push(cls);
            // wrap ONLY start (decoupled wrapMethods)
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(cls, mnStart); ST.keep.push(origStart);
            var spec = {mode:'byname', subs:['tunnel'], log:true};
            var im = ST.makeWrapAfter(origStart, spec, 5.0);
            ST.SetAttrStr(cls, mnStart, im);

            function startInst(instName){
              var inst = ST.GetAttrStr(main, cstr(instName));
              var b = ST.GetAttrStr(inst, cstr('start'));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              var rl = res.isNull()? null : L(res);
              return { inst:inst, res:rl };
            }

            // B: tunnel-named interval -> scaled
            var t = startInst('tunnel_ival');
            R.tunnel = { result_passed_through: (t.res === 777),
                         started_once: (L(ST.GetAttrStr(t.inst, cstr('started'))) === 1),
                         setPlayRate_calls: L(ST.GetAttrStr(t.inst, cstr('spr_count'))),
                         play_rate: D(ST.GetAttrStr(t.inst, cstr('play_rate'))),
                         tstate_clean: ST.Occurred().isNull() };
            ST.clearExc();

            // C: other-named interval -> NOT scaled
            var o = startInst('other_ival');
            R.other = { result_passed_through: (o.res === 888),
                        started_once: (L(ST.GetAttrStr(o.inst, cstr('started'))) === 1),
                        setPlayRate_calls: L(ST.GetAttrStr(o.inst, cstr('spr_count'))),
                        play_rate: D(ST.GetAttrStr(o.inst, cstr('play_rate'))),
                        tstate_clean: ST.Occurred().isNull() };
            ST.clearExc();

            R.logged_names = ST.log.slice().sort();

            ST.SetAttrStr(cls, mnStart, origStart);   // revert
            ST.clearExc();

            R.ok = !!(R.discovery_pass &&
                      R.tunnel.result_passed_through && R.tunnel.started_once &&
                      R.tunnel.setPlayRate_calls === 1 && R.tunnel.play_rate === 5.0 && R.tunnel.tstate_clean &&
                      R.other.result_passed_through && R.other.started_once &&
                      R.other.setPlayRate_calls === 0 && R.other.play_rate === 1.0 && R.other.tstate_clean &&
                      R.logged_names.indexOf('tunnel-walk-Mr.Beanwhip') >= 0 &&
                      R.logged_names.indexOf('gui-fade-blah') >= 0);
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
    print("[ivalname] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
        print("[ivalname] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[ivalname] hook never fired in 20s")
    elif box.get("detached"):
        print("[ivalname] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[ivalname] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[ivalname] target_alive=%s" % alive)
    print("[ivalname] VERDICT: %s" % (
        "PASS -- discovers the Python MetaInterval by signature, wraps only start(), logs every "
        "started interval's getName(), and setPlayRate(5.0)s ONLY the name-matching interval "
        "(pass-through preserved, non-match untouched, tstate clean)"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
