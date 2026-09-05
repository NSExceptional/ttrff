#!/usr/bin/env python3
# localtest/modset_test.py -- OFFLINE validation of the MODSET matching logic (the production mode
# in frida/trampoline_inject.py: TTRMOD_MODE=modset). MODSET is the GENERAL INTERVAL HOOK driven by
# a curated name->factor TABLE instead of one substring+factor: wrap the Python MetaInterval.start,
# read each started interval's getName(), and setPlayRate it with the factor of the FIRST table entry
# whose `match` is a substring (or prefix) of the name. A name matching NO entry is logged but never
# scaled. This test drives the SAME modset branch that ships in trampoline_inject.py against stock
# arm64 CPython 3.8 with a mock MetaInterval, asserting:
#   A. discovery finds EXACTLY the MetaInterval mock by signature start+setPlayRate+append+clearIntervals
#      (a decoy start/setPlayRate-only class is NOT discovered);
#   B. each matched interval -> original ran (pass-through), scaled ONCE with its entry's OWN factor
#      (teleport 4.0, book 3.0, transitions 3.0, tunnel 4.0), by the right GROUP;
#   C. FIRST match wins: "openBook-42" matches the specific "openBook" (3.0) before the broad "Book"
#      (99.0) that follows it in the table;
#   D. each UNMATCHED interval -> original ran, NOT scaled (play_rate stays 1.0), and logged;
#   E. JUNK-SAFE: an interval whose getName() raises, and one whose getName() returns a non-string,
#      each pass through cleanly, are not scaled, and leave the tstate clean (no crash);
#   F. tstate clean after every case.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/modset_test.py frida/run-injector.sh
#     (or: /path/to/arm64-frida-python localtest/modset_test.py)

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

# The test table -- same shape as modset.json's active entries. NB the broad "Book" (99.0) sits AFTER
# "openBook" (3.0) to prove first-match ordering (assertion C).
TABLE = [
    {"match": "teleportOut", "factor": 4.0, "group": "teleport",    "prefix": False},
    {"match": "teleportIn",  "factor": 4.0, "group": "teleport",    "prefix": False},
    {"match": "openBook",    "factor": 3.0, "group": "book",        "prefix": False},
    {"match": "closeBook",   "factor": 3.0, "group": "book",        "prefix": False},
    {"match": "irisTask",    "factor": 3.0, "group": "transitions", "prefix": False},
    {"match": "tunnel",      "factor": 4.0, "group": "tunnel",      "prefix": False},
    {"match": "Book",        "factor": 99.0, "group": "broadBook",  "prefix": False},
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


# Mock Panda MetaInterval: getName() returns its name (or misbehaves for the junk cases); start()
# returns a sentinel (pass-through check) and RESETS play_rate (hence wrap-AFTER); setPlayRate records.
# append/clearIntervals are the Python-only discriminators distinguishing the Python MetaInterval from
# the C++ CInterval base (which lacks the list builders).
TARGET_PROG = r"""
import sys, types, time

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
        # Python-only discriminators (absent on the C++ CInterval/CMetaInterval):
        def append(self, ival): pass
        def clearIntervals(self, *a, **k): pass
        def extend(self, ivals): pass
    return MetaIntervalMock

_mmod = types.ModuleType("vlt1609aac2.vltinterval.vltMetaInterval")
_mmod.MetaInterval = _make_metaival()
sys.modules["vlt1609aac2.vltinterval.vltMetaInterval"] = _mmod
MI = _mmod.MetaInterval

# matched (each gets its entry's own factor / group):
teleport_out = MI("teleportOut-112139724", 701)
teleport_in  = MI("teleportIn-999",        702)
open_book    = MI("openBook-42",           703)   # first-match: "openBook" (3.0) before broad "Book" (99.0)
iris         = MI("irisTask",              704)
tunnel_walk  = MI("tunnelWalkSeq-Beanwhip", 705)
# unmatched (must NOT scale):
unmatched1   = MI("stareAt-ToonEyes-5",    706)
unmatched2   = MI("someGameplaySeq-7",     707)
# junk-safe (getName misbehaves):
junk_raise   = MI("jr", 708, junk='raise')
junk_nonstr  = MI("jn", 709, junk='nonstr')

# decoy: start/setPlayRate but NOT append/clearIntervals -> must NOT be discovered
def _make_plain():
    class PlainThing:
        def start(self, *a, **k): return 1
        def setPlayRate(self, r): pass
    return PlainThing
_pmod = types.ModuleType("decoymod3")
_pmod.PlainThing = _make_plain()
sys.modules["decoymod3"] = _pmod

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
        scaledGroups: {}, scaledNames: [],
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
      // MODSET applyAfter -- MIRRORS the spec.mode==='modset' branch in frida/trampoline_inject.py:
      // inst IS the interval; read getName(); first matching table entry wins; scale with its own
      // factor; unmatched names logged; every miss clears the tstate.
      ST.applyModset = function(inst){
        try {
          var gm2 = ST.GetAttrStr(inst, cstr('getName'));
          if (gm2.isNull()){ ST.clearExc(); return 0; }
          var nm4 = ST.Call(gm2, ST.TupleNew(0), ptr(0));
          if (nm4.isNull()){ ST.clearExc(); return 0; }
          var nms4 = null; try { nms4 = ST.AsUTF8(nm4).readCString(); } catch(e){ nms4 = null; }
          if (nms4 === null){ ST.clearExc(); return 0; }
          var entries = ST.entries || [], matched = null;
          for (var mi=0; mi<entries.length; mi++){
            var en = entries[mi]; if (!en || !en.match) continue;
            var isHit = en.prefix ? (nms4.lastIndexOf(en.match, 0) === 0) : (nms4.indexOf(en.match) >= 0);
            if (isHit){ matched = en; break; }               // FIRST match wins
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

            // A: discover the Python MetaInterval by start+setPlayRate+append+clearIntervals
            var sig = ['start','setPlayRate','append','clearIntervals'];
            var found = ST.scanBySignature(md, sig);
            var names = {}; for (var i=0;i<found.length;i++){ names[found[i].class_name] = found[i]; }
            R.found_names = Object.keys(names).sort();
            R.discovery_pass = (R.found_names.length === 1 && R.found_names[0] === 'MetaIntervalMock');

            var trec = names['MetaIntervalMock'];
            if (!trec){ send({t:'done', r:{ok:false, stage:'MetaIntervalMock not discovered', found:R.found_names}}); return; }
            var cls = trec.clsPtr; ST.keep.push(cls);
            var mnStart = cstr('start'); ST.keep.push(mnStart);
            var origStart = ST.GetAttrStr(cls, mnStart); ST.keep.push(origStart);
            var im = ST.makeWrapAfter(origStart);
            ST.SetAttrStr(cls, mnStart, im);

            function drive(instName, expectSentinel){
              var inst = ST.GetAttrStr(main, cstr(instName));
              var b = ST.GetAttrStr(inst, cstr('start'));
              var res = b.isNull()? ptr(0) : ST.Call(b, ST.TupleNew(0), ptr(0));
              var rl = res.isNull()? null : L(res);
              var out = {
                passed_through: (rl === expectSentinel),
                started_once: (L(ST.GetAttrStr(inst, cstr('started'))) === 1),
                setPlayRate_calls: L(ST.GetAttrStr(inst, cstr('spr_count'))),
                play_rate: D(ST.GetAttrStr(inst, cstr('play_rate'))),
                tstate_clean: ST.Occurred().isNull(),
              };
              ST.clearExc();
              return out;
            }

            R.teleport_out = drive('teleport_out', 701);
            R.teleport_in  = drive('teleport_in',  702);
            R.open_book    = drive('open_book',    703);
            R.iris         = drive('iris',         704);
            R.tunnel_walk  = drive('tunnel_walk',  705);
            R.unmatched1   = drive('unmatched1',   706);
            R.unmatched2   = drive('unmatched2',   707);
            R.junk_raise   = drive('junk_raise',   708);
            R.junk_nonstr  = drive('junk_nonstr',  709);

            R.scaled_groups = ST.scaledGroups;
            R.scaled_names  = ST.scaledNames.slice().sort();
            R.logged_names  = ST.log.slice().sort();

            ST.SetAttrStr(cls, mnStart, origStart);   // revert
            ST.clearExc();

            function scaled(o, f){ return o.passed_through && o.started_once && o.setPlayRate_calls === 1 && o.play_rate === f && o.tstate_clean; }
            function untouched(o){ return o.passed_through && o.started_once && o.setPlayRate_calls === 0 && o.play_rate === 1.0 && o.tstate_clean; }

            R.ok = !!(
              R.discovery_pass &&
              scaled(R.teleport_out, 4.0) && scaled(R.teleport_in, 4.0) &&
              scaled(R.open_book, 3.0) &&        // C: first-match -> 3.0, NOT the broad 99.0
              scaled(R.iris, 3.0) && scaled(R.tunnel_walk, 4.0) &&
              untouched(R.unmatched1) && untouched(R.unmatched2) &&
              untouched(R.junk_raise) && untouched(R.junk_nonstr) &&
              R.scaled_groups.teleport === 2 && R.scaled_groups.book === 1 &&
              R.scaled_groups.transitions === 1 && R.scaled_groups.tunnel === 1 &&
              (R.scaled_groups.broadBook === undefined) &&
              R.logged_names.indexOf('stareAt-ToonEyes-5') >= 0 &&
              R.logged_names.indexOf('someGameplaySeq-7') >= 0 &&
              R.logged_names.length === 2                       // junk names never logged (getName failed)
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
    print("[modset] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib, "table": TABLE})
    if not init.get("ok"):
        print("[modset] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(20.0):
        print("[modset] hook never fired in 20s")
    elif box.get("detached"):
        print("[modset] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[modset] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[modset] target_alive=%s" % alive)
    print("[modset] VERDICT: %s" % (
        "PASS -- modset discovers the Python MetaInterval by signature, wraps start(), and scales "
        "each started interval with the FIRST-matching table entry's own factor/group "
        "(first-match ordering honored, unmatched logged-not-scaled, junk-safe, tstate clean)"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
