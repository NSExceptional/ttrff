#!/usr/bin/env python3
"""READ-ONLY world-state reader for the live client: where is the toon, where are the pickups.

Separate from `trampoline_inject.py` on purpose. That injector is the load-bearing, working mod;
this attaches a second, strictly read-only script that installs no hooks and setattr's nothing, so
a bug here cannot destabilise the mod or leave a trampoline pointing at freed agent memory.

It reuses the injector's per-build tables and its two hard-won correctness rules:
  * reach the GIL via PyGILState_Ensure/Release -- the packed Windows build fail-fasts on any
    code patch, so the Interceptor bootstrap is not available here (see STATUS.md)
  * clear the pending exception on EVERY exit path -- a leaked exception is inherited by the
    game's next task and turns into an AttributeError/disconnect

Modes:
    discover   tally every class in base.cr.doId2do (what IS a jellybean bag called?)
    nodes      scene-graph node names under render, with counts
    state      one world-state read as JSON  (--match to pick the pickup class)
    watch      state on a loop, JSON per line

Usage:
    python frida/worldstate.py discover
    python frida/worldstate.py state --match JellybeanBag
    python frida/worldstate.py watch --match JellybeanBag --hz 2

NOTE ON REFCOUNTS: every C-API getattr/call here returns a NEW reference and there is no Py_DecRef
in the Windows table, so each tick leaks a few small objects (~2 KB at 5 pickups). Bound methods on
the toon are cached to cut most of it. Acceptable for a session; if it ever matters, derive
Py_DecRef and release properly rather than hand-decrementing ob_refcnt -- a refcount that reaches
zero without tp_dealloc running is worse than the leak.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import trampoline_inject as TI          # noqa: E402  -- per-build tables + engine discovery

# Py_True / Py_False live in the table's _meta block (they are data, not functions, so they are not
# part of load_symbols' output). Used only to interpret a bool return such as NodePath.isHidden().
_META = json.load(open(os.path.join(os.path.dirname(HERE), "capi-symbols-win.json"))).get("_meta", {})
_SING = _META.get("singletons", {})
TRUE_OBJ = _SING.get("Py_True")
FALSE_OBJ = _SING.get("Py_False")

JS = r"""
var ST = null;

rpc.exports = {
  init: function (p) {
    var out = { ok: false, notes: [] };
    try {
      var slide = Process.mainModule.base.sub(ptr(p.image_base));
      function rt(v) { return ptr(v).add(slide); }
      var F = {};
      for (var n in p.syms) F[n] = rt(p.syms[n].vmaddr);

      ST = {
        slide: slide,
        Call:       new NativeFunction(F['PyObject_Call'],          'pointer', ['pointer','pointer','pointer']),
        GetAttrStr: new NativeFunction(F['PyObject_GetAttrString'], 'pointer', ['pointer','pointer']),
        DictGetStr: new NativeFunction(F['PyDict_GetItemString'],   'pointer', ['pointer','pointer']),
        TupleNew:   new NativeFunction(F['PyTuple_New'],            'pointer', ['long']),
        TupleSet:   new NativeFunction(F['PyTuple_SetItem'],        'int',     ['pointer','long','pointer']),
        cell:       rt(p.tstate_cell),
        interp_off: p.interp_off, modules_off: p.modules_off,
        FloatType:  p.float_type ? rt(p.float_type) : null,
        PyTrue:     p.py_true  ? rt(p.py_true)  : null,
        PyFalse:    p.py_false ? rt(p.py_false) : null,
        keep: [], mcache: {}
      };
      if (F['PyObject_GetIter'])      ST.GetIter    = new NativeFunction(F['PyObject_GetIter'],      'pointer', ['pointer']);
      if (F['PyIter_Next'])           ST.IterNext   = new NativeFunction(F['PyIter_Next'],           'pointer', ['pointer']);
      if (F['PyGILState_Ensure'])     ST.GilEnsure  = new NativeFunction(F['PyGILState_Ensure'],     'int',     []);
      if (F['PyGILState_Release'])    ST.GilRelease = new NativeFunction(F['PyGILState_Release'],    'void',    ['int']);
      if (F['PyUnicode_FromString'])  ST.UniFromStr = new NativeFunction(F['PyUnicode_FromString'],  'pointer', ['pointer']);
      if (F['PyTuple_GetItem'])       ST.TupleGet   = new NativeFunction(F['PyTuple_GetItem'],       'pointer', ['pointer','long']);
      // Needed by mkint() and therefore by every call taking an int argument (getSolid(i),
      // getPoint(j), movePointer). It was never bound here, so mkint() returned NULL and those
      // calls received a NULL argument -- which crashed the client twice, and made movePointer
      // silently fail so every "Panda-placed" click fell back to a focus-stealing raw click.
      if (F['PyFloat_FromDouble'])    ST.FloatFromDouble = new NativeFunction(F['PyFloat_FromDouble'], 'pointer', ['double']);
      if (!ST.GilEnsure || !ST.GilRelease) { out.notes.push('no GIL symbols -- cannot run safely'); return out; }
      if (!ST.GetIter || !ST.IterNext)     { out.notes.push('no GetIter/IterNext -- iteration disabled'); }

      // tp_name of an object's type. For a heap type (a Python class) this IS the class name.
      ST.tpname = function (o) {
        try { return o.add(8).readPointer().add(0x18).readPointer().readCString(); } catch (e) { return '?'; }
      };
      // CRITICAL: never leave a pending exception on the tstate (curexc at +0x58/+0x60/+0x68).
      ST.clearExc = function () {
        try {
          var t = ST.cell.readPointer();
          if (!t.isNull()) { t.add(0x58).writePointer(ptr(0)); t.add(0x60).writePointer(ptr(0)); t.add(0x68).writePointer(ptr(0)); }
        } catch (e) {}
      };
      ST.sysmodules = function () {
        var t = ST.cell.readPointer(); if (t.isNull()) return ptr(0);
        var i = t.add(ST.interp_off).readPointer(); if (i.isNull()) return ptr(0);
        return i.add(ST.modules_off).readPointer();
      };
      ST.builtins = function () {
        var md = ST.sysmodules(); if (md.isNull()) return ptr(0);
        var b = ST.DictGetStr(md, Memory.allocUtf8String('builtins'));
        if (b.isNull()) ST.clearExc();
        return b;
      };
      ST.attr = function (o, name) {
        try {
          if (!o || o.isNull()) return ptr(0);
          var r = ST.GetAttrStr(o, Memory.allocUtf8String(name));
          if (r.isNull()) ST.clearExc();
          return r;
        } catch (e) { ST.clearExc(); return ptr(0); }
      };
      // PyTuple_SetItem STEALS a reference to the value. Every call here that passes a shared
      // object as an argument -- render, aspect2d -- was therefore decrementing that object's
      // refcount once per call. It survived only because those nodes carry huge refcounts, but at
      // 2 Hz over a long session it is a genuine use-after-free waiting to happen. Bump the count
      // before handing the object over; over-incrementing merely leaks, under-incrementing frees
      // something the game is still using.
      ST.incref = function (o) {
        try { if (o && !o.isNull()) o.writeU64(o.readU64() + 1); } catch (e) {}
        return o;
      };
      ST.mkstr = function (s) {
        try { return ST.UniFromStr ? ST.UniFromStr(Memory.allocUtf8String(s)) : ptr(0); }
        catch (e) { ST.clearExc(); return ptr(0); }
      };
      // No PyUnicode_AsUTF8 in the Windows table: read the compact-ASCII body inline, else the
      // cached utf8 pointer. CPython 3.8 unicode: state @+0x20 (compact bit5, ascii bit6).
      ST.str = function (o) {
        try {
          if (!o || o.isNull()) return null;
          var st = o.add(0x20).readU32();
          var p2 = (((st >> 5) & 1) && ((st >> 6) & 1)) ? o.add(0x30) : o.add(0x38).readPointer();
          if (p2.isNull()) return null;
          return p2.readCString();
        } catch (e) { return null; }
      };
      // obj.<name>() -> str, or null. Generic string-returning call (nodePath.getName() etc).
      ST.callStr = function (o, name) {
        try {
          var m = ST.attr(o, name);
          if (m.isNull()) return null;
          var r = ST.Call(m, ST.TupleNew(0), ptr(0));
          if (r.isNull()) { ST.clearExc(); return null; }
          var s = ST.str(r);
          ST.clearExc();
          return s;
        } catch (e) { ST.clearExc(); return null; }
      };
      // obj.<name>() -> true/false/null. Compared against the Py_True singleton rather than
      // interpreting bytes, so a non-bool return simply yields null.
      ST.callBool = function (o, name) {
        try {
          var m = ST.attr(o, name);
          if (m.isNull()) return null;
          var r = ST.Call(m, ST.TupleNew(0), ptr(0));
          if (r.isNull()) { ST.clearExc(); return null; }
          ST.clearExc();
          if (ST.PyTrue && r.equals(ST.PyTrue)) return true;
          if (ST.PyFalse && r.equals(ST.PyFalse)) return false;
          return null;
        } catch (e) { ST.clearExc(); return null; }
      };
      // Read a float object's ob_fval inline at +0x10. No PyFloat_AsDouble in the Windows table,
      // and none is needed -- same trick as the AsUTF8 compact-ASCII fallback.
      ST.fval = function (o) {
        try {
          if (!o || o.isNull()) return null;
          if (ST.FloatType && !o.add(8).readPointer().equals(ST.FloatType)) return null;
          return o.add(0x10).readDouble();
        } catch (e) { return null; }
      };
      // obj.<name>(...args) -> float, or null. `cacheKey` reuses the bound method across ticks --
      // but ONLY for the same object. A bound method carries its object, so a cache keyed by name
      // alone kept reading the OLD toon after a "got sleepy" logout and re-login: its heading never
      // changed, and the bot turned on the spot forever trying to line up. The cached entry
      // remembers which object it was bound to, and a different object refetches.
      ST.callFloat = function (o, name, args, cacheKey) {
        try {
          var m = ptr(0);
          var c = cacheKey ? ST.mcache[cacheKey] : null;
          if (c && c.obj.equals(o)) m = c.m;
          else {
            m = ST.attr(o, name);
            if (m.isNull()) return null;
            if (cacheKey) { ST.mcache[cacheKey] = { obj: o, m: m }; ST.keep.push(m); }
          }
          for (var q = 0; args && q < args.length; q++) {
            if (!args[q] || args[q].isNull()) return null;       // see callRawFn: NULL args crash
          }
          var t = ST.TupleNew(args ? args.length : 0);
          if (t.isNull()) { ST.clearExc(); return null; }
          for (var i = 0; args && i < args.length; i++) ST.TupleSet(t, i, ST.incref(args[i]));
          var r = ST.Call(m, t, ptr(0));
          if (r.isNull()) { ST.clearExc(); return null; }
          var d = ST.fval(r);
          ST.clearExc();
          return d;
        } catch (e) { ST.clearExc(); return null; }
      };
      // Iterate any Python iterable, calling cb(item). Bounded so a pathological container
      // cannot stall the game while we hold the GIL.
      ST.each = function (it, cb, limit) {
        if (!ST.GetIter || !ST.IterNext) return 0;
        var n = 0;
        try {
          var i = ST.GetIter(it);
          if (i.isNull()) { ST.clearExc(); return 0; }
          for (;;) {
            var v = ST.IterNext(i);
            if (v.isNull()) break;
            cb(v); n++;
            if (limit && n >= limit) break;
          }
          ST.clearExc();
        } catch (e) { ST.clearExc(); }
        return n;
      };
      ST.gil = function (fn) {
        var st;
        try { st = ST.GilEnsure(); } catch (e) { return { ok: false, e: 'Ensure: ' + e }; }
        var res = null, err = null;
        try { res = fn(); } catch (e) { err = String(e); }
        ST.clearExc();
        try { ST.GilRelease(st); } catch (e) { err = err || ('Release: ' + e); }   // ALWAYS release
        return err ? { ok: false, e: err } : { ok: true, r: res };
      };
      // base.cr.doId2do.values() as an iterable sequence, or null.
      ST.doValues = function (base) {
        var cr = ST.attr(base, 'cr');
        if (cr.isNull()) return null;
        var d2d = ST.attr(cr, 'doId2do');
        if (d2d.isNull()) return null;
        var vals = ST.attr(d2d, 'values');
        if (vals.isNull()) return null;
        var seq = ST.Call(vals, ST.TupleNew(0), ptr(0));
        if (seq.isNull()) { ST.clearExc(); return null; }
        return seq;
      };

      ST.hasAll = function (o, names) {
        for (var i = 0; i < names.length; i++) { if (ST.attr(o, names[i]).isNull()) return false; }
        return true;
      };
      // Classify an object once per CLASS, then cache by tp_name -- the signature probe costs
      // several getattrs, and a 2 Hz loop must not repeat it for every object on every tick.
      ST.roleCache = {};
      ST.roleOf = function (o) {
        var t = ST.tpname(o) || '?';
        var cached = ST.roleCache[t];
        if (cached) return cached;
        var r = 'other';
        if (ST.hasAll(o, ['tunnelOut'])) r = 'me';
        else if (ST.hasAll(o, ['treasure'])) r = ST.hasAll(o, ['value']) ? 'bag' : 'treasure';
        ST.roleCache[t] = r;
        return r;
      };
      // World position. An avatar IS a NodePath; a treasure HAS one (.nodePath) -- calling getX on
      // the treasure itself silently yields nothing, so fall through rather than dropping it.
      ST.posOf = function (o, rargs, ck) {
        var src = o;
        var x = ST.callFloat(o, 'getX', rargs, ck ? ck + '.gx' : null);
        if (x === null) {
          var np = ST.attr(o, 'nodePath');
          if (np.isNull()) return null;
          src = np;
          x = ST.callFloat(np, 'getX', rargs, null);
          if (x === null) return null;
        }
        var y = ST.callFloat(src, 'getY', rargs, null);
        if (y === null) return null;
        return { x: x, y: y, z: ST.callFloat(src, 'getZ', rargs, null), src: src };
      };
      // Visual centre and size of a widget, in `rel` space, from getTightBounds().
      //
      // A widget's NODE ORIGIN is NOT where it appears. The trampoline dialog's OK button reports
      // an origin at z=+0.16 while the green button is drawn near z=-0.45 -- clicking the origin
      // hits the dialog's background and does nothing, which left the bot frozen in front of it.
      // getTightBounds gives the drawn extent, whose midpoint is what a user would aim at.
      // World-space axis-aligned bounds of a node, or null. getTightBounds(rel) returns a
      // (Point3 min, Point3 max) tuple, or None when the subgraph has no geometry.
      ST.boundsOf = function (np, rel) {
        try {
          if (!ST.TupleGet) return null;
          var m = ST.attr(np, 'getTightBounds');
          if (m.isNull()) return null;
          var t = ST.TupleNew(1);
          ST.TupleSet(t, 0, ST.incref(rel));
          var r = ST.Call(m, t, ptr(0));
          if (r.isNull()) { ST.clearExc(); return null; }
          var lo = ST.TupleGet(r, 0), hi = ST.TupleGet(r, 1);
          if (lo.isNull() || hi.isNull()) { ST.clearExc(); return null; }
          var b = { x0: ST.callFloat(lo, 'getX', [], null), y0: ST.callFloat(lo, 'getY', [], null),
                    z0: ST.callFloat(lo, 'getZ', [], null), x1: ST.callFloat(hi, 'getX', [], null),
                    y1: ST.callFloat(hi, 'getY', [], null), z1: ST.callFloat(hi, 'getZ', [], null) };
          ST.clearExc();
          if (b.x0 === null || b.x1 === null || b.y0 === null || b.y1 === null) return null;
          return b;
        } catch (e) { ST.clearExc(); return null; }
      };

      ST.centerOf = function (np, rel) {
        try {
          // getTightBounds() returns None for these nodes (Panda gives None when the subgraph has
          // no geometry of its own), so the DirectGUI-native route is PGItem.getFrame(): the
          // widget rect (left, right, bottom, top) in the item's OWN space. Combined with the
          // node's origin and scale relative to `rel`, that is the drawn centre.
          var nodef = ST.attr(np, 'node');
          if (nodef.isNull()) return null;
          var n = ST.Call(nodef, ST.TupleNew(0), ptr(0));
          if (n.isNull()) { ST.clearExc(); return null; }
          var gf = ST.attr(n, 'getFrame');
          if (gf.isNull()) return null;
          var f = ST.Call(gf, ST.TupleNew(0), ptr(0));
          if (f.isNull()) { ST.clearExc(); return null; }
          // LVecBase4: x=left y=right z=bottom w=top
          var l = ST.callFloat(f, 'getX', [], null), r2 = ST.callFloat(f, 'getY', [], null);
          var b = ST.callFloat(f, 'getZ', [], null), t2 = ST.callFloat(f, 'getW', [], null);
          ST.clearExc();
          if (l === null || r2 === null || b === null || t2 === null) return null;
          var ox = ST.callFloat(np, 'getX', [rel], null);
          var oz = ST.callFloat(np, 'getZ', [rel], null);
          if (ox === null || oz === null) return null;
          var sx = ST.callFloat(np, 'getSx', [rel], null);
          var sz = ST.callFloat(np, 'getSz', [rel], null);
          if (sx === null) sx = 1.0;
          if (sz === null) sz = 1.0;
          return { x: ox + ((l + r2) / 2.0) * sx, z: oz + ((b + t2) / 2.0) * sz,
                   w: (r2 - l) * sx, h: (t2 - b) * sz };
        } catch (e) { ST.clearExc(); return null; }
      };

      // NOTE: node names do NOT identify a pickup's kind. A DistributedObject names its own node
      // 'treasure-<doId>' and the child holding the model is named just 'treasure', so neither
      // says whether it is an ice cream, a jellybean bag or a coin bag. `value` is the only
      // discriminator that works -- see the role table above. Do not retry the node-name route.
      // Build a Python int. There is no PyLong_FromLong in the Windows table, but `int` is a
      // builtin and PyFloat_FromDouble is available, so int(float) gets there in one call.
      ST.mkint = function (v) {
        try {
          if (!ST.FloatFromDouble) return ptr(0);
          var bi = ST.builtins();
          var intf = ST.attr(bi, 'int');
          if (intf.isNull()) return ptr(0);
          var f = ST.FloatFromDouble(v);
          if (f.isNull()) return ptr(0);
          var t = ST.TupleNew(1);
          ST.TupleSet(t, 0, f);            // steals the float we just made: correct, do not incref
          var r = ST.Call(intf, t, ptr(0));
          if (r.isNull()) { ST.clearExc(); return ptr(0); }
          return r;
        } catch (e) { ST.clearExc(); return ptr(0); }
      };
      // Put the OS cursor at a pixel inside the game window, using Panda's OWN api. This is the
      // fix for clicking the wrong place: rather than converting fractions to screen pixels
      // ourselves -- and getting window size, DPI and Panda's aspect ratio involved -- we hand
      // Panda window-relative pixels and let it move the pointer. Whatever Panda's MouseWatcher
      // then reads is by construction the point we asked for.
      ST.movePointer = function (px, py) {
        try {
          var bi = ST.builtins();
          var base = ST.attr(bi, 'base');
          if (base.isNull()) return false;
          var win = ST.attr(base, 'win');
          if (win.isNull()) return false;
          var mp = ST.attr(win, 'movePointer');
          if (mp.isNull()) return false;
          var a0 = ST.mkint(0), a1 = ST.mkint(px), a2 = ST.mkint(py);
          if (a0.isNull() || a1.isNull() || a2.isNull()) return false;
          var t = ST.TupleNew(3);
          ST.TupleSet(t, 0, a0); ST.TupleSet(t, 1, a1); ST.TupleSet(t, 2, a2);
          var r = ST.Call(mp, t, ptr(0));
          if (r.isNull()) { ST.clearExc(); return false; }
          ST.clearExc();
          return true;
        } catch (e) { ST.clearExc(); return false; }
      };
      // panda3d.core, straight out of sys.modules (it is always loaded; this is a dict lookup).
      ST.core = function () {
        if (ST._core) return ST._core;
        var md = ST.sysmodules(); if (md.isNull()) return ptr(0);
        var m = ST.DictGetStr(md, Memory.allocUtf8String('panda3d.core'));
        if (m.isNull()) { ST.clearExc(); return ptr(0); }
        ST._core = m; ST.keep.push(m);
        return m;
      };
      // INPUT, IN-PROCESS. A key is pressed on the window's own GraphicsWindowInputDevice -- the
      // object Panda's window proc feeds from real WM_KEYDOWNs -- so the game cannot tell it from
      // a keyboard, and nothing outside the process is involved: no focus change, no cursor, no
      // external tool. Measured identical to a real key: a 0.5s 'a' turns 46.7 deg (model 47.5),
      // a 0.7s 'w' walks 14.60 units (the out-of-process tool measured 14.6).
      // button_down/up take the device's own lock, so calling them from this thread is safe; the
      // event is consumed by the data graph on the game's main thread at its next frame.
      ST.held = {};
      ST.key = function (name, down) {
        try {
          var core = ST.core(); if (core.isNull()) return false;
          // Button handles are process-wide constants, so caching them is safe. The input device
          // is NOT cached: it belongs to the current window, which the game can replace.
          ST.kbh = ST.kbh || {};
          var hk = ST.kbh[name];
          if (!hk) {
            var KB = ST.attr(core, 'KeyboardButton'); if (KB.isNull()) return false;
            hk = ST.callRaw(KB, 'asciiKey', [ST.mkstr(name)]);
            if (hk.isNull()) return false;
            ST.kbh[name] = hk; ST.keep.push(hk);
          }
          var win = ST.attr(ST.attr(ST.builtins(), 'base'), 'win');
          var dev = ST.callRaw(win, 'getInputDevice', [ST.mkint(0)]);
          if (dev.isNull()) return false;
          var r = ST.callRaw(dev, down ? 'buttonDown' : 'buttonUp', [hk]);
          return !r.isNull();
        } catch (e) { ST.clearExc(); return false; }
      };
      ST.release = function (name) {
        var h = ST.held[name];
        if (!h) return;
        clearTimeout(h);
        delete ST.held[name];
        ST.gil(function () { return ST.key(name, false); });
      };
      // Call a bound method / callable with PyObject args, returning the raw result (or NULL).
      // Args are increfed because PyTuple_SetItem steals a reference.
      ST.callRawFn = function (m, args) {
        try {
          if (!m || m.isNull()) return ptr(0);
          // NEVER hand Python a NULL argument: the callee dereferences it and the whole client
          // dies natively, with no exception and no traceback. Refuse the call instead.
          for (var q = 0; args && q < args.length; q++) {
            if (!args[q] || args[q].isNull()) return ptr(0);
          }
          var t = ST.TupleNew(args ? args.length : 0);
          if (t.isNull()) { ST.clearExc(); return ptr(0); }
          for (var i = 0; args && i < args.length; i++) ST.TupleSet(t, i, ST.incref(args[i]));
          var r = ST.Call(m, t, ptr(0));
          if (r.isNull()) { ST.clearExc(); return ptr(0); }
          return r;
        } catch (e) { ST.clearExc(); return ptr(0); }
      };
      ST.callRaw = function (o, name, args) {
        var m = ST.attr(o, name);
        if (m.isNull()) return ptr(0);
        return ST.callRawFn(m, args);
      };
      // obj.<name>() -> int, or null. getWord()/getNumSolids() return Python ints, and callFloat
      // rejects those (it type-checks against PyFloat_Type), which is why every collide mask came
      // back None on the first attempt.
      ST.callInt = function (o, name) {
        try {
          var m = ST.attr(o, name);
          if (m.isNull()) return null;
          var r = ST.Call(m, ST.TupleNew(0), ptr(0));
          if (r.isNull()) { ST.clearExc(); return null; }
          var v = ST.longValue(r);
          ST.clearExc();
          return v;
        } catch (e) { ST.clearExc(); return null; }
      };
      // CPython 3.8 PyLongObject: ob_size @+0x10 (sign + digit count), 30-bit digits from +0x18.
      ST.longValue = function (v) {
        try {
          if (!v || v.isNull() || ST.tpname(v) !== 'int') return null;
          var size = v.add(0x10).readS64();
          if (size === 0) return 0;
          var neg = size < 0, n = neg ? -size : size;
          if (n > 3) return null;
          var d = v.add(0x18).readU32() & 0x3FFFFFFF;
          if (n >= 2) d += (v.add(0x1c).readU32() & 0x3FFFFFFF) * 1073741824;
          if (n >= 3) d += (v.add(0x20).readU32() & 0x3FFFFFFF) * 1152921504606846976;
          return neg ? -d : d;
        } catch (e) { return null; }
      };
      // Small non-negative int attribute (the bag's bean count). Guarded on tp_name so this never
      // reinterprets some other object's bytes as a PyLong; CPython 3.8: ob_size @+0x10, digits
      // (30 bits each) from +0x18.
      ST.intAttr = function (o, name) {
        try {
          var v = ST.attr(o, name);
          if (v.isNull() || ST.tpname(v) !== 'int') return null;
          var size = v.add(0x10).readS64();
          if (size === 0) return 0;
          var neg = size < 0, n = neg ? -size : size;
          if (n > 2) return null;
          var d = v.add(0x18).readU32() & 0x3FFFFFFF;
          if (n === 2) d += (v.add(0x1c).readU32() & 0x3FFFFFFF) * 1073741824;
          return neg ? -d : d;
        } catch (e) { ST.clearExc(); return null; }
      };

      out.ok = true;
      out.slide = slide.toString();
      out.have_unicode = !!ST.UniFromStr;
      return out;
    } catch (e) {
      return { ok: false, notes: ['init threw: ' + e] };
    }
  },

  // --- keys: hold for a duration, released BY THE AGENT --------------------------------------
  // The release is a timer in here, not a second call from the host, so a host that dies or
  // stalls mid-hold cannot strand a key down and walk the toon off into the distance. Holding a
  // key that is already held just re-arms its timer.
  keyHold: function (name, ms) {
    if (ST.held[name]) { clearTimeout(ST.held[name]); delete ST.held[name]; }
    var r = ST.gil(function () { return ST.key(name, true); });
    if (!r.ok || !r.r) return { ok: false, e: r.e || 'buttonDown failed' };
    ST.held[name] = setTimeout(function () { ST.release(name); }, Math.max(1, ms | 0));
    return { ok: true };
  },
  // Release everything this script is holding. Never sends an up for a key it did not press, so
  // it cannot interfere with a player who is steering by hand.
  keysRelease: function () {
    var names = Object.keys(ST.held);
    for (var i = 0; i < names.length; i++) ST.release(names[i]);
    return { ok: true, released: names };
  },
  // Frida calls this right before the script is unloaded: pending timers die with the script, so
  // anything still held would otherwise stay down.
  dispose: function () {
    try { var names = Object.keys(ST ? ST.held : {}); for (var i = 0; i < names.length; i++) ST.release(names[i]); } catch (e) {}
  },

  // --- press a DirectGUI button, IN-PROCESS ----------------------------------------------------
  // No pointer at all. A real click ends with PGButton throwing its click event
  // ('click-mouse1-pg123') onto Panda's global event queue, and DirectButton runs its command when
  // the game's event manager dispatches it. This queues exactly that event, taking the name from
  // the button itself (getClickEvent), so it is dispatched on the game's MAIN thread at its next
  // frame -- the command never runs on this thread. One int parameter stands in for the
  // MouseWatcherParameter a real click carries; DirectButton.commandFunc ignores it.
  // Refuses a button that is hidden or inactive, i.e. one a player could not click either.
  press: function (cfg) {
    return ST.gil(function () {
      var core = ST.core(); if (core.isNull()) return { err: 'no panda3d.core' };
      var a2d = ST.attr(ST.builtins(), 'aspect2d'); if (a2d.isNull()) return { err: 'no aspect2d' };
      var np = ST.callRaw(a2d, 'find', [ST.mkstr('**/' + cfg.name)]);
      if (np.isNull() || ST.callBool(np, 'isEmpty') === true) return { err: 'no button ' + cfg.name };
      if (ST.callBool(np, 'isHidden') === true) return { err: 'hidden' };
      var n = ST.callRaw(np, 'node', []); if (n.isNull()) return { err: 'no node' };
      if (ST.callBool(n, 'getActive') === false) return { err: 'inactive' };
      var one = ST.callRaw(ST.attr(core, 'MouseButton'), 'one', []);
      var evn = ST.callRaw(n, 'getClickEvent', [one]);
      var name = ST.str(evn);
      if (!name) return { err: 'no click event' };
      var ev = ST.callRawFn(ST.attr(core, 'Event'), [evn]);
      var par = ST.callRawFn(ST.attr(core, 'EventParameter'), [ST.mkint(0)]);
      if (ev.isNull() || par.isNull()) return { err: 'cannot build event' };
      if (ST.callRaw(ev, 'addParameter', [par]).isNull()) return { err: 'addParameter failed' };
      var q = ST.callRaw(ST.attr(core, 'EventQueue'), 'getGlobalEventQueue', []);
      if (q.isNull()) return { err: 'no event queue' };
      if (ST.callRaw(q, 'queueEvent', [ev]).isNull()) return { err: 'queueEvent failed' };
      return { queued: name };
    });
  },

  // --- tally the classes of every live distributed object -----------------------------------
  discover: function () {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var base = ST.attr(bi, 'base');
      if (base.isNull()) return { err: 'no base (not in game?)' };
      var seq = ST.doValues(base);
      if (seq === null) return { err: 'no base.cr.doId2do' };
      var tally = {};
      var n = ST.each(seq, function (o) {
        var t = ST.tpname(o);
        tally[t] = (tally[t] || 0) + 1;
      }, 8000);
      return { count: n, classes: tally };
    });
  },

  // --- every TextNode under aspect2d, with its text --------------------------------------------
  // Diagnostic for the button-label path: if this finds nothing, the problem is reading text at
  // all; if it finds text but the buttons do not, the problem is the parent/child relationship.
  guitext: function () {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var a2d = ST.attr(bi, 'aspect2d');
      if (a2d.isNull()) return { err: 'no aspect2d' };
      var fam = ST.attr(a2d, 'findAllMatches');
      var pat = ST.mkstr('**/+TextNode');
      if (fam.isNull() || pat.isNull()) return { err: 'cannot search' };
      var t = ST.TupleNew(1);
      ST.TupleSet(t, 0, pat);
      var col = ST.Call(fam, t, ptr(0));
      if (col.isNull()) { ST.clearExc(); return { err: 'findAllMatches(+TextNode) failed' }; }
      var out = [];
      ST.each(col, function (np) {
        if (out.length >= 60) return;
        var ent = { np_name: ST.callStr(np, 'getName'), tp: null, text: null, via: null };
        var nodef = ST.attr(np, 'node');
        if (!nodef.isNull()) {
          var n = ST.Call(nodef, ST.TupleNew(0), ptr(0));
          if (n.isNull()) { ST.clearExc(); }
          else {
            ent.tp = ST.tpname(n);
            ent.text = ST.callStr(n, 'getText');
            if (ent.text !== null) ent.via = 'node().getText()';
            if (ent.text === null) {
              ent.text = ST.callStr(n, 'getWtext');
              if (ent.text !== null) ent.via = 'node().getWtext()';
            }
          }
        }
        out.push(ent);
      }, 500);
      return { found: out.length, items: out };
    });
  },

  // --- step-limited probe of the wall-extraction calls -------------------------------------------
  // The polygon scan crashed the client twice, once even with a 10 ms budget, so it is a specific
  // call rather than GIL hold time. This runs the pipeline on ONE wall node and stops after
  // `upto` steps; the host calls upto=1,2,3,... as SEPARATE RPCs, so a crash at step N means
  // steps < N are proven safe and step N is the culprit -- one crash to find it, not a series.
  // The node is found with ST.each (proven safe thousands of times), not getPath(i).
  wallProbe: function (upto) {
    return ST.gil(function () {
      var bi = ST.builtins();
      var render = ST.attr(bi, 'render');
      var fam = ST.attr(render, 'findAllMatches');
      var col = ST.callRawFn(fam, [ST.mkstr('**/+CollisionNode')]);
      if (col.isNull()) return { err: 'findAllMatches failed' };
      var found = null;
      ST.each(col, function (np) {
        if (found) return;
        var nm = ST.callStr(np, 'getName') || '';
        if (nm.indexOf('GW.') === 0 || nm.indexOf('distAvatar') === 0 || nm.indexOf('shadowPlacer') >= 0) return;
        var cn = ST.callRaw(np, 'node', []);
        if (cn.isNull()) return;
        var bm = ST.callRaw(cn, 'getIntoCollideMask', []);
        var mask = bm.isNull() ? null : ST.callInt(bm, 'getWord');
        if (mask === null || !(mask & 1)) return;
        if ((ST.callInt(cn, 'getNumSolids') || 0) < 1) return;
        found = { np: np, cn: cn, name: nm };
      }, 3000);
      if (!found) return { err: 'no wall node with solids' };
      var out = { node: found.name, reached: 0 };
      // step 1: getSolid(0)
      var so = ST.callRaw(found.cn, 'getSolid', [ST.mkint(0)]);
      out.reached = 1; out.solid_ok = !so.isNull(); out.type = so.isNull() ? null : ST.tpname(so);
      if (upto <= 1 || so.isNull()) return out;
      // step 2: getNumPoints()
      out.npts = ST.callInt(so, 'getNumPoints');
      out.reached = 2;
      if (upto <= 2) return out;
      // step 3: getPoint(0)
      var lp = ST.callRaw(so, 'getPoint', [ST.mkint(0)]);
      out.reached = 3; out.point_ok = !lp.isNull();
      if (!lp.isNull()) out.local = [ST.callFloat(lp, 'getX', [], null), ST.callFloat(lp, 'getY', [], null)];
      if (upto <= 3 || lp.isNull()) return out;
      // step 4: render.getRelativePoint(np, point)
      var grp = ST.attr(render, 'getRelativePoint');
      var wp = ST.callRawFn(grp, [found.np, lp]);
      out.reached = 4; out.world_ok = !wp.isNull();
      if (!wp.isNull()) out.world = [ST.callFloat(wp, 'getX', [], null), ST.callFloat(wp, 'getY', [], null)];
      return out;
    });
  },

  // --- wall POLYGONS as world-space 2D segments ------------------------------------------------
  // The sphere model cannot represent a long wall: a bounding sphere around a tunnel side or the
  // play-area edge is enormous, so those were filtered out entirely and the bot walked into them.
  // This reads the actual CollisionPolygon vertices of every wall-mask (0x1) node, moves them into
  // world space with render.getRelativePoint(node, point) -- the Point3 returned by getPoint() is
  // passed straight through, so nothing has to be constructed -- and emits each edge as a 2D
  // segment tagged with the polygon's z-range, so the host keeps only walls at toon height.
  //
  // CHUNKED, BY TIME. The first version walked all ~950 collision nodes in ONE call while holding
  // the GIL, so the game could not run a single frame until it finished -- and it crashed the
  // client mid-scan. Now wallsBegin() caches the node collection, and each wallsChunk() processes
  // nodes only until its time budget is spent, then returns a cursor. The host sleeps between
  // chunks, so the game keeps rendering and servicing its connection throughout.
  wallsBegin: function () {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var render = ST.attr(bi, 'render');
      if (render.isNull()) return { err: 'no render' };
      var fam = ST.attr(render, 'findAllMatches');
      var pat = ST.mkstr('**/+CollisionNode');
      if (fam.isNull() || pat.isNull()) return { err: 'cannot search' };
      var col = ST.callRawFn(fam, [pat]);
      if (col.isNull()) return { err: 'findAllMatches failed' };
      var grp = ST.attr(render, 'getRelativePoint');
      if (grp.isNull()) return { err: 'no getRelativePoint' };
      ST.keep.push(col); ST.keep.push(grp);
      ST.wall = { col: col, render: render, grp: grp };
      return { total: ST.callInt(col, 'getNumPaths') };
    });
  },

  // cfg: {start, total, budget_ms, cx, cy, range, max_solids}
  wallsChunk: function (cfg) {
    return ST.gil(function () {
      if (!ST.wall) return { err: 'wallsBegin first' };
      var t0 = Date.now();
      var budget = cfg.budget_ms || 30;
      var maxSolids = cfg.max_solids || 128;
      var near = cfg.range !== undefined && cfg.cx !== undefined;
      var rargs = [ST.wall.render];
      var out = { seg: [], round: [], types: {}, polys: 0, walls: 0, far: 0, calls_ms: 0 };
      var i = cfg.start;
      for (; i < cfg.total; i++) {
        if (Date.now() - t0 >= budget) break;
        var np = ST.callRaw(ST.wall.col, 'getPath', [ST.mkint(i)]);
        if (np.isNull()) continue;
        var nm = ST.callStr(np, 'getName') || '';
        if (nm.indexOf('distAvatarCollNode') === 0 || nm.indexOf('shadowPlacerRay') >= 0 ||
            nm.indexOf('cloudSphere') === 0 || nm.indexOf('treasureSphere') === 0 ||
            nm.indexOf('GW.') === 0 || nm.indexOf('ccLineNode') === 0) continue;
        if (near) {
          // cull on the bounding sphere BEFORE touching any vertex -- the cheap test first
          var bv = ST.callRaw(np, 'getBounds', []);
          var rad = bv.isNull() ? null : ST.callFloat(bv, 'getRadius', [], null);
          var nx = ST.callFloat(np, 'getX', rargs, null), ny = ST.callFloat(np, 'getY', rargs, null);
          if (rad !== null && nx !== null && ny !== null) {
            var dx0 = nx - cfg.cx, dy0 = ny - cfg.cy;
            if (Math.sqrt(dx0 * dx0 + dy0 * dy0) - rad > cfg.range) { out.far++; continue; }
          }
        }
        var cn = ST.callRaw(np, 'node', []);
        if (cn.isNull()) continue;
        var bm = ST.callRaw(cn, 'getIntoCollideMask', []);
        var mask = bm.isNull() ? null : ST.callInt(bm, 'getWord');
        if (mask === null || !(mask & 1)) continue;
        out.walls++;
        var ns = ST.callInt(cn, 'getNumSolids') || 0;
        for (var si = 0; si < ns && si < maxSolids; si++) {
          var so = ST.callRaw(cn, 'getSolid', [ST.mkint(si)]);
          if (so.isNull()) continue;
          var tp = ST.tpname(so);
          out.types[tp] = (out.types[tp] || 0) + 1;
          // ROUND solids (tree trunks, posts) exactly, as a capsule: axis A-B plus radius, with a
          // sphere as the degenerate A == B. These used to be approximated by the whole node's
          // bounding sphere, which is far fatter than what it contains.
          var isSph = tp.indexOf('CollisionSphere') >= 0;          // not CollisionInvSphere
          if (isSph || tp.indexOf('CollisionCapsule') >= 0 || tp.indexOf('CollisionTube') >= 0) {
            var pa = ST.callRaw(so, isSph ? 'getCenter' : 'getPointA', []);
            var pb = isSph ? pa : ST.callRaw(so, 'getPointB', []);
            var rad0 = ST.callFloat(so, 'getRadius', [], null);
            if (pa.isNull() || pb.isNull() || rad0 === null) continue;
            var wa = ST.callRawFn(ST.wall.grp, [np, pa]);
            var wb = isSph ? wa : ST.callRawFn(ST.wall.grp, [np, pb]);
            if (wa.isNull() || wb.isNull()) continue;
            var sc = ST.callFloat(np, 'getSx', rargs, null);
            var rr = rad0 * (sc ? Math.abs(sc) : 1.0);
            var ax = ST.callFloat(wa, 'getX', [], null), ay = ST.callFloat(wa, 'getY', [], null), az = ST.callFloat(wa, 'getZ', [], null);
            var bx = ST.callFloat(wb, 'getX', [], null), by = ST.callFloat(wb, 'getY', [], null), bz = ST.callFloat(wb, 'getZ', [], null);
            if (ax === null || ay === null || az === null || bx === null || by === null || bz === null) continue;
            out.round.push(ax, ay, bx, by, Math.min(az, bz) - rr, Math.max(az, bz) + rr, rr);
            continue;
          }
          if (tp.indexOf('CollisionPolygon') < 0) continue;
          var npts = ST.callInt(so, 'getNumPoints') || 0;
          if (npts < 2 || npts > 64) continue;
          var P = [];
          for (var j = 0; j < npts; j++) {
            var lp = ST.callRaw(so, 'getPoint', [ST.mkint(j)]);
            if (lp.isNull()) { P = null; break; }
            var wp = ST.callRawFn(ST.wall.grp, [np, lp]);
            if (wp.isNull()) { P = null; break; }
            var x = ST.callFloat(wp, 'getX', [], null), y = ST.callFloat(wp, 'getY', [], null);
            var z = ST.callFloat(wp, 'getZ', [], null);
            if (x === null || y === null || z === null) { P = null; break; }
            P.push([x, y, z]);
          }
          if (!P) continue;
          out.polys++;
          var zmin = 1e9, zmax = -1e9;
          for (var k = 0; k < P.length; k++) { if (P[k][2] < zmin) zmin = P[k][2]; if (P[k][2] > zmax) zmax = P[k][2]; }
          for (var k2 = 0; k2 < P.length; k2++) {
            var a = P[k2], bb = P[(k2 + 1) % P.length];
            var ex = bb[0] - a[0], ey = bb[1] - a[1];
            if (ex * ex + ey * ey < 0.01) continue;      // vertical edge: no footprint
            out.seg.push(a[0], a[1], bb[0], bb[1], zmin, zmax);
          }
        }
      }
      out.next = i;
      out.ms = Date.now() - t0;
      return out;
    });
  },

  // --- collision geometry under render ---------------------------------------------------------
  // The bot has had no obstacle awareness at all: walls, buildings and fences are scene-graph
  // COLLISION GEOMETRY, not distributed objects, so they never appear in doId2do. They do appear
  // under render as CollisionNodes, which is the cheapest route to knowing what is in the way.
  //
  // Exploratory: reports how many exist and how many yield usable world-space bounds, because
  // getTightBounds() returns None for nodes with no drawn geometry (learned from the GUI work)
  // and collision solids may well be in that category.
  collision: function (cfg) {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var render = ST.attr(bi, 'render');
      if (render.isNull()) return { err: 'no render' };
      var fam = ST.attr(render, 'findAllMatches');
      var pat = ST.mkstr('**/+CollisionNode');
      if (fam.isNull() || pat.isNull()) return { err: 'cannot search' };
      var t = ST.TupleNew(1);
      ST.TupleSet(t, 0, ST.incref(pat));
      var col = ST.Call(fam, t, ptr(0));
      if (col.isNull()) { ST.clearExc(); return { err: 'findAllMatches(+CollisionNode) failed' }; }

      var lim = (cfg && cfg.limit) || 4000;
      var total = 0, withPos = 0, withRadius = 0, samples = [], tally = {}, out = [];
      ST.each(col, function (np) {
        total++;
        // getTightBounds() is useless here -- it covers DRAWN geometry and collision solids are
        // not drawn (0 of 958 nodes returned any). The node's world position always works, and a
        // coarse size comes from the node's own BoundingVolume, which collision solids do define.
        var x = ST.callFloat(np, 'getX', [render], null);
        var y = ST.callFloat(np, 'getY', [render], null);
        var z = ST.callFloat(np, 'getZ', [render], null);
        if (x === null || y === null) return;
        withPos++;
        var rad = null, cx = null, cy = null, cz = null, mask = null, nsolid = null;
        // A node's INTO collide mask says what it can be collided INTO by. Barriers (walls) and
        // triggers (event spheres, pickup spheres) carry different bits, and only the barriers
        // stop a walking toon -- which is why bounding spheres alone predicted nothing.
        var nodef2 = ST.attr(np, 'node');
        if (!nodef2.isNull()) {
          var cn = ST.Call(nodef2, ST.TupleNew(0), ptr(0));
          if (cn.isNull()) { ST.clearExc(); }
          else {
            var gm = ST.attr(cn, 'getIntoCollideMask');
            if (!gm.isNull()) {
              var bm = ST.Call(gm, ST.TupleNew(0), ptr(0));
              if (bm.isNull()) { ST.clearExc(); }
              else { mask = ST.callInt(bm, 'getWord'); ST.clearExc(); }
            }
            nsolid = ST.callInt(cn, 'getNumSolids');
            ST.clearExc();
          }
        }
        var gb = ST.attr(np, 'getBounds');
        if (!gb.isNull()) {
          var bv = ST.Call(gb, ST.TupleNew(0), ptr(0));
          if (bv.isNull()) { ST.clearExc(); }
          else {
            rad = ST.callFloat(bv, 'getRadius', [], null);
            // A CollisionNode's ORIGIN is not necessarily its solid's centre -- the solid is
            // defined in the node's local space and may be offset. Take the bounding volume's
            // centre and carry it as a local offset so the host can see whether it matters.
            var ctr = ST.attr(bv, 'getCenter');
            if (!ctr.isNull()) {
              var c = ST.Call(ctr, ST.TupleNew(0), ptr(0));
              if (c.isNull()) { ST.clearExc(); }
              else {
                cx = ST.callFloat(c, 'getX', [], null);
                cy = ST.callFloat(c, 'getY', [], null);
                cz = ST.callFloat(c, 'getZ', [], null);
              }
            }
            ST.clearExc();
          }
        }
        if (rad !== null) withRadius++;
        var nm = ST.callStr(np, 'getName') || '?';
        // Keep only things worth steering around. Excluded, and why:
        //   distAvatarCollNode / NPCToon rays  -- other toons MOVE, so a cached snapshot would be
        //                                         stale within seconds (NPCToon bodies are kept)
        //   SC.shadowPlacerRay / GW.cRayNode   -- ground-probe rays, radius 0, not obstacles
        //   cloudSphere                        -- sky decoration, far above the ground
        //   treasureSphere                     -- the PICKUPS; avoiding those defeats the point
        if (cfg && cfg.static_only) {
          if (nm.indexOf('distAvatarCollNode') === 0 || nm.indexOf('shadowPlacerRay') >= 0 ||
              nm.indexOf('cloudSphere') === 0 || nm.indexOf('treasureSphere') === 0 ||
              // GW.* is the local toon's OWN GravityWalker collision (wall sphere, event sphere,
              // ground ray) and ccLineNode is its chat placer -- all sitting exactly at the toon.
              // Treating them as obstacles makes the bot permanently blocked by itself.
              nm.indexOf('GW.') === 0 || nm.indexOf('ccLineNode') === 0 ||
              rad === null || rad <= 0.05) {
            return;
          }
          if (out.length < ((cfg && cfg.limit_out) || 1200)) {
            out.push({ name: nm, x: x, y: y, z: z, r: rad, cx: cx, cy: cy, cz: cz,
                       mask: mask, solids: nsolid });
          }
        }
        // names carry a per-instance id (distAvatarCollNode-112733738); strip it so the tally
        // shows KINDS of collider rather than one row per object
        var key = nm.replace(/[-_]?[0-9]{3,}$/, '');
        if (!tally[key]) tally[key] = { n: 0, rmax: 0 };
        tally[key].n++;
        if (rad !== null && rad > tally[key].rmax) tally[key].rmax = rad;
        if (samples.length < ((cfg && cfg.samples) || 14)) {
          samples.push({ name: nm, x: x, y: y, z: z, r: rad });
        }
      }, lim);
      return { total: total, with_pos: withPos, with_radius: withRadius,
               samples: samples, tally: tally, obstacles: out };
    });
  },

  // --- put the pointer somewhere, via Panda ------------------------------------------------------
  // cfg = {fx, fy} fractions of the render area, or {px, py} raw pixels.
  point: function (cfg) {
    return ST.gil(function () {
      var bi = ST.builtins();
      var base = ST.attr(bi, 'base');
      if (base.isNull()) return { err: 'no base' };
      var win = ST.attr(base, 'win');
      if (win.isNull()) return { err: 'no base.win' };
      var w = ST.callInt(win, 'getXSize'), h = ST.callInt(win, 'getYSize');
      var ar = ST.callFloat(base, 'getAspectRatio', [], null);
      var px = cfg && cfg.px, py = cfg && cfg.py;
      if ((px === undefined || px === null) && cfg && cfg.fx !== undefined && w && h) {
        px = Math.round(cfg.fx * w);
        py = Math.round(cfg.fy * h);
      }
      var ok = null;
      if (px !== undefined && px !== null) ok = ST.movePointer(px, py);
      return { w: w, h: h, aspect: ar, px: px, py: py, moved: ok };
    });
  },

  // --- DirectGUI widget registry ---------------------------------------------------------------
  // Clicking a widget by SCREEN COORDINATE is the fragile half of driving this game: it depends on
  // window size, DPI, the real cursor position (Panda reads the device, not the posted message)
  // and focus. DirectGUI keeps every widget in a registry keyed by the same `<class>-pg<id>` name
  // the scene graph reports, so the robust path is to look the widget up and invoke its command
  // in-process -- no coordinates at all. `direct.gui.DirectGuiBase` is Panda's own module, not
  // vault-hashed, so it resolves by name.
  guiregistry: function (key) {
    return ST.gil(function () {
      var md = ST.sysmodules();
      if (md.isNull()) return { err: 'no sys.modules' };
      var mod = ST.DictGetStr(md, Memory.allocUtf8String('direct.gui.DirectGuiBase'));
      if (mod.isNull()) {
        ST.clearExc();
        // Not under its canonical name: this engine bundles/renames modules, so report the
        // candidates rather than guessing at another spelling.
        var keysf = ST.attr(md, 'keys');
        var cands = [];
        if (!keysf.isNull()) {
          var kseq = ST.Call(keysf, ST.TupleNew(0), ptr(0));
          if (kseq.isNull()) { ST.clearExc(); }
          else {
            ST.each(kseq, function (k) {
              var t = ST.str(k);
              if (t && cands.length < 60 && (t.indexOf('gui') >= 0 || t.indexOf('Gui') >= 0 ||
                                             t.indexOf('direct') === 0)) cands.push(t);
            }, 6000);
          }
        }
        return { err: 'no direct.gui.DirectGuiBase', candidates: cands };
      }
      var cls = ST.attr(mod, 'DirectGuiWidget');
      if (cls.isNull()) return { err: 'no DirectGuiWidget' };
      var gd = ST.attr(cls, 'guiDict');
      if (gd.isNull()) return { err: 'no guiDict' };

      if (!key) {
        var keysf = ST.attr(gd, 'keys');
        if (keysf.isNull()) return { err: 'guiDict has no .keys' };
        var kseq = ST.Call(keysf, ST.TupleNew(0), ptr(0));
        if (kseq.isNull()) { ST.clearExc(); return { err: 'keys() failed' }; }
        var ks = [];
        var n = ST.each(kseq, function (k) { if (ks.length < 400) { var t = ST.str(k); if (t) ks.push(t); } }, 2000);
        return { count: n, keys: ks };
      }

      var w = ST.DictGetStr(gd, Memory.allocUtf8String(key));
      if (w.isNull()) { ST.clearExc(); return { err: 'no widget ' + key }; }
      var dirf = ST.attr(ST.builtins(), 'dir');
      var attrs = [];
      if (!dirf.isNull()) {
        var t2 = ST.TupleNew(1);
        ST.TupleSet(t2, 0, ST.incref(w));
        var lst = ST.Call(dirf, t2, ptr(0));
        if (lst.isNull()) { ST.clearExc(); }
        else { ST.each(lst, function (o) { var nm = ST.str(o); if (nm && nm.charAt(0) !== '_') attrs.push(nm); }, 600); }
      }
      return { cls: ST.tpname(w), attrs: attrs };
    });
  },

  // --- on-screen DirectGUI buttons ------------------------------------------------------------
  // Clickable widgets read from the SCENE GRAPH rather than guessed from pixels. Panda puts 2-D UI
  // under aspect2d, and a DirectGUI button is a PGButton node, so `**/+PGButton` enumerates every
  // one of them with its real name -- and the TextNode beneath it carries the visible label.
  //
  // Coordinates come back in aspect2d space (x in [-aspect, +aspect], z in [-1, 1], origin centre)
  // because the agent has no idea how big the window is; the host converts to fractions.
  buttons: function () {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var a2d = ST.attr(bi, 'aspect2d');
      if (a2d.isNull()) return { err: 'no aspect2d' };
      var fam = ST.attr(a2d, 'findAllMatches');
      if (fam.isNull()) return { err: 'aspect2d has no findAllMatches' };
      var pat = ST.mkstr('**/+PGButton');
      if (pat.isNull()) return { err: 'no PyUnicode_FromString' };
      var t = ST.TupleNew(1);
      ST.TupleSet(t, 0, pat);
      var col = ST.Call(fam, t, ptr(0));
      if (col.isNull()) { ST.clearExc(); return { err: 'findAllMatches(+PGButton) failed' }; }

      var out = [];
      ST.each(col, function (np) {
        if (out.length >= 80) return;
        // Hidden widgets outnumber visible ones -- every closed panel leaves its buttons parented
        // but stashed -- so a list that ignored visibility would be mostly noise.
        var hidden = ST.callBool(np, 'isHidden');
        if (hidden === true) return;
        var ent = { name: ST.callStr(np, 'getName'), text: null, w: null, h: null, geom: [], active: null };
        // What the button LOOKS like, by name. PGButton keeps its art in per-state subgraphs that
        // are not children in the scene graph, so this reads state 0 (ready). Model node names are
        // not vault-hashed and say what a control is -- the HUD reads 'BookIcon_CLSD',
        // 'FriendsBox_Closed', 'ChtBx_ChtBtn_UP' -- which is how a panel's close button is told
        // apart from its Buy button without a screenshot.
        //
        // The LABEL lives there too, and not always in state 0: the Picnic Games exit button (art
        // 'CrtAtoon_Btn2_UP', Make-a-Toon's cancel) is blank when idle and reads "Cancel" only in
        // its rollover/pressed states. So take the first non-empty text from any state.
        var pn = ST.callRaw(np, 'node', []);
        if (!pn.isNull()) {
          ent.active = ST.callBool(pn, 'getActive');
          var nsd = Math.min(ST.callInt(pn, 'getNumStateDefs') || 0, 4);
          for (var si = 0; si < nsd; si++) {
            var sd = ST.callRaw(pn, 'getStateDef', [ST.mkint(si)]);
            if (sd.isNull()) continue;
            if (si === 0) {
              var gs = ST.callRaw(sd, 'findAllMatches', [ST.mkstr('**')]);
              if (!gs.isNull()) {
                ST.each(gs, function (g) {
                  var gn = ST.callStr(g, 'getName');
                  if (gn && gn.indexOf('state_') !== 0 && ent.geom.length < 12) ent.geom.push(gn);
                }, 60);
              }
            }
            if (ent.text) continue;
            var st = ST.callRaw(sd, 'findAllMatches', [ST.mkstr('**/+TextNode')]);
            if (st.isNull()) continue;
            ST.each(st, function (tn) {
              if (ent.text) return;
              var nd = ST.callRaw(tn, 'node', []);
              var s0 = nd.isNull() ? null : ST.callStr(nd, 'getText');
              if (s0 && s0.replace(/\s/g, '').length) ent.text = s0;
            }, 8);
          }
        }
        var c = ST.centerOf(np, a2d);
        if (c) { ent.x = c.x; ent.z = c.z; ent.w = c.w; ent.h = c.h; }
        else {   // no drawn geometry: fall back to the node origin
          ent.x = ST.callFloat(np, 'getX', [a2d], null);
          ent.z = ST.callFloat(np, 'getZ', [a2d], null);
        }
        // The visible label is a TextNode somewhere beneath the button.
        var tfam = ST.attr(np, 'findAllMatches');
        if (!tfam.isNull()) {
          var tp = ST.mkstr('**/+TextNode');
          if (!tp.isNull()) {
            var tt = ST.TupleNew(1);
            ST.TupleSet(tt, 0, tp);
            var tcol = ST.Call(tfam, tt, ptr(0));
            if (tcol.isNull()) { ST.clearExc(); }
            else {
              ST.each(tcol, function (tn) {
                if (ent.text) return;
                var node = ST.attr(tn, 'node');
                if (node.isNull()) return;
                var n = ST.Call(node, ST.TupleNew(0), ptr(0));
                if (n.isNull()) { ST.clearExc(); return; }
                var s = ST.callStr(n, 'getText');
                if (s && s.replace(/\s/g, '').length) ent.text = s;
              }, 12);
            }
          }
        }
        out.push(ent);
      }, 400);
      var base = ST.attr(bi, 'base');
      return { buttons: out, aspect: base.isNull() ? null : ST.callFloat(base, 'getAspectRatio', [], null) };
    });
  },

  // --- scene-graph node names under render ---------------------------------------------------
  nodes: function (pattern) {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var render = ST.attr(bi, 'render');
      if (render.isNull()) return { err: 'no render' };
      var fam = ST.attr(render, 'findAllMatches');
      if (fam.isNull()) return { err: 'render has no findAllMatches' };
      var pat = ST.mkstr(pattern || '**');
      if (pat.isNull()) return { err: 'no PyUnicode_FromString -- cannot build pattern' };
      var t = ST.TupleNew(1);
      ST.TupleSet(t, 0, pat);
      var col = ST.Call(fam, t, ptr(0));
      if (col.isNull()) { ST.clearExc(); return { err: 'findAllMatches failed' }; }
      var tally = {};
      var n = ST.each(col, function (np) {
        var g = ST.attr(np, 'getName');
        if (g.isNull()) return;
        var r = ST.Call(g, ST.TupleNew(0), ptr(0));
        if (r.isNull()) { ST.clearExc(); return; }
        var s = ST.str(r);
        if (s) tally[s] = (tally[s] || 0) + 1;
      }, 6000);
      return { count: n, names: tally };
    });
  },

  // --- dir() any dotted path off builtins -----------------------------------------------------
  // Diagnostic: the vault hashes CLASS names but not attribute/method names, so dir() is how we
  // find out what an object really is (the same lever scanBySignature uses in the injector).
  probe: function (path) {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var cur = bi;
      var parts = String(path || '').split('.');
      for (var i = 0; i < parts.length; i++) {
        if (!parts[i]) continue;
        cur = ST.attr(cur, parts[i]);
        if (cur.isNull()) return { err: 'missing attribute: ' + parts[i] };
      }
      var dirf = ST.attr(bi, 'dir');
      if (dirf.isNull()) return { err: 'no builtins.dir' };
      var t = ST.TupleNew(1);
      ST.TupleSet(t, 0, ST.incref(cur));
      var lst = ST.Call(dirf, t, ptr(0));
      if (lst.isNull()) { ST.clearExc(); return { err: 'dir() failed' }; }
      var names = [];
      ST.each(lst, function (o) { var s = ST.str(o); if (s) names.push(s); }, 4000);
      return { cls: ST.tpname(cur), count: names.length, names: names };
    });
  },

  // --- identify each distributed-object class by its METHOD names -----------------------------
  // Class names are vault hashes (vlt3b810b5c); method names are not. One representative per
  // class gets dir()'d, so a bag announces itself by what it can DO.
  classes: function () {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var base = ST.attr(bi, 'base');
      if (base.isNull()) return { err: 'no base' };
      var seq = ST.doValues(base);
      if (seq === null) return { err: 'no base.cr.doId2do' };
      var dirf = ST.attr(bi, 'dir');
      if (dirf.isNull()) return { err: 'no builtins.dir' };
      var seen = {};
      ST.each(seq, function (o) {
        var t = ST.tpname(o) || '?';
        if (seen[t]) { seen[t].n++; return; }
        var ent = { n: 1, methods: [] };
        var tu = ST.TupleNew(1);
        ST.TupleSet(tu, 0, ST.incref(o));
        var lst = ST.Call(dirf, tu, ptr(0));
        if (lst.isNull()) { ST.clearExc(); }
        else {
          ST.each(lst, function (s) {
            var nm = ST.str(s);
            if (nm && nm.charAt(0) !== '_') ent.methods.push(nm);
          }, 4000);
        }
        seen[t] = ent;
      }, 8000);
      return { classes: seen };
    });
  },

  // --- one world-state read -------------------------------------------------------------------
  // Objects are identified by SIGNATURE, never by the vlt* hash: the vault renames every TTR
  // identifier per build (that is why base.localAvatar does not exist -- 'localAvatar' is hashed),
  // but it cannot rename inherited framework attributes. So:
  //    local toon  = the object exposing `tunnelOut`      (LocalToon; vlt725d40df on this build)
  //    bag         = a treasure that also has `value`     (vlt433b51a4) -- BOTH the jellybean bags
  //                  and the Cartoonival coin bags land here; they share one class and differ
  //                  only in `value`, so nothing distinguishes them and nothing needs to
  //    treasure    = `treasure` WITHOUT `value`           (vltb3cf91ab) -- ice cream / laff
  //                  restores. Not worth chasing: a toon at full laff walks straight through.
  // The signature test costs several getattrs, so it runs ONCE PER CLASS and is then cached by
  // tp_name; steady-state ticks are pure pointer reads.
  state: function (cfg) {
    return ST.gil(function () {
      var bi = ST.builtins();
      if (bi.isNull()) return { err: 'no builtins' };
      var base = ST.attr(bi, 'base');
      if (base.isNull()) return { err: 'no base' };
      var render = ST.attr(bi, 'render');
      var rargs = render.isNull() ? [] : [render];
      var seq = ST.doValues(base);
      if (seq === null) return { err: 'no base.cr.doId2do' };

      // BOTH treasure kinds are chased. `value` (bean count) exists only on the valued kind, so a
      // plain treasure simply reports value:null -- it is still a target, not a lesser one.
      var out = { me: null, targets: [] };
      var lim = (cfg && cfg.limit) || 40;
      ST.each(seq, function (o) {
        var role = ST.roleOf(o);
        if (role === 'me') {
          if (out.me) return;
          var p = ST.posOf(o, rargs, 'me');
          if (!p) return;
          // `ref` identifies THIS toon object: a logout and re-login creates a new one, which the
          // host uses to drop everything it learned about the previous session.
          out.me = { cls: ST.tpname(o), ref: o.toString(), x: p.x, y: p.y, z: p.z,
                     h: ST.callFloat(o, 'getH', rargs, 'me.h') };
        } else if (role === 'bag' || role === 'treasure') {
          if (out.targets.length >= lim) return;
          var q = ST.posOf(o, rargs, null);
          if (!q) return;
          out.targets.push({ kind: role, x: q.x, y: q.y, z: q.z,
                             value: role === 'bag' ? ST.intAttr(o, 'value') : null });
        }
      }, 8000);
      if (!out.me) return { err: 'local toon not found (not in world yet?)' };
      return out;
    });
  }
};
"""


def make_exports(session, verbose=False):
    """Create the read-only script on an EXISTING session. Returns (exports, script).

    Split out of attach() so the INJECTOR can share its own session rather than opening a second
    one on the same process: frida allows several scripts per session, so the mods and this
    read-only reader cost exactly one attach between them. Fewer attaches is the point -- the
    client uploads a Sentry minidump naming frida-agent if it ever crashes while attached.
    """
    syms = TI.load_symbols()
    need = ["PyObject_Call", "PyObject_GetAttrString", "PyDict_GetItemString", "PyTuple_New",
            "PyTuple_SetItem", "PyGILState_Ensure", "PyGILState_Release"]
    missing = [n for n in need if n not in syms]
    if missing:
        raise SystemExit("worldstate: per-build table is missing %s -- see STATUS.md"
                         % ", ".join(missing))
    script = session.create_script(JS)
    script.load()
    ex = script.exports_sync
    init = ex.init({
        "image_base": hex(TI.IMAGE_BASE),
        "syms": {k: {"vmaddr": hex(v["vmaddr"])} for k, v in syms.items()},
        "tstate_cell": TI.TSTATE_CELL,
        "interp_off": TI.INTERP_OFF, "modules_off": TI.MODULES_OFF,
        "float_type": TI.FLOAT_TYPE,
        "py_true": TRUE_OBJ, "py_false": FALSE_OBJ,
    })
    if not init.get("ok"):
        raise SystemExit("worldstate: init failed: %s" % init.get("notes"))
    if verbose:
        print("[ws] read-only script loaded, slide %s" % init.get("slide"), file=sys.stderr)
    # Returns the script too so the caller can unload this BEFORE reverting and detaching. Leaving
    # two scripts to be torn down together by detach is an untested interleaving, and the
    # injector's revert path is the one thing in this repo that must never be disturbed.
    return ex, script


def attach(verbose=True):
    """Attach read-only and return (session, exports). Raises on failure."""
    import frida
    syms = TI.load_symbols()
    need = ["PyObject_Call", "PyObject_GetAttrString", "PyDict_GetItemString", "PyTuple_New",
            "PyTuple_SetItem", "PyGILState_Ensure", "PyGILState_Release"]
    missing = [n for n in need if n not in syms]
    if missing:
        raise SystemExit("worldstate: per-build table is missing %s -- see STATUS.md"
                         % ", ".join(missing))

    pids = TI.find_engine_pids()
    pid = pids[0]
    session = __import__("frida").get_local_device().attach(pid)
    ex, _script = make_exports(session, verbose=False)
    if verbose:
        print("[ws] attached pid %d" % pid, file=sys.stderr)
    return session, ex


def a2d_to_fraction(x, z, aspect):
    """aspect2d coords -> client-area fractions (0..1 from the top-left), for display.

    Panda's 2-D UI space has the origin at the CENTRE, x spanning [-aspect, +aspect] and z spanning
    [-1, 1] with +z up. Screen fractions run [0, 1] from the top-left, hence the flip on z.

    Cross-checked against a coordinate found the hard way months earlier: the Shticker Book button
    reads (1.509, -0.830) here, which converts to (0.953, 0.915) -- the old empirically-tuned value
    was (0.969, 0.924). Reading the widget beats eyeballing the screenshot, and agrees with it.
    """
    if x is None or z is None:
        return None
    return (0.5 + x / (2.0 * aspect), 0.5 - z / 2.0)


def fetch_walls(ex, cx, cy, rng=150.0, budget_ms=30, pause=0.03, log=None):
    """Wall geometry near (cx, cy), gathered in GIL-releasing chunks. Returns (segs, rounds, stats).

    segs    polygon edges   (x1, y1, x2, y2, zmin, zmax)
    rounds  spheres/capsules (x1, y1, x2, y2, zmin, zmax, radius) -- a sphere has A == B

    Each chunk holds the GIL for at most `budget_ms`, then this sleeps `pause` so the game runs a
    few frames before the next one. A single all-at-once pass over the scene crashed the client.
    """
    b = ex.walls_begin()
    if not b.get("ok") or (b.get("r") or {}).get("err"):
        return [], [], {"err": (b.get("r") or {}).get("err") or b.get("e")}
    total = (b.get("r") or {}).get("total") or 0
    segs, rounds, types, worst, chunks, start = [], [], {}, 0, 0, 0
    while start < total:
        r = ex.walls_chunk({"start": start, "total": total, "budget_ms": budget_ms,
                            "cx": cx, "cy": cy, "range": rng})
        if not r.get("ok"):
            break
        c = r.get("r") or {}
        if c.get("err"):
            break
        seg = c.get("seg") or []
        for i in range(0, len(seg), 6):
            segs.append(tuple(seg[i:i + 6]))
        rnd = c.get("round") or []
        for i in range(0, len(rnd), 7):
            rounds.append(tuple(rnd[i:i + 7]))
        for k, v in (c.get("types") or {}).items():
            types[k] = types.get(k, 0) + v
        worst = max(worst, c.get("ms") or 0)
        chunks += 1
        if c.get("next", start) <= start:     # no progress: bail rather than spin
            break
        start = c["next"]
        time.sleep(pause)
    return segs, rounds, {"total": total, "chunks": chunks, "worst_ms": worst, "types": types}


def unwrap(res, what):
    """frida gives back {ok, r} / {ok:false, e}; flatten it or die with the reason."""
    if not isinstance(res, dict):
        raise SystemExit("worldstate: %s returned %r" % (what, res))
    if not res.get("ok"):
        raise SystemExit("worldstate: %s failed: %s" % (what, res.get("e")))
    return res.get("r") or {}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=["discover", "nodes", "state", "watch", "probe", "classes",
                                     "buttons", "guitext", "collision", "gui", "walls",
                                     "press", "key"])
    ap.add_argument("--match", action="append", default=[],
                    help="substring of the pickup class name (repeatable)")
    ap.add_argument("--path", default="base", help="probe: dotted attribute path from builtins; "
                    "press: the button's node name; key: the key")
    ap.add_argument("--ms", type=int, default=300, help="key: how long to hold it")
    ap.add_argument("--pattern", default="**", help="nodes: scene-graph pattern")
    ap.add_argument("--hz", type=float, default=2.0, help="watch: reads per second")
    ap.add_argument("--top", type=int, default=60, help="discover/nodes: how many rows to print")
    a = ap.parse_args()

    session, ex = attach()
    try:
        if a.mode == "discover":
            r = unwrap(ex.discover(), "discover")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            print("%d distributed objects\n" % r["count"])
            for cls, n in sorted(r["classes"].items(), key=lambda kv: -kv[1])[:a.top]:
                print("  %5d  %s" % (n, cls))
        elif a.mode == "nodes":
            r = unwrap(ex.nodes(a.pattern), "nodes")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            print("%d nodes under render matching %s\n" % (r["count"], a.pattern))
            for nm, n in sorted(r["names"].items(), key=lambda kv: -kv[1])[:a.top]:
                print("  %5d  %s" % (n, nm))
        elif a.mode == "collision":
            r = unwrap(ex.collision({}), "collision")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            print("%d CollisionNodes under render; %d gave a world position, %d a radius"
                  % (r["total"], r["with_pos"], r["with_radius"]))
            print()
            print("%-40s %7s %9s" % ("collider kind", "count", "max r"))
            for k, v in sorted((r.get("tally") or {}).items(), key=lambda kv: -kv[1]["n"])[:30]:
                print("  %-38s %7d %9.1f" % (k[:38], v["n"], v["rmax"]))
        elif a.mode == "walls":
            me = ((ex.state({}).get("r") or {}).get("me")) or {}
            t0 = time.time()
            segs, rounds, st = fetch_walls(ex, me.get("x", 0.0), me.get("y", 0.0))
            if st.get("err"):
                raise SystemExit("worldstate: %s" % st["err"])
            print("%d collision nodes in %d chunks, %.1fs wall-clock; longest GIL hold %d ms"
                  % (st["total"], st["chunks"], time.time() - t0, st["worst_ms"]))
            print("%d wall segments and %d round solids near the toon" % (len(segs), len(rounds)))
            for k, v in sorted(st["types"].items(), key=lambda kv: -kv[1]):
                print("   %6d  %s" % (v, k))
        elif a.mode == "gui":
            r = unwrap(ex.guiregistry(a.path if a.path != "base" else None), "gui")
            if r.get("err"):
                if r.get("candidates"):
                    print("%s; candidate modules:" % r["err"])
                    for c in r["candidates"]:
                        print("   %s" % c)
                    return 0
                raise SystemExit("worldstate: %s" % r["err"])
            if "keys" in r:
                print("%d widgets in DirectGUI's registry; first 40:" % r["count"])
                for k in r["keys"][:40]:
                    print("   %s" % k)
            else:
                print("%s -> %s" % (a.path, r["cls"]))
                ats = r["attrs"]
                for i in range(0, len(ats), 4):
                    print("  " + "".join("%-28s" % x for x in ats[i:i + 4]))
        elif a.mode == "guitext":
            r = unwrap(ex.guitext(), "guitext")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            print("%d TextNodes under aspect2d" % r["found"])
            print()
            for it in r["items"]:
                print("  %-26s %-20s via=%-20s %r"
                      % (str(it.get("np_name"))[:26], str(it.get("tp"))[:20],
                         it.get("via"), it.get("text")))
        elif a.mode == "buttons":
            r = unwrap(ex.buttons(), "buttons")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            bs = r["buttons"]
            print("%d visible DirectGUI buttons" % len(bs))
            print()
            asp = r.get("aspect") or 16.0 / 9.0
            print("aspect %.3f" % asp)
            print("%-30s %-18s %8s %8s   %-12s %s" % ("name", "label", "x", "z", "screen at", "art"))
            for b in bs:
                f = a2d_to_fraction(b.get("x"), b.get("z"), asp)
                print("%-30s %-18s %8s %8s   %-12s %s%s"
                      % (str(b.get("name"))[:30], " ".join(str(b.get("text")).split())[:18],
                         "-" if b.get("x") is None else "%.3f" % b["x"],
                         "-" if b.get("z") is None else "%.3f" % b["z"],
                         "-" if f is None else "%.3f,%.3f" % f,
                         " ".join(b.get("geom") or [])[:60],
                         "" if b.get("active") is not False else "  (inactive)"))
        elif a.mode == "press":
            print(json.dumps(unwrap(ex.press({"name": a.path}), "press")))
            time.sleep(0.5)                  # let the game dispatch it before we detach
        elif a.mode == "key":
            me0 = (unwrap(ex.state({}), "state").get("me")) or {}
            print(json.dumps(ex.key_hold(a.path, a.ms)))
            time.sleep(a.ms / 1000.0 + 0.4)
            me1 = (unwrap(ex.state({}), "state").get("me")) or {}
            if me0 and me1:
                print("turned %+.1f deg, moved %.2f units"
                      % (((me1["h"] - me0["h"] + 180.0) % 360.0) - 180.0,
                         ((me1["x"] - me0["x"]) ** 2 + (me1["y"] - me0["y"]) ** 2) ** 0.5))
        elif a.mode == "probe":
            r = unwrap(ex.probe(a.path), "probe")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            print("%s -> %s  (%d attrs)\n" % (a.path, r["cls"], r["count"]))
            names = r["names"]
            for i in range(0, len(names), 4):
                print("  " + "".join("%-30s" % n for n in names[i:i + 4]))
        elif a.mode == "classes":
            r = unwrap(ex.classes(), "classes")
            if r.get("err"):
                raise SystemExit("worldstate: %s" % r["err"])
            for cls, ent in sorted(r["classes"].items(), key=lambda kv: -kv[1]["n"]):
                print("\n=== %s  (x%d, %d public attrs)" % (cls, ent["n"], len(ent["methods"])))
                ms = ent["methods"]
                for i in range(0, len(ms), 4):
                    print("  " + "".join("%-30s" % m for m in ms[i:i + 4]))
        elif a.mode == "state":
            print(json.dumps(unwrap(ex.state({"match": a.match}), "state"), indent=1))
        else:
            period = 1.0 / max(a.hz, 0.1)
            while True:
                t0 = time.perf_counter()
                try:
                    print(json.dumps(unwrap(ex.state({"match": a.match}), "state")), flush=True)
                except SystemExit as e:
                    print(json.dumps({"err": str(e)}), flush=True)
                dt = period - (time.perf_counter() - t0)
                if dt > 0:
                    time.sleep(dt)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
