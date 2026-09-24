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
      // obj.<name>(...args) -> float, or null. `cacheKey` reuses the bound method across ticks.
      ST.callFloat = function (o, name, args, cacheKey) {
        try {
          var m = ptr(0);
          if (cacheKey && ST.mcache[cacheKey]) m = ST.mcache[cacheKey];
          else {
            m = ST.attr(o, name);
            if (m.isNull()) return null;
            if (cacheKey) { ST.mcache[cacheKey] = m; ST.keep.push(m); }
          }
          var t = ST.TupleNew(args ? args.length : 0);
          if (t.isNull()) { ST.clearExc(); return null; }
          for (var i = 0; args && i < args.length; i++) ST.TupleSet(t, i, args[i]);
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
      // NOTE: node names do NOT identify a pickup's kind. A DistributedObject names its own node
      // 'treasure-<doId>' and the child holding the model is named just 'treasure', so neither
      // says whether it is an ice cream, a jellybean bag or a coin bag. `value` is the only
      // discriminator that works -- see the role table above. Do not retry the node-name route.
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
        var ent = {
          name: ST.callStr(np, 'getName'),
          x: ST.callFloat(np, 'getX', [a2d], null),
          z: ST.callFloat(np, 'getZ', [a2d], null),
          text: null
        };
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
      return { buttons: out };
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
      ST.TupleSet(t, 0, cur);
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
        ST.TupleSet(tu, 0, o);
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
          out.me = { cls: ST.tpname(o), x: p.x, y: p.y, z: p.z,
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
        session.detach()
        raise SystemExit("worldstate: init failed: %s" % init.get("notes"))
    if verbose:
        print("[ws] attached pid %d, slide %s" % (pid, init.get("slide")), file=sys.stderr)
    return session, ex


def a2d_to_fraction(x, z, aspect):
    """aspect2d coords -> client-area fractions, ready for winctl.inputs.click.

    Panda's 2-D UI space has the origin at the CENTRE, x spanning [-aspect, +aspect] and z spanning
    [-1, 1] with +z up. Screen fractions run [0, 1] from the top-left, hence the flip on z.

    Cross-checked against a coordinate found the hard way months earlier: the Shticker Book button
    reads (1.509, -0.830) here, which converts to (0.953, 0.915) -- the old empirically-tuned value
    was (0.969, 0.924). Reading the widget beats eyeballing the screenshot, and agrees with it.
    """
    if x is None or z is None:
        return None
    return (0.5 + x / (2.0 * aspect), 0.5 - z / 2.0)


def game_aspect(default=16.0 / 9.0):
    """Client width/height of the live game window, or `default` if winctl is unavailable."""
    try:
        from winctl import windows
        w = windows.list_windows(cls="WinGraphicsWindow0")
        if w and w[0].get("clientH"):
            return float(w[0]["clientW"]) / float(w[0]["clientH"])
    except Exception:
        pass
    return default


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
                                     "buttons", "guitext"])
    ap.add_argument("--match", action="append", default=[],
                    help="substring of the pickup class name (repeatable)")
    ap.add_argument("--path", default="base", help="probe: dotted attribute path from builtins")
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
            asp = game_aspect()
            print("aspect %.3f" % asp)
            print("%-30s %-24s %8s %8s   %s" % ("name", "label", "x", "z", "click at"))
            for b in bs:
                f = a2d_to_fraction(b.get("x"), b.get("z"), asp)
                print("%-30s %-24s %8s %8s   %s"
                      % (str(b.get("name"))[:30], str(b.get("text"))[:24],
                         "-" if b.get("x") is None else "%.3f" % b["x"],
                         "-" if b.get("z") is None else "%.3f" % b["z"],
                         "-" if f is None else "%.3f,%.3f" % f))
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
