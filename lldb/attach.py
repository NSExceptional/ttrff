# attach.py -- runs inside lldb (`command script import`).
#
# Attaches to a running TTREngine, resolves the (stripped) CPython C-API
# functions from vmaddrs supplied by the driver, verifies the prologue bytes,
# then runs an injected Python bootstrap.
#
# TTR's frozen Panda3D "deploy-stub" build DEAD-STRIPS the whole PyRun_* family
# AND the bytecode compiler, and exec/eval are code-object-only. The real
# primitive for this build is "marshal_evalcode"; the two string-based ones are
# kept only for other/hypothetical builds. Selected by job["primitive"]:
#
#   "marshal_evalcode" (the one that works on shipping TTR):
#       gil  = PyGILState_Ensure()
#       buf  = <lldb AllocateMemory + WriteMemory of the 3.7 marshal blob>
#       ba   = PyByteArray_FromStringAndSize(buf, len)   # copies; then free buf
#       co   = marshal.loads(0, ba)                       # METH_O: (mod, arg)
#       # PyModule_GetDict/AddModule are inlined, so read f_globals off the frame:
#       tstate = *(void**)(current_tstate_ptr + slide)
#       gd     = *(void**)(*(void**)(tstate + 24) + 48)   # frame->f_globals
#       res  = PyEval_EvalCode(co, gd, gd)
#       if !res: PyErr_PrintEx(1)
#       PyGILState_Release(gil)
#     addr keys: gil_ensure, gil_release, bytes_from_string_and_size,
#                marshal_loads, eval_code, [err_printex]
#     job also needs: payload_marshal_hex, globals_from_frame
#
#   "exec_builtins" (legacy, dead-stripped here):
#       gil  = PyGILState_Ensure()
#       bmod = PyImport_ImportModule("builtins")
#       main = PyImport_AddModule("__main__")
#       gd   = PyModule_GetDict(main)
#       res  = PyObject_CallMethod(bmod, "exec", "sO", bootstrap, gd)
#       if !res and err_print: PyErr_Print()
#       PyGILState_Release(gil)
#     addr keys: ensure, release, import_module, add_module, module_getdict,
#                call_method, [err_print]
#
#   "compile_eval" (fallback):
#       gil  = PyGILState_Ensure()
#       main = PyImport_AddModule("__main__"); gd = PyModule_GetDict(main)
#       code = Py_CompileStringExFlags(bootstrap, "<ttrmod>", 257, NULL, -1)
#       res  = PyEval_EvalCode(code, gd, gd)
#       if !res and err_print: PyErr_Print()
#       PyGILState_Release(gil)
#     addr keys: ensure, release, add_module, module_getdict, compile, eval,
#                [err_print]
#
# The bootstrap string is `exec(bytes.fromhex('..').decode('utf-8'))` -- pure
# ASCII, only single-quotes -- so it drops cleanly into a C string literal.
#
# Job (env TTRMOD_JOB, JSON):
#   { "pid", "exe", "image_base_vmaddr", "primitive",
#     "addrs": {name: vmaddr, ...}, "verify": {name: "aa bb ..", ...},
#     "bootstrap": "<python one-liner>" }
# Result JSON -> env TTRMOD_JOB + ".result".

import os
import json
import lldb


def _load_base(target, exe):
    """Runtime load address of the main executable's Mach-O header."""
    fs = lldb.SBFileSpec(exe)
    mod = target.FindModule(fs)
    if not mod or not mod.IsValid():
        # fall back: first module is the executable
        mod = target.GetModuleAtIndex(0)
    hdr = mod.GetObjectFileHeaderAddress()
    return hdr.GetLoadAddress(target), mod


def _read_bytes(process, addr, n):
    err = lldb.SBError()
    data = process.ReadMemory(addr, n, err)
    if not err.Success():
        return None
    return bytes(data)


def _verify(process, addr, hexpat):
    if not hexpat:
        return True, "no-verify"
    want = bytes(int(b, 16) for b in hexpat.split())
    got = _read_bytes(process, addr, len(want))
    if got is None:
        return False, "read failed"
    if got != want:
        return False, "prologue mismatch got=%s" % (" ".join("%02x" % c for c in got))
    return True, "ok"


def run(debugger):
    job_path = os.environ["TTRMOD_JOB"]
    result_path = job_path + ".result"
    out = {"ok": False, "stage": "start", "notes": []}

    def finish():
        with open(result_path, "w") as f:
            json.dump(out, f, indent=2)

    try:
        job = json.load(open(job_path))
        debugger.SetAsync(False)

        target = debugger.CreateTarget("")
        err = lldb.SBError()
        listener = debugger.GetListener()
        process = target.AttachToProcessWithID(listener, int(job["pid"]), err)
        out["stage"] = "attached"
        if not err.Success() or not process or not process.IsValid():
            out["notes"].append("attach failed: %s" % err.GetCString())
            return finish()

        base, mod = _load_base(target, job["exe"])
        slide = base - int(job["image_base_vmaddr"])
        out["load_base"] = hex(base)
        out["slide"] = hex(slide)

        addrs = {k: int(v) + slide for k, v in job["addrs"].items()}
        out["resolved"] = {k: hex(v) for k, v in addrs.items()}

        # verify prologues (guards against a patched/updated binary)
        verify = job.get("verify", {})
        bad = []
        for k, a in addrs.items():
            ok, why = _verify(process, a, verify.get(k))
            if not ok:
                bad.append("%s@%s: %s" % (k, hex(a), why))
        if bad:
            out["notes"].append("VERIFY FAILED (binary changed? re-derive offsets): " + "; ".join(bad))
            process.Detach()
            return finish()

        frame = process.GetSelectedThread().GetSelectedFrame()

        opts = lldb.SBExpressionOptions()
        opts.SetIgnoreBreakpoints(True)
        opts.SetFetchDynamicValue(lldb.eNoDynamicValues)
        opts.SetTryAllThreads(True)          # let other threads run so the GIL can be released
        opts.SetUnwindOnError(True)
        opts.SetTimeoutInMicroSeconds(10 * 1000 * 1000)

        def ev(expr):
            v = frame.EvaluateExpression(expr, opts)
            e = v.GetError()
            if e.Fail():
                raise RuntimeError("expr failed: %s :: %s" % (expr[:80], e.GetCString()))
            return v

        def evp(expr):   # evaluate, return as unsigned (pointer/handle)
            return ev(expr).GetValueAsUnsigned()

        boot = job.get("bootstrap", "")
        cstr = boot.replace("\\", "\\\\").replace('"', '\\"') if boot else ""
        primitive = job.get("primitive", "marshal_evalcode")
        out["primitive"] = primitive

        # gil ensure/release use different addr keys under marshal_evalcode
        # (offsets.json names them gil_ensure/gil_release) vs the legacy paths.
        ensure_key = "gil_ensure" if primitive == "marshal_evalcode" else "ensure"
        release_key = "gil_release" if primitive == "marshal_evalcode" else "release"

        # For marshal_evalcode, capture the live game frame's f_globals *before*
        # PyGILState_Ensure -- Ensure may swap _PyThreadState_Current to lldb's
        # calling thread (whose frame is NULL). At attach time the global still
        # points at the GIL-holding game thread with a valid frame; this is a
        # pure memory read (no GIL needed).
        gd_pre = None
        if primitive == "marshal_evalcode":
            gff = job.get("globals_from_frame", {})
            tstate_vmaddr = int(str(gff.get("current_tstate_ptr_vmaddr", "0")), 0)
            off_frame = int(gff.get("tstate_to_frame_offset", 24))
            off_globals = int(gff.get("frame_to_f_globals_offset", 48))
            if not tstate_vmaddr:
                raise RuntimeError("globals_from_frame.current_tstate_ptr_vmaddr missing")
            out["stage"] = "read f_globals off live frame (pre-GIL)"
            tstate = evp("*(void**)%d" % (tstate_vmaddr + slide))
            if not tstate:
                raise RuntimeError("current PyThreadState is NULL "
                                   "(no thread holds the GIL now; retry during active play)")
            frame_ptr = evp("*(void**)%d" % (tstate + off_frame))
            if not frame_ptr:
                raise RuntimeError("top PyThreadState has no frame "
                                   "(interpreter idle in C; retry during active play)")
            gd_pre = evp("*(void**)%d" % (frame_ptr + off_globals))
            if not gd_pre:
                raise RuntimeError("frame f_globals is NULL")
            out["frame_globals"] = hex(gd_pre)

        # 1) gil = PyGILState_Ensure()
        out["stage"] = "gil-ensure"
        gil = ev("(long)((long(*)())%d)()" % addrs[ensure_key]).GetValueAsSigned()
        out["gil"] = gil

        res = 1  # non-null == success sentinel
        try:
            if primitive == "marshal_evalcode":
                # 3.7-marshalled code object -> a scratch buffer in the target
                blob = bytes.fromhex(job["payload_marshal_hex"])
                out["stage"] = "alloc target buffer"
                perms = lldb.ePermissionsReadable | lldb.ePermissionsWritable
                aerr = lldb.SBError()
                buf = process.AllocateMemory(len(blob), perms, aerr)
                if not aerr.Success() or not buf:
                    raise RuntimeError("AllocateMemory failed: %s" % aerr.GetCString())
                out["buf"] = hex(buf)
                out["stage"] = "write marshal blob"
                werr = lldb.SBError()
                wrote = process.WriteMemory(buf, blob, werr)
                if not werr.Success() or wrote != len(blob):
                    raise RuntimeError("WriteMemory failed: %s (%s/%d)"
                                       % (werr.GetCString(), wrote, len(blob)))

                # ba = PyByteArray_FromStringAndSize(buf, len)  -- copies the data
                out["stage"] = "PyByteArray_FromStringAndSize"
                ba = evp('(void*)((void*(*)(char*,long))%d)(%d,%d)'
                         % (addrs["bytes_from_string_and_size"], buf, len(blob)))
                if not ba:
                    raise RuntimeError("PyByteArray_FromStringAndSize returned NULL")
                # bytearray owns a copy now; reclaim the scratch buffer
                process.DeallocateMemory(buf)

                # co = marshal.loads(0, ba)  -- METH_O; module arg is ignored
                out["stage"] = "marshal.loads"
                co = evp('(void*)((void*(*)(void*,void*))%d)(0,%d)'
                         % (addrs["marshal_loads"], ba))
                if not co:
                    out["notes"].append("marshal.loads returned NULL")
                    if "err_printex" in addrs:
                        ev("(void)((void(*)(int))%d)(1)" % addrs["err_printex"])
                    raise RuntimeError("marshal.loads failed (bad blob / version mismatch)")

                # res = PyEval_EvalCode(co, gd, gd) -- gd captured pre-GIL above
                out["stage"] = "PyEval_EvalCode"
                res = evp('(void*)((void*(*)(void*,void*,void*))%d)(%d,%d,%d)'
                          % (addrs["eval_code"], co, gd_pre, gd_pre))
            elif primitive == "exec_builtins":
                out["stage"] = "import builtins"
                bmod = evp('(void*)((void*(*)(char*))%d)("builtins")' % addrs["import_module"])
                out["stage"] = "add __main__"
                main = evp('(void*)((void*(*)(char*))%d)("__main__")' % addrs["add_module"])
                out["stage"] = "module getdict"
                gd = evp('(void*)((void*(*)(void*))%d)(%d)' % (addrs["module_getdict"], main))
                out["stage"] = "call exec"
                res = evp('(void*)((void*(*)(void*,char*,char*,char*,void*))%d)'
                          '(%d,"exec","sO","%s",%d)'
                          % (addrs["call_method"], bmod, cstr, gd))
            elif primitive == "compile_eval":
                out["stage"] = "add __main__"
                main = evp('(void*)((void*(*)(char*))%d)("__main__")' % addrs["add_module"])
                out["stage"] = "module getdict"
                gd = evp('(void*)((void*(*)(void*))%d)(%d)' % (addrs["module_getdict"], main))
                out["stage"] = "compile"
                code = evp('(void*)((void*(*)(char*,char*,int,void*,int))%d)'
                           '("%s","<ttrmod>",257,0,-1)' % (addrs["compile"], cstr))
                if not code:
                    raise RuntimeError("Py_CompileStringExFlags returned NULL")
                out["stage"] = "eval"
                res = evp('(void*)((void*(*)(void*,void*,void*))%d)(%d,%d,%d)'
                          % (addrs["eval"], code, gd, gd))
            else:
                raise RuntimeError("unknown primitive %r" % primitive)

            out["res_ptr"] = hex(res)
            if not res:
                out["notes"].append("in-process call returned NULL (a Python exception was raised)")
                if "err_printex" in addrs:
                    out["stage"] = "err_printex"
                    ev("(void)((void(*)(int))%d)(1)" % addrs["err_printex"])
                elif "err_print" in addrs:
                    out["stage"] = "err_print"
                    ev("(void)((void(*)())%d)()" % addrs["err_print"])
        finally:
            # 3) PyGILState_Release(gil) -- always, even on failure
            out["stage"] = "gil-release"
            ev("(void)((void(*)(long))%d)(%d)" % (addrs[release_key], gil))

        process.Detach()
        out["stage"] = "detached"
        out["ok"] = bool(res)
        return finish()
    except Exception as e:
        out["notes"].append("exception: %r" % e)
        try:
            finish()
        except Exception:
            pass


def __lldb_init_module(debugger, internal_dict):
    # invoked automatically on `command script import`; run immediately.
    run(debugger)
