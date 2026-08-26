# attach.py -- runs inside lldb (`command script import`).
#
# Attaches to a running TTREngine, resolves the (stripped) CPython C-API
# functions from vmaddrs supplied by the driver, verifies the prologue bytes,
# then runs an injected Python bootstrap.
#
# TTR's frozen Panda3D "deploy-stub" build DEAD-STRIPS the whole PyRun_* family,
# so we cannot use PyRun_SimpleString. Two surviving primitives are supported,
# selected by job["primitive"]:
#
#   "exec_builtins" (preferred):
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

        boot = job["bootstrap"]
        cstr = boot.replace("\\", "\\\\").replace('"', '\\"')  # for a C string literal
        primitive = job.get("primitive", "exec_builtins")
        out["primitive"] = primitive

        # 1) gil = PyGILState_Ensure()
        out["stage"] = "gil-ensure"
        gil = ev("(long)((long(*)())%d)()" % addrs["ensure"]).GetValueAsSigned()
        out["gil"] = gil

        res = 1  # non-null == success sentinel
        try:
            if primitive == "exec_builtins":
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
                if "err_print" in addrs:
                    out["stage"] = "err_print"
                    ev("(void)((void(*)())%d)()" % addrs["err_print"])
        finally:
            # 3) PyGILState_Release(gil) -- always, even on failure
            out["stage"] = "gil-release"
            ev("(void)((void(*)(long))%d)(%d)" % (addrs["release"], gil))

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
