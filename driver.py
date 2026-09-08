#!/usr/bin/env python3
"""
ttrff driver -- host side.

Finds the running TTREngine, looks up the CPython C-API function addresses for
this exact binary build (keyed by its arm64 Mach-O UUID in offsets.json), then
drives lldb to inject inproc/payload.py into the live interpreter.

Cosmetic-only battle-animation speedups on the owner's own client. ToS-gray,
at-own-risk. See README.md.

Usage:
    python3 driver.py            # apply patches from config.json
    python3 driver.py --revert   # restore all originals
    python3 driver.py --config other.json
    python3 driver.py --status   # just print last in-process status
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD = os.path.join(HERE, "inproc", "payload.py")
ATTACH = os.path.join(HERE, "lldb", "attach.py")
OFFSETS = os.path.join(HERE, "offsets.json")
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
DEFAULT_BIN = os.path.expanduser(
    "~/Library/Application Support/Toontown Rewritten/"
    "Toontown Rewritten.app/Contents/MacOS/TTREngine")
STATUS_FILE = "/tmp/ttrmod-status.json"

# The engine embeds a hardened, symbol-stripped CPython 3.7 whose bytecode
# compiler is dead-stripped, so source cannot be compiled in-process. The
# marshal_evalcode primitive instead compiles the payload to a code object on
# the HOST and marshals it -- but the marshal/code-object format is version-
# locked, so this MUST be done with a real CPython 3.7.x. Point TTRMOD_PY37 at
# one, or install python.org 3.7. Any 3.7.x works (x86_64 under Rosetta is fine;
# only compile()+marshal.dumps() are used -- no extension modules needed).
PY37_CANDIDATES = [
    os.environ.get("TTRMOD_PY37", ""),
    "/Library/Frameworks/Python.framework/Versions/3.7/bin/python3.7",
    "python3.7",
]


def find_lldb():
    """Return (lldb_path, developer_dir). A debugserver from a *beta* Xcode
    (e.g. Xcode 26.x on macOS 15) SEGFAULTs in __ptrace on attach ("lost
    connection"), so prefer an OS-matched toolchain: env override, then a stable
    Xcode 16.x, then the Command Line Tools, then whatever is on PATH."""
    import glob
    env_lldb = os.environ.get("TTRMOD_LLDB", "")
    if env_lldb and os.path.exists(env_lldb):
        return env_lldb, os.environ.get("TTRMOD_DEVELOPER_DIR") or None
    # stable Xcode 16.x (highest first), then CLT
    xcodes = sorted(glob.glob("/Applications/Xcode-16*.app"), reverse=True)
    for x in xcodes:
        p = os.path.join(x, "Contents/Developer/usr/bin/lldb")
        if os.path.exists(p):
            return p, os.path.join(x, "Contents/Developer")
    clt = "/Library/Developer/CommandLineTools/usr/bin/lldb"
    if os.path.exists(clt):
        return clt, "/Library/Developer/CommandLineTools"
    return shutil.which("lldb"), None

# stdin: payload source (utf-8); stdout: marshalled 3.7 code object (raw bytes).
_MARSHAL_HELPER = (
    "import sys, marshal\n"
    "src = sys.stdin.buffer.read().decode('utf-8')\n"
    "co = compile(src, %r, 'exec')\n"
    "sys.stdout.buffer.write(marshal.dumps(co))\n"
)


def find_py37():
    for cand in PY37_CANDIDATES:
        if not cand:
            continue
        path = cand if os.path.sep in cand else shutil.which(cand)
        if not path or not os.path.exists(path):
            continue
        try:
            ver = subprocess.check_output(
                [path, "-c", "import sys;print('%d.%d' % sys.version_info[:2])"],
                text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            continue
        if ver == "3.7":
            return path
    return None


def build_payload_marshal(py37, cfg_path, status_path):
    """Compile (header + hud.py + payload.py) to a single 3.7 code object on the
    host and return the marshalled bytes. The header bakes the config/status
    paths into the code object so no in-process env plumbing is needed once it
    runs. hud.py (if present) is concatenated ahead of payload.py so its
    setup_hud/teardown_hud functions live in the same module namespace that
    payload.py's main() calls into -- the target has no importable sibling files,
    so everything must be one code object."""
    header = (
        "import os\n"
        "os.environ['TTRMOD_CFG'] = %r\n"
        "os.environ['TTRMOD_STATUS'] = %r\n"
    ) % (cfg_path, status_path)
    parts = [header]
    hud_path = os.path.join(HERE, "inproc", "hud.py")
    if os.path.exists(hud_path):
        parts.append("# ==== inproc/hud.py ====\n" + open(hud_path, "r").read())
    parts.append("# ==== inproc/payload.py ====\n" + open(PAYLOAD, "r").read())
    src = "\n".join(parts)
    helper = _MARSHAL_HELPER % PAYLOAD
    proc = subprocess.run([py37, "-c", helper], input=src.encode("utf-8"),
                          capture_output=True)
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError("3.7 compile/marshal failed:\n%s"
                           % proc.stderr.decode("utf-8", "replace"))
    return proc.stdout


def _legacy_bootstrap(cfg_path, status_path):
    """String bootstrap for the legacy exec_builtins/compile_eval primitives
    (both dead-stripped in the shipping TTR build; kept for other builds)."""
    inner = (
        "import os\n"
        "os.environ['TTRMOD_CFG'] = %r\n"
        "os.environ['TTRMOD_STATUS'] = %r\n"
        "exec(compile(open(%r,'r').read(), %r, 'exec'))\n"
        % (cfg_path, status_path, PAYLOAD, PAYLOAD)
    )
    hexed = inner.encode("utf-8").hex()
    # only single quotes + hex chars -> trivially safe through lldb C-string literal
    return "exec(bytes.fromhex('%s').decode('utf-8'))" % hexed


def find_pid():
    # match the engine process; the on-disk name may be "TTREngine" or
    # "Toontown Rewritten".
    for pat in ("TTREngine", "Toontown Rewritten"):
        try:
            out = subprocess.check_output(["pgrep", "-f", pat], text=True).split()
        except subprocess.CalledProcessError:
            out = []
        # filter out ourselves / the launcher patcher if any
        pids = [int(p) for p in out]
        if pids:
            return pids[0]
    return None


def binary_uuid(binpath, arch="arm64"):
    out = subprocess.check_output(["otool", "-arch", arch, "-l", binpath], text=True)
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        if "LC_UUID" in ln:
            for j in range(i, min(i + 3, len(lines))):
                if "uuid" in lines[j]:
                    return lines[j].split()[-1].strip()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--binary", default=DEFAULT_BIN)
    ap.add_argument("--revert", action="store_true")
    ap.add_argument("--probe", action="store_true",
                    help="read-only smoke test: attach, report current target "
                         "values, change nothing")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--pid", type=int, default=None)
    args = ap.parse_args()

    if args.status:
        if os.path.exists(STATUS_FILE):
            print(open(STATUS_FILE).read())
        else:
            print("no status file yet at %s" % STATUS_FILE)
        return 0

    if not os.path.exists(args.binary):
        print("ERROR: engine binary not found at %s" % args.binary, file=sys.stderr)
        return 2

    uuid = binary_uuid(args.binary)
    if not uuid:
        print("ERROR: could not read arm64 UUID from binary", file=sys.stderr)
        return 2

    if not os.path.exists(OFFSETS):
        print("ERROR: offsets.json missing. Derive C-API addrs with the `re` skill.",
              file=sys.stderr)
        return 3
    offs_all = json.load(open(OFFSETS))
    off = offs_all.get(uuid)
    if not off:
        print("ERROR: no offsets recorded for this build.\n"
              "  binary UUID: %s\n"
              "  The engine was likely auto-patched. Re-derive the CPython C-API\n"
              "  vmaddrs (PyGILState_Ensure/Release, PyEval_EvalCode, marshal.loads,\n"
              "  PyByteArray_FromStringAndSize + the current-tstate global) with the\n"
              "  `re` skill and add an entry under this UUID in offsets.json.\n"
              "  Known UUIDs: %s" % (uuid, ", ".join(offs_all.keys()) or "(none)"),
              file=sys.stderr)
        return 3

    primitive = off.get("primitive", "marshal_evalcode")
    required = {
        # The real primitive for TTR's hardened, compiler-stripped 3.7 build:
        # host-marshalled code object -> marshal.loads -> PyEval_EvalCode, with
        # f_globals read off the live frame (no module-dict call to pin).
        "marshal_evalcode": ["gil_ensure", "gil_release", "eval_code",
                             "marshal_loads", "bytes_from_string_and_size"],
        # Legacy string-based primitives -- both dead-stripped in this build,
        # kept only for other/hypothetical builds that still link them.
        "exec_builtins": ["ensure", "release", "import_module", "add_module",
                          "module_getdict", "call_method"],
        "compile_eval": ["ensure", "release", "add_module", "module_getdict",
                         "compile", "eval"],
    }.get(primitive)
    if required is None:
        print("ERROR: offsets.json specifies unknown primitive %r" % primitive, file=sys.stderr)
        return 3
    missing = [k for k in required if not int(off["addrs"].get(k, 0))]
    if missing:
        print("ERROR: offsets.json is missing/placeholder addresses %s for primitive %r\n"
              "  (build UUID %s). Derive the CPython C-API vmaddrs with the `re` skill\n"
              "  and fill them in (see README 'Re-deriving offsets')."
              % (missing, primitive, uuid), file=sys.stderr)
        return 3

    # marshal_evalcode needs the current-PyThreadState global (+ struct offsets)
    # to read f_globals off the live frame -- PyModule_GetDict/AddModule are
    # inlined in this build, so there's no dict-returning call to pin.
    gff = off.get("globals_from_frame", {})
    if primitive == "marshal_evalcode" and not gff.get("current_tstate_ptr_vmaddr"):
        print("ERROR: offsets.json[%s] is missing globals_from_frame."
              "current_tstate_ptr_vmaddr (needed to read f_globals off the live "
              "frame). Re-derive with the `re` skill." % uuid, file=sys.stderr)
        return 3

    # we need a real CPython 3.7 to produce a code object the engine can unmarshal
    py37 = None
    if primitive == "marshal_evalcode":
        py37 = find_py37()
        if not py37:
            print("ERROR: no CPython 3.7 found to marshal the payload for the "
                  "engine's 3.7 interpreter.\n"
                  "  A 3.8+ marshal blob will NOT load in 3.7. Install python.org "
                  "3.7 (any 3.7.x)\n"
                  "  or set TTRMOD_PY37=/path/to/python3.7. Only compile()+"
                  "marshal.dumps() are used.", file=sys.stderr)
            return 7

    pid = args.pid or find_pid()
    if not pid:
        print("ERROR: TTREngine is not running. Launch the game first "
              "(reaching the login screen is enough).", file=sys.stderr)
        return 4

    # config: allow --revert / --probe to override the file's mode
    cfg = json.load(open(args.config))
    if args.revert:
        cfg = dict(cfg)
        cfg["revert"] = True
    if args.probe:
        cfg = dict(cfg)
        cfg["probe"] = True
    # write the effective config to a temp file the payload will read
    cfg_fd, cfg_path = tempfile.mkstemp(prefix="ttrmod-cfg-", suffix=".json")
    with os.fdopen(cfg_fd, "w") as f:
        json.dump(cfg, f)

    job = {
        "pid": pid,
        "exe": args.binary,
        "image_base_vmaddr": off.get("image_base_vmaddr", 0x100000000),
        "primitive": primitive,
        "addrs": {k: v for k, v in off["addrs"].items() if int(v)},
        "verify": off.get("verify", {}),
        "globals_from_frame": gff,
    }
    if primitive == "marshal_evalcode":
        try:
            blob = build_payload_marshal(py37, cfg_path, STATUS_FILE)
        except RuntimeError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 7
        job["payload_marshal_hex"] = blob.hex()
        job["py37"] = py37
    else:
        job["bootstrap"] = _legacy_bootstrap(cfg_path, STATUS_FILE)
    job_fd, job_path = tempfile.mkstemp(prefix="ttrmod-job-", suffix=".json")
    with os.fdopen(job_fd, "w") as f:
        json.dump(job, f)
    result_path = job_path + ".result"

    if os.path.exists(STATUS_FILE):
        try:
            os.remove(STATUS_FILE)
        except OSError:
            pass

    env = dict(os.environ)
    env["TTRMOD_JOB"] = job_path
    lldb_path, dev_dir = find_lldb()
    if not lldb_path:
        print("ERROR: no lldb found. Install Xcode or the Command Line Tools.",
              file=sys.stderr)
        return 8
    if dev_dir:
        env["DEVELOPER_DIR"] = dev_dir   # make lldb launch the matching debugserver
    print("[ttrmod] %s pid=%d uuid=%s" % (
        "PROBING (read-only)" if cfg.get("probe")
        else "REVERTING" if cfg.get("revert") else "applying", pid, uuid))
    print("[ttrmod] lldb=%s%s" % (lldb_path, " (DEVELOPER_DIR=%s)" % dev_dir if dev_dir else ""))
    proc = subprocess.run(
        [lldb_path, "--batch", "-o", "command script import %s" % ATTACH, "-o", "quit"],
        env=env, capture_output=True, text=True, timeout=120)

    lldb_res = {}
    if os.path.exists(result_path):
        lldb_res = json.load(open(result_path))
    else:
        print("ERROR: lldb produced no result. stderr:\n%s\nstdout:\n%s" % (
            proc.stderr[-2000:], proc.stdout[-2000:]), file=sys.stderr)
        return 5

    if not lldb_res.get("ok"):
        print("ERROR: injection did not complete cleanly:")
        print(json.dumps(lldb_res, indent=2))
        return 6

    print("[ttrmod] injection OK (primitive=%s load_base=%s slide=%s res=%s)" % (
        lldb_res.get("primitive"), lldb_res.get("load_base"),
        lldb_res.get("slide"), lldb_res.get("res_ptr")))

    # read the in-process status the payload wrote
    for _ in range(20):
        if os.path.exists(STATUS_FILE):
            break
        time.sleep(0.1)
    if os.path.exists(STATUS_FILE):
        st = json.load(open(STATUS_FILE))
        mode = "probe" if st.get("probe") else "revert" if st.get("revert") else "apply"
        print("[ttrmod] in-process (%s): probe=%d applied=%d skipped=%d reverted=%d errors=%d" % (
            mode, len(st.get("probe", [])), len(st.get("applied", [])),
            len(st.get("skipped", [])), len(st.get("reverted", [])), len(st.get("errors", []))))
        for p in st.get("probe", []):
            print("   ? %-18s %s = %s" % (p["id"], p.get("target"), p.get("value")))
        for a in st.get("applied", []):
            print("   + %-18s %s  %s" % (a["id"], a["target"], a.get("detail", "")))
        for s in st.get("skipped", []):
            print("   - skip %-15s %s" % (s["id"], s["reason"]))
        for e in st.get("errors", []):
            print("   ! %s" % e)
        if st.get("modules_seen"):
            print("   (diagnostics: modules_seen recorded in %s)" % STATUS_FILE)
    else:
        print("[ttrmod] WARNING: no in-process status file; payload may not have "
              "reached the game modules yet (import hook will apply them on load).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
