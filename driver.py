#!/usr/bin/env python3
"""
ttr-mods driver -- host side.

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


def build_bootstrap(cfg_path, status_path):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--binary", default=DEFAULT_BIN)
    ap.add_argument("--revert", action="store_true")
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
              "  vmaddrs (PyGILState_Ensure/Release, PyRun_SimpleString) with the\n"
              "  `re` skill and add an entry under this UUID in offsets.json.\n"
              "  Known UUIDs: %s" % (uuid, ", ".join(offs_all.keys()) or "(none)"),
              file=sys.stderr)
        return 3

    primitive = off.get("primitive", "exec_builtins")
    required = {
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

    pid = args.pid or find_pid()
    if not pid:
        print("ERROR: TTREngine is not running. Launch the game first "
              "(reaching the login screen is enough).", file=sys.stderr)
        return 4

    # config: allow --revert to override the file's mode
    cfg = json.load(open(args.config))
    if args.revert:
        cfg = dict(cfg)
        cfg["revert"] = True
    # write the effective config to a temp file the payload will read
    cfg_fd, cfg_path = tempfile.mkstemp(prefix="ttrmod-cfg-", suffix=".json")
    with os.fdopen(cfg_fd, "w") as f:
        json.dump(cfg, f)

    bootstrap = build_bootstrap(cfg_path, STATUS_FILE)

    job = {
        "pid": pid,
        "exe": args.binary,
        "image_base_vmaddr": off.get("image_base_vmaddr", 0x100000000),
        "primitive": primitive,
        "addrs": {k: v for k, v in off["addrs"].items() if int(v)},
        "verify": off.get("verify", {}),
        "bootstrap": bootstrap,
    }
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
    print("[ttrmod] %s pid=%d uuid=%s" % (
        "REVERTING" if cfg.get("revert") else "applying", pid, uuid))
    proc = subprocess.run(
        ["lldb", "--batch", "-o", "command script import %s" % ATTACH, "-o", "quit"],
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
        mode = "revert" if st.get("revert") else "apply"
        print("[ttrmod] in-process (%s): applied=%d skipped=%d reverted=%d errors=%d" % (
            mode, len(st.get("applied", [])), len(st.get("skipped", [])),
            len(st.get("reverted", [])), len(st.get("errors", []))))
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
