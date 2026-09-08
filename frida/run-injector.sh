#!/bin/sh
# Wrapper so a scoped sudoers NOPASSWD rule can run the frida injector as root
# (task_for_pid on the hardened engine needs root here). Args: --probe|--apply|--revert
cd /Users/tanner/Developer/ttrff || exit 1
export PYTHONPATH=/Users/tanner/Library/Python/3.13/lib/python/site-packages
export TTRMOD_PY37=/Library/Frameworks/Python.framework/Versions/3.7/bin/python3.7
export PYTHONUNBUFFERED=1   # logs are immediate: Python block-buffers stdout when it isn't a TTY (piped/wrapped), so without this the [SCALED]/[IVALNAME] output piles up and is lost on Ctrl+C
SCRIPT="${TTRMOD_SCRIPT:-frida/inject.py}"   # override for diag.py etc.
exec frida/ttr-frida-runner "$SCRIPT" "$@"
