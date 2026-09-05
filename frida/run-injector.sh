#!/bin/sh
# Wrapper so a scoped sudoers NOPASSWD rule can run the frida injector as root
# (task_for_pid on the hardened engine needs root here). Args: --probe|--apply|--revert
cd /Users/tanner/Developer/ttr-mods || exit 1
export PYTHONPATH=/Users/tanner/Library/Python/3.13/lib/python/site-packages
export TTRMOD_PY37=/Library/Frameworks/Python.framework/Versions/3.7/bin/python3.7
SCRIPT="${TTRMOD_SCRIPT:-frida/inject.py}"   # override for diag.py etc.
exec frida/ttr-frida-runner "$SCRIPT" "$@"
