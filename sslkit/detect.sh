#!/bin/sh
# POSIX wrapper around detect.py (source of truth). Unix LF.
cd "$(dirname "$0")" || exit 1
exec python3 detect.py "$@"
