#!/bin/zsh --login
exec python3 $(dirname "$0")/tracee-capture.py "$@"