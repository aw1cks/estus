#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Expected one observation label' >&2
    exit 64
fi
printf 'label=%s\n' "$1"
command uname -s
command id -u
