#!/bin/sh
set -eu

fail() {
  printf 'estus-dev-launch: %s\n' "$1" >&2
  exit 2
}

script_dir=${0%/*}
[ "$script_dir" != "$0" ] || script_dir=.
root=$(CDPATH='' cd -- "$script_dir/../.." && pwd -P) \
  || fail 'cannot resolve the checkout root'
record=$root/target/estus-dev/prepared
if ! { exec 3< "$record"; } 2>/dev/null; then
  fail 'missing preparation; run nix run .#dev-prepare from the checkout first'
fi
if ! {
  IFS='' read -r version <&3 && IFS='' read -r prepared_root <&3 \
    && IFS='' read -r artifact <&3 && IFS='' read -r config <&3
}; then
  fail 'invalid preparation; run nix run .#dev-prepare again'
fi
extra=''
if IFS= read -r extra <&3 || [ -n "$extra" ]; then
  fail 'invalid preparation; run nix run .#dev-prepare again'
fi
exec 3<&-
[ "$version" = estus-dev-v1 ] && [ "$prepared_root" = "$root" ] \
  || fail 'preparation belongs to another checkout; run nix run .#dev-prepare again'
case "$artifact" in
  /nix/store/*) ;;
  *) fail 'invalid prepared artifact; run nix run .#dev-prepare again' ;;
esac
store_name=${artifact#/nix/store/}
case "$store_name" in
  ''|*/*) fail 'invalid prepared artifact; run nix run .#dev-prepare again' ;;
esac
[ -x "$artifact/bin/estus" ] \
  || fail 'prepared artifact is unavailable; run nix run .#dev-prepare again'
case "$config" in
  /*) ;;
  *) fail 'invalid prepared configuration; run nix run .#dev-prepare again' ;;
esac
if [ "$#" -ne 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --config ] \
    || fail 'usage: estus-dev-launch.sh [--config PATH]'
  case "$2" in
    /*) config=$2 ;;
    *) config=$PWD/$2 ;;
  esac
fi
[ -f "$config" ] && [ -r "$config" ] \
  || fail 'configuration is missing or unreadable; prepare again or select --config PATH'

# The prepared or deliberately selected file is the only policy source. The
# native wrapper supplies its own matching installed catalog and OpenSSH paths.
unset ESTUS_CONFIG ESTUS_SSH_CONFIG ESTUS_SSH ESTUS_CATALOG_ROOT \
  ESTUS_ANSIBLE_RUNTIME ESTUS_PYTHON_RUNTIME
exec "$artifact/bin/estus" --config "$config"
