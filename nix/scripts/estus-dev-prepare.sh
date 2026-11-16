#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf 'estus-dev-prepare: %s\n' "$*" >&2
  exit 1
}

project_root=.
while (( $# )); do
  case "$1" in
    --project-root)
      (( $# >= 2 )) || fail '--project-root requires a path'
      project_root=$2
      shift 2
      ;;
    --help|-h)
      printf 'Usage: estus-dev-prepare [--project-root PATH]\n'
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ "$project_root" != *$'\n'* ]] || fail 'paths must not contain newlines'
# Retain command-output newlines until they can be checked, including a newline
# at the end of a checkout name. Never infer the checkout from this store script.
if ! root=$(git -C "$project_root" rev-parse --show-toplevel && printf '.'); then
  fail 'a Git checkout is required'
fi
root=${root%.}
root=${root%$'\n'}
[[ "$root" != *$'\n'* ]] || fail 'paths must not contain newlines'
if ! root=$(cd -- "$root" && pwd -P && printf '.'); then
  fail 'cannot resolve the checkout root'
fi
root=${root%.}
root=${root%$'\n'}
[[ "$root" = /* && "$root" != *$'\n'* ]] || fail 'invalid checkout path'
cd -- "$root"
[[ -f flake.nix ]] || fail 'the checkout root must contain flake.nix'

# Do not follow a redirected runtime directory or adopt non-private state.
[[ ! -L target ]] || fail 'target must not be a symlink'
mkdir -p -- target
state=$root/target/estus-dev
if ! mkdir -m 700 -- "$state" 2>/dev/null; then
  [[ -d "$state" && ! -L "$state" && -O "$state" ]] || fail 'runtime state must be an owned directory'
  [[ $(stat -c '%a' -- "$state") = 700 ]] || fail 'runtime state must have mode 0700'
fi
lock=$state/prepare.lock
mkdir -m 700 -- "$lock" 2>/dev/null || fail 'preparation is already locked; no state was changed'
run_dir=
published=false
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$run_dir" && "$published" = false ]]; then
    rm -f -- "$run_dir/config.toml" "$run_dir/prepared"
    rmdir -- "$run_dir"
  fi
  rmdir -- "$lock"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A failed build must not leave a previous artifact designated as prepared.
rm -f -- "$state/prepared"
mkdir -p -- "$root/nix/result/native"
# A raw local flake reference in a verified Git checkout uses only indexed
# sources, rather than copying ignored/private state as a path flake would.
nix build --no-write-lock-file --out-link "$root/nix/result/native/default" '.#default'
artifact=$(readlink -e -- "$root/nix/result/native/default")
case "$artifact" in
  /nix/store/*) ;;
  *) fail 'the native build did not resolve to a Nix store package' ;;
esac
store_name=${artifact#/nix/store/}
[[ "$store_name" != */* && "$store_name" != *$'\n'* && -x "$artifact/bin/estus" ]] \
  || fail 'the native build did not produce an estus executable'

# Each successful artifact gets a new immutable-by-convention config path.
# safe_config is pinned by the packaged entrypoint, never an ambient policy.
run_dir=$(mktemp -d "$state/preparation.XXXXXXXX")
config=$run_dir/config.toml
cat -- "$safe_config" > "$config"
printf '%s\n' 'estus-dev-v1' "$root" "$artifact" "$config" > "$run_dir/prepared"
mv -T -- "$run_dir/prepared" "$state/prepared"
published=true
printf 'Prepared: %s\nArtifact: %s\nConfig: %s\n' "$root" "$artifact" "$config"
