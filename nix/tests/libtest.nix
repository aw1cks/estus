{ pkgs }:
let
  mkTestScript =
    { name
    , harness
    , listArgs
    , runArgs
    , exactScenario ? null
    , extraSetup ? ""
    }:
    let
      listFlags = pkgs.lib.escapeShellArgs listArgs;
      runFlags = pkgs.lib.escapeShellArgs runArgs;
    in
    pkgs.writeShellScript "${name}-runner" ''
      set -euo pipefail
      ${extraSetup}
      list_output=$("${harness}" ${listFlags} --list --format terse)
      ${if exactScenario != null then ''
        matches=$(printf '%s\n' "$list_output" | ${pkgs.gnugrep}/bin/grep -cxF ${pkgs.lib.escapeShellArg "${exactScenario}: test"} || true)
        if [ "$matches" -ne 1 ]; then
          echo "expected 1 matching test, found $matches" >&2
          exit 1
        fi
      '' else ''
        matches=$(printf '%s\n' "$list_output" | ${pkgs.gnugrep}/bin/grep -cE ': test$' || true)
        if [ "$matches" -lt 1 ]; then
          echo "expected at least 1 matching test, found $matches" >&2
          exit 1
        fi
      ''}
      log=$(${pkgs.coreutils}/bin/mktemp)
      cleanup_files=("$log")
      if [ -n "''${ESTUS_CLEANUP_DIR:-}" ]; then
        cleanup_files+=("$ESTUS_CLEANUP_DIR")
      fi
      trap '${pkgs.coreutils}/bin/rm -rf -- "''${cleanup_files[@]}"' EXIT
      "${harness}" ${runFlags} "$@" | ${pkgs.coreutils}/bin/tee "$log"
      passed=0
      while IFS= read -r line; do
        if [[ "$line" =~ ^test\ result:\ ok\.\ ([0-9]+)\ passed\; ]]; then
          passed=''${BASH_REMATCH[1]}
        fi
      done < "$log"
      if [ "$passed" -lt 1 ]; then
        echo "expected at least 1 passing test, found $passed" >&2
        exit 1
      fi
    '';
in
{
  inherit mkTestScript;
}
