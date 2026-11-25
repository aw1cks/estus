#!/usr/bin/env bash
# Re-run a finished workflow run's failed jobs, but only when GitHub itself
# failed to run them: the job never got a runner, or its runner died. A job that
# ran and failed is a result, not noise, and is never retried here.
#
#   RUN_ID=<run id> GH_REPO=<owner/repo> scripts/ci-retry.sh
#
# DRY_RUN=1 prints the decision without re-running anything. ATTEMPT=<n>
# inspects an earlier attempt of the run instead of the latest (implies a dry
# run, since only the latest attempt can be re-run).
set -euo pipefail
: "${RUN_ID:?set RUN_ID to the workflow run to inspect}"
: "${GH_REPO:?set GH_REPO to owner/repo}"
case "$RUN_ID" in '' | *[!0-9]*) echo "RUN_ID must be a run number, got: $RUN_ID" >&2; exit 2 ;; esac

MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}
# Messages GitHub attaches to a job when the failure was its own.
INFRASTRUCTURE=(
  "was not acquired by Runner"
  "lost communication with the server"
  "runner has received a shutdown signal"
)

# A run cannot be re-run while any of it is still in progress.
status=
for _ in $(seq 1 60); do
  status=$(gh api "repos/$GH_REPO/actions/runs/$RUN_ID" --jq .status)
  [ "$status" = completed ] && break
  sleep 15
done
if [ "$status" != completed ]; then
  echo "run $RUN_ID is still $status after 15 minutes; not retrying" >&2
  exit 1
fi

latest=$(gh api "repos/$GH_REPO/actions/runs/$RUN_ID" --jq .run_attempt)
attempt=${ATTEMPT:-$latest}
if [ -n "${ATTEMPT:-}" ]; then DRY_RUN=1; fi
echo "run $RUN_ID, inspecting attempt $attempt of $latest (at most $MAX_ATTEMPTS)"
if [ -z "${DRY_RUN:-}" ] && [ "$latest" -ge "$MAX_ATTEMPTS" ]; then
  echo "already at attempt $latest; not retrying"
  exit 0
fi

failed=$(gh api --paginate "repos/$GH_REPO/actions/runs/$RUN_ID/attempts/$attempt/jobs" \
  --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled" or .conclusion == "timed_out") | "\(.id)\t\(.name)"')
if [ -z "$failed" ]; then
  echo "no failed jobs"
  exit 0
fi

infrastructure=()
genuine=()
while IFS=$'\t' read -r id name; do
  messages=$(gh api "repos/$GH_REPO/check-runs/$id/annotations" --jq '.[].message')
  cause=
  for pattern in "${INFRASTRUCTURE[@]}"; do
    if grep -qF -- "$pattern" <<<"$messages"; then cause=$pattern; break; fi
  done
  if [ -n "$cause" ]; then
    infrastructure+=("$name ($cause)")
  else
    genuine+=("$name")
  fi
done <<<"$failed"

for job in "${infrastructure[@]}"; do echo "infrastructure: $job"; done
if [ "${#genuine[@]}" -gt 0 ]; then
  for job in "${genuine[@]}"; do echo "not an infrastructure failure: $job"; done
  echo "not retrying: at least one job failed for its own reasons and needs a look"
  exit 0
fi
if [ -n "${DRY_RUN:-}" ]; then
  echo "would re-run the failed jobs as attempt $((latest + 1))"
  exit 0
fi
gh run rerun "$RUN_ID" --failed --repo "$GH_REPO"
echo "re-running the failed jobs as attempt $((latest + 1))"
