#!/usr/bin/env bash
#
# Watch the live worker count against the baseline taken while the cluster was
# healthy and, the first time it drops, collect the cluster forensics right then.
# Waiting for the end of the job is too late: eksctl's CloudFormation stacks and
# the AWS-side state of a torn down nodegroup are most informative while the
# teardown is still in progress. Runs detached in the background and exits after
# one collection; the failure path of post-logic collects again at the end.

set -u

ARTIFACTS_SUFFIX="${1:?artifacts_suffix argument is required}"
NODE_BASELINE="${2:?node baseline path is required}"
INTERVAL="${3:-30}"

BASELINE="$(jq '[.items[]] | length' "${NODE_BASELINE}")"
if ! [ "${BASELINE}" -gt 0 ] 2>/dev/null; then
  echo "Baseline node count is not usable ('${BASELINE}'), not watching."
  exit 0
fi

echo "Watching for a drop below ${BASELINE} nodes every ${INTERVAL}s"

# Require two consecutive observations so that a transient API-server blip does
# not spend the single collection this watchdog is allowed.
drops=0
while true; do
  live="$(kubectl get nodes --no-headers 2>/dev/null | wc -l)"
  if [ "${live}" -lt "${BASELINE}" ]; then
    drops=$((drops + 1))
    echo "$(date -u +%H:%M:%S) live=${live} baseline=${BASELINE} consecutive=${drops}"
  else
    drops=0
  fi

  if [ "${drops}" -ge 2 ]; then
    echo "Worker count dropped from ${BASELINE} to ${live}, collecting forensics"
    NODE_BASELINE="${NODE_BASELINE}" \
      bash "$(dirname "$0")/action.sh" "${ARTIFACTS_SUFFIX}" node-loss
    exit 0
  fi

  sleep "${INTERVAL}"
done
