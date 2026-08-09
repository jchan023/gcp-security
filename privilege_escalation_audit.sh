#!/bin/bash -
#===============================================================================
# Scan Cloud Audit Logs for IAM policy changes that GRANT a highly privileged
# role (owner/editor/*Admin) to a member - the core insider-threat and
# compromised-credential pattern of an account acquiring or retaining broad
# access. Complements privileged_roles_audit.sh (which shows current state)
# by showing who granted what to whom, and when.
#
# Lookback window defaults to 24h; override with LOOKBACK_HOURS.
#===============================================================================
set -uo pipefail

LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"

# GNU date (-d) vs BSD/macOS date (-v) - BSD date doesn't support -d at all
# and fails silently under 2>/dev/null, which would otherwise make this
# script find nothing regardless of what's in the logs.
if date --version >/dev/null 2>&1; then
  SINCE=$(date -u -d "-${LOOKBACK_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ)
else
  SINCE=$(date -u -v-"${LOOKBACK_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.org/download/)" >&2
  exit 1
fi

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  HITS=$(gcloud logging read \
    "logName=\"projects/$project/logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.methodName=\"SetIamPolicy\" AND timestamp>=\"$SINCE\"" \
    --project="$project" \
    --order=asc \
    --format=json 2>/dev/null \
    | jq -r '
        .[] |
        . as $entry |
        (($entry.protoPayload.serviceData.policyDelta.bindingDeltas
          // $entry.protoPayload.metadata.policyDelta.bindingDeltas)
          // []) as $deltas |
        $deltas[] |
        select(.action == "ADD") |
        select(.role == "roles/owner" or .role == "roles/editor" or (.role | test("Admin$"))) |
        ($entry.protoPayload.authenticationInfo.principalEmail // "") as $principal |
        (.member // "") as $member |
        [$entry.timestamp, $principal, .role, $member,
         (if ($member | endswith($principal)) and ($principal != "") then "SELF-GRANT" else "" end)] | @tsv
      ')

  if [ -n "$HITS" ]; then
    echo "$HITS" | awk -F'\t' -v p="$project" \
      '{tag = $5 != "" ? "  [" $5 "]" : ""; printf "%s: %s  %s granted %s to %s%s\n", p, $1, $2, $3, $4, tag}'
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No privileged-role grants in the last ${LOOKBACK_HOURS}h"
fi
