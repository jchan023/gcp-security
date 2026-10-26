#!/bin/bash -
#===============================================================================
# Audit org policy at its SOURCE rather than per-project effective state
# (org_policy_audit.sh covers that):
#
#   1. org level: key constraints that are not set on the organization at all
#      (or set but not enforced / unrestricted). If the org never sets them,
#      every project is one missing override away from drift.
#   2. project overrides: policies set directly on a project that turn a key
#      constraint OFF (enforced: false, or allow-all list). Drift in
#      org_policy_audit.sh says a constraint is off; this says whether the
#      project actively overrode it.
#
# Key-constraint lists are a starting point - tune to your org.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

BOOL_KEYS=(
  constraints/iam.disableServiceAccountKeyCreation
  constraints/iam.disableServiceAccountKeyUpload
  constraints/iam.automaticIamGrantsForDefaultServiceAccounts
  constraints/compute.requireOsLogin
  constraints/compute.disableSerialPortAccess
  constraints/storage.uniformBucketLevelAccess
  constraints/storage.publicAccessPrevention
  constraints/sql.restrictPublicIp
  constraints/compute.skipDefaultNetworkCreation
)
LIST_KEYS=(
  constraints/compute.vmExternalIpAccess
  constraints/iam.allowedPolicyMemberDomains
)

FOUND=false

# Echo "restricted" if a policy JSON actually restricts, else "open".
policy_state() {
  echo "$1" | jq -r '
    if (.booleanPolicy.enforced == true) then "restricted"
    elif (.listPolicy.allValues == "DENY") or ((.listPolicy.allowedValues // []) | length > 0)
         or ((.listPolicy.deniedValues // []) | length > 0) then "restricted"
    else "open" end'
}

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't audit org policy source" >&2
  exit 1
fi

for org in $ORGS; do
  for c in "${BOOL_KEYS[@]}" "${LIST_KEYS[@]}"; do
    POLICY=$(gcloud resource-manager org-policies describe "$c" --organization="$org" --format=json 2>"$ERR") \
      || { skip_check "org $org" "org policy $c"; continue; }
    if [ "$(policy_state "$POLICY")" != "restricted" ]; then
      echo "org $org: $c NOT set/enforced at the organization level"
      FOUND=true
    fi
  done
done

KEYS_REGEX=$(printf '%s|' "${BOOL_KEYS[@]}" "${LIST_KEYS[@]}"); KEYS_REGEX="^(${KEYS_REGEX%|})\$"
for project in $(gcloud projects list --format="value(projectId)"); do
  POLICIES=$(gcloud resource-manager org-policies list --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "project org-policy overrides"; continue; }
  [ -z "$POLICIES" ] && continue
  echo "$POLICIES" | jq -c '.[]?' | while read -r p; do
    c=$(echo "$p" | jq -r '.constraint')
    echo "$c" | grep -qE "$KEYS_REGEX" || continue
    if [ "$(policy_state "$p")" != "restricted" ]; then
      echo "$project: project-level override disables $c"
    fi
  done
done > "$ERR.overrides"
if [ -s "$ERR.overrides" ]; then cat "$ERR.overrides"; FOUND=true; fi
rm -f "$ERR.overrides"

if [ "$FOUND" = false ]; then
  echo "No org-level policy gaps or project overrides found for key constraints"
fi
