#!/bin/bash -
#===============================================================================
# Flag projects where key security-relevant (boolean) org policy constraints
# are not enforced - including not set at all, which defaults to "not
# enforced" for these constraints. Org policies are usually set once at the
# org/folder level and then silently drift via project-level exceptions;
# this catches that drift instead of assuming the org-level setting still
# applies everywhere.
#
# Constraint list is a starting point, not exhaustive - tune to your org.
# Boolean constraints are checked for "enforced"; list constraints (e.g.
# compute.vmExternalIpAccess, iam.allowedPolicyMemberDomains) are checked
# separately below for being left unrestricted (allValues: ALLOW, or no list
# policy set at all).
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

CONSTRAINTS=(
  "constraints/iam.disableServiceAccountKeyCreation"
  "constraints/iam.disableServiceAccountKeyUpload"
  "constraints/iam.automaticIamGrantsForDefaultServiceAccounts"
  "constraints/compute.requireOsLogin"
  "constraints/compute.requireShieldedVm"
  "constraints/compute.disableSerialPortAccess"
  "constraints/storage.uniformBucketLevelAccess"
  "constraints/storage.publicAccessPrevention"
  "constraints/sql.restrictPublicIp"
  "constraints/sql.restrictAuthorizedNetworks"
  "constraints/compute.skipDefaultNetworkCreation"
)

# List constraints that should have an explicit allow/deny list. A finding
# means the constraint is unset or set to allow-all.
LIST_CONSTRAINTS=(
  "constraints/compute.vmExternalIpAccess"
  "constraints/iam.allowedPolicyMemberDomains"
)

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.org/download/)" >&2
  exit 1
fi

FOUND=false

for project in $AUDIT_PROJECTS; do
  for constraint in "${CONSTRAINTS[@]}"; do
    ENFORCED=$(gcloud resource-manager org-policies describe "$constraint" \
      --project="$project" --effective \
      --format="value(booleanPolicy.enforced)" 2>/dev/null)

    if [ "$ENFORCED" != "True" ]; then
      echo "$project: $constraint NOT enforced"
      FOUND=true
    fi
  done

  for constraint in "${LIST_CONSTRAINTS[@]}"; do
    POLICY=$(gcloud resource-manager org-policies describe "$constraint" \
      --project="$project" --effective --format=json 2>"$ERR") \
      || { skip_check "$project" "$constraint"; continue; }
    STATE=$(echo "$POLICY" | jq -r '
      if (.listPolicy.allValues == "DENY")
         or ((.listPolicy.allowedValues // []) | length > 0)
         or ((.listPolicy.deniedValues // []) | length > 0)
      then "restricted" else "open" end' 2>/dev/null)
    if [ "$STATE" != "restricted" ]; then
      echo "$project: $constraint NOT enforced (no allow/deny list set - unrestricted)"
      FOUND=true
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No org policy drift found - all checked constraints enforced"
fi
