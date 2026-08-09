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
# Deliberately limited to boolean constraints (allow/deny list constraints
# like compute.vmExternalIpAccess need different parsing and aren't checked
# here).
#===============================================================================
set -uo pipefail

CONSTRAINTS=(
  "constraints/iam.disableServiceAccountKeyCreation"
  "constraints/iam.disableServiceAccountKeyUpload"
  "constraints/iam.automaticIamGrantsForDefaultServiceAccounts"
  "constraints/compute.requireOsLogin"
  "constraints/compute.requireShieldedVm"
  "constraints/compute.disableSerialPortAccess"
  "constraints/storage.uniformBucketLevelAccess"
)

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  for constraint in "${CONSTRAINTS[@]}"; do
    ENFORCED=$(gcloud resource-manager org-policies describe "$constraint" \
      --project="$project" --effective \
      --format="value(booleanPolicy.enforced)" 2>/dev/null)

    if [ "$ENFORCED" != "True" ]; then
      echo "$project: $constraint NOT enforced"
      FOUND=true
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No org policy drift found - all checked constraints enforced"
fi
