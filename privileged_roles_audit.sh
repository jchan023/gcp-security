#!/bin/bash -
#===============================================================================
# Flag members holding basic (primitive) owner/editor roles, plus any custom
# IAM roles in use, across every project in the org. Owner/editor are the
# broadest roles GCP offers and custom roles need manual review since their
# permission set can be arbitrarily broad.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  OWNER_EDITOR=$(gcloud projects get-iam-policy "$project" \
    --flatten="bindings[].members" \
    --filter="bindings.role:roles/owner OR bindings.role:roles/editor" \
    --format="value(bindings.role, bindings.members)" 2>"$ERR") \
      || { skip_check "$project" "primitive roles"; OWNER_EDITOR=""; }

  if [ -n "$OWNER_EDITOR" ]; then
    echo "$OWNER_EDITOR" | sed "s/^/$project [primitive role]: /"
    FOUND=true
  fi

  CUSTOM_ROLES=$(gcloud projects get-iam-policy "$project" \
    --flatten="bindings[].members" \
    --filter="bindings.role:projects/ OR bindings.role:organizations/" \
    --format="value(bindings.role, bindings.members)" 2>"$ERR") \
      || { skip_check "$project" "custom roles"; CUSTOM_ROLES=""; }

  if [ -n "$CUSTOM_ROLES" ]; then
    echo "$CUSTOM_ROLES" | sed "s/^/$project [custom role, review manually]: /"
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No primitive owner/editor bindings or custom roles found"
fi
