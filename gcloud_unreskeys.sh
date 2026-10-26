#!/bin/bash -
#===============================================================================
# Scan every project in the current GCP org for API keys with no restrictions
# (no API restrictions, no application restrictions). Unrestricted keys are a
# common source of credential abuse if leaked.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  KEYS=$(gcloud services api-keys list --project="$project" \
    --filter="NOT restrictions:*" \
    --format="value(displayName, uid)" 2>"$ERR") \
      || { skip_check "$project" "API keys"; KEYS=""; }

  if [ -n "$KEYS" ]; then
    echo "$KEYS" | sed "s/^/$project: /"
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No unrestricted keys found"
fi
