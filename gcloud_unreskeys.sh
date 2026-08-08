#!/bin/bash -
#===============================================================================
# Scan every project in the current GCP org for API keys with no restrictions
# (no API restrictions, no application restrictions). Unrestricted keys are a
# common source of credential abuse if leaked.
#===============================================================================
set -uo pipefail

FOUND_KEYS=false

for project in $(gcloud projects list --format="value(projectId)"); do
  KEYS=$(gcloud services api-keys list --project="$project" \
    --filter="NOT restrictions:*" \
    --format="value(displayName, uid)" 2>/dev/null)

  if [ -n "$KEYS" ]; then
    echo "$KEYS" | sed "s/^/$project: /"
    FOUND_KEYS=true
  fi
done

if [ "$FOUND_KEYS" = false ]; then
  echo "No unrestricted keys found"
fi
