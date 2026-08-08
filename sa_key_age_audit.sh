#!/bin/bash -
#===============================================================================
# Flag user-managed service account keys older than MAX_KEY_AGE_DAYS
# (default 90) across every project in the org. Long-lived SA keys are one of
# the most common ways stale credentials end up leaked or forgotten about.
#===============================================================================
set -uo pipefail

MAX_KEY_AGE_DAYS="${MAX_KEY_AGE_DAYS:-90}"
NOW_EPOCH=$(date -u +%s)
FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  SAS=$(gcloud iam service-accounts list --project="$project" \
    --format="value(email)" 2>/dev/null)

  for sa in $SAS; do
    KEYS=$(gcloud iam service-accounts keys list --iam-account="$sa" \
      --project="$project" --managed-by=user \
      --format="value(name.basename(), validAfterTime)" 2>/dev/null)

    [ -z "$KEYS" ] && continue

    while IFS=$'\t' read -r key_id created; do
      [ -z "$key_id" ] && continue
      CREATED_EPOCH=$(date -u -d "$created" +%s 2>/dev/null) || continue
      AGE_DAYS=$(( (NOW_EPOCH - CREATED_EPOCH) / 86400 ))

      if [ "$AGE_DAYS" -gt "$MAX_KEY_AGE_DAYS" ]; then
        echo "$project: $sa key=$key_id age=${AGE_DAYS}d (created $created)"
        FOUND=true
      fi
    done <<< "$KEYS"
  done
done

if [ "$FOUND" = false ]; then
  echo "No user-managed service account keys older than ${MAX_KEY_AGE_DAYS}d found"
fi
