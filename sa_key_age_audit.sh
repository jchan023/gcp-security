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

# GNU date (-d) vs BSD/macOS date (-j -f) - BSD date doesn't support -d at
# all and fails silently under 2>/dev/null, which would otherwise make this
# script find nothing regardless of key age. validAfterTime is normally
# "2026-08-09T22:08:30Z" with no fractional seconds, but strip any just in
# case since BSD date's -f match is strict.
to_epoch() {
  local ts="${1%%.*}"
  ts="${ts%Z}Z"
  if date --version >/dev/null 2>&1; then
    date -u -d "$ts" +%s 2>/dev/null
  else
    date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s 2>/dev/null
  fi
}

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
      CREATED_EPOCH=$(to_epoch "$created") || continue
      [ -z "$CREATED_EPOCH" ] && continue
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
