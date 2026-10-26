#!/bin/bash -
#===============================================================================
# Cover IAM exposure the per-project scripts cannot see, using Cloud Asset
# Inventory to search IAM policies across the whole org in one pass:
#
#   1. PUBLIC: allUsers / allAuthenticatedUsers on ANY resource - Cloud Run
#      services (public invoker), Cloud Functions, Pub/Sub, Secret Manager,
#      KMS, Artifact Registry, images, folders, the org itself, etc.
#      Projects and GCS buckets are skipped here: public_access_audit.sh
#      already reports those.
#   2. PRIVILEGED AT ORG/FOLDER LEVEL: roles/owner, roles/editor or any
#      roles/*Admin granted on the organization or a folder. Those inherit
#      into every project beneath, yet privileged_roles_audit.sh only reads
#      each project's own policy.
#
# Requires the Cloud Asset API enabled and cloudasset.assets.searchAllIamPolicies
# on the org; if the search fails the org is reported as SKIPPED rather than
# silently treated as clean.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.org/download/)" >&2
  exit 1
fi

FOUND=false

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't search org-wide IAM" >&2
  exit 1
fi

for org in $ORGS; do
  POLICIES=$(gcloud asset search-all-iam-policies --scope="organizations/$org" \
    --format=json 2>"$ERR") || { skip_check "org $org" "Cloud Asset IAM search"; continue; }
  [ -z "$POLICIES" ] && POLICIES="[]"
  # Org-wide search covers excluded projects too; drop their resources.
  if [ -s "$EXCLUDED_FILE" ]; then
    POLICIES=$(echo "$POLICIES" | jq -c --rawfile ex "$EXCLUDED_FILE" '($ex | split("\n") | map(select(. != ""))) as $x
      | [.[] | . as $p | select(([$x[] | . as $e | ($p.resource | contains($e)) or ($p.project // "" | contains($e))] | any) | not)]')
  fi

  PUBLIC=$(echo "$POLICIES" | jq -r '
    .[] | select(.assetType != "cloudresourcemanager.googleapis.com/Project"
                 and .assetType != "storage.googleapis.com/Bucket")
        | . as $p
        | $p.policy.bindings[]?
        | select(any(.members[]?; . == "allUsers" or . == "allAuthenticatedUsers"))
        | [$p.assetType, $p.resource, .role,
           ([.members[] | select(. == "allUsers" or . == "allAuthenticatedUsers")] | join(","))] | @tsv')
  if [ -n "$PUBLIC" ]; then
    echo "$PUBLIC" | awk -F'\t' -v o="$org" \
      '{printf "org %s [public %s]: %s  %s -> %s\n", o, $1, $2, $3, $4}'
    FOUND=true
  fi

  PRIV=$(echo "$POLICIES" | jq -r '
    .[] | select(.assetType == "cloudresourcemanager.googleapis.com/Organization"
                 or .assetType == "cloudresourcemanager.googleapis.com/Folder")
        | . as $p
        | $p.policy.bindings[]?
        | select(.role == "roles/owner" or .role == "roles/editor" or (.role | test("Admin$")))
        | . as $b | $b.members[]?
        | [$p.assetType, $p.resource, $b.role, .] | @tsv')
  if [ -n "$PRIV" ]; then
    echo "$PRIV" | awk -F'\t' -v o="$org" \
      '{sub(/.*\//, "", $1); printf "org %s [privileged role at %s level]: %s  %s %s\n", o, tolower($1), $2, $3, $4}'
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No public resource IAM or org/folder-level privileged grants found"
fi
