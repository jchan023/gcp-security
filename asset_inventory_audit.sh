#!/bin/bash -
#===============================================================================
# Org-wide asset inventory for change detection. Lists one line per
# security-relevant asset across the whole org via Cloud Asset Inventory.
# The email builder already tracks each line's first-seen date, so a NEW
# line is a newly created asset (bucket, VM, key, service account, cluster,
# database, secret, ...) and a line that disappears is dropped - no separate
# snapshot file is needed. First run lists everything as new.
#
# Requires the Cloud Asset API enabled and cloudasset.assets.searchAllResources
# on the org; if the search fails the org is reported SKIPPED.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

ASSET_TYPES="${ASSET_TYPES:-storage.googleapis.com/Bucket,compute.googleapis.com/Instance,compute.googleapis.com/Firewall,compute.googleapis.com/Network,compute.googleapis.com/ForwardingRule,container.googleapis.com/Cluster,sqladmin.googleapis.com/Instance,iam.googleapis.com/ServiceAccount,iam.googleapis.com/ServiceAccountKey,run.googleapis.com/Service,cloudfunctions.googleapis.com/CloudFunction,secretmanager.googleapis.com/Secret,cloudkms.googleapis.com/CryptoKey,bigquery.googleapis.com/Dataset,pubsub.googleapis.com/Topic,cloudresourcemanager.googleapis.com/Project,cloudresourcemanager.googleapis.com/Folder}"
FOUND=false

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't search the asset inventory" >&2
  exit 1
fi

for org in $ORGS; do
  ASSETS=$(gcloud asset search-all-resources --scope="organizations/$org" --asset-types="$ASSET_TYPES" \
    --format="value(assetType,name)" 2>"$ERR") \
    || { skip_check "org $org" "Cloud Asset resource search"; continue; }
  if [ -n "$ASSETS" ]; then
    echo "$ASSETS" | sort | awk -F'\t' -v o="$org" '{n=$2; sub(/^\/\//,"",n); printf "org %s: %s  %s\n", o, $1, n}'
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No tracked assets found in the asset inventory"
fi
