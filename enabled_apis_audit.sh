#!/bin/bash -
#===============================================================================
# Report high-risk APIs that are enabled per project - compute, containers,
# serverless, databases, ML and build services are the usual footholds for
# cryptomining and data exfiltration, and a project that shouldn't use them
# is easiest to spot by what is switched on.
#
# Everything on HIGH_RISK_APIS is listed as a finding unless approved for
# that project via APPROVED_APIS (space-separated "project=api" pairs, e.g.
# "my-proj=compute.googleapis.com"). Accepted pairs belong in the risk
# register; this keeps the weekly list a diff of what changed.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

APPROVED_APIS="${APPROVED_APIS:-}"
HIGH_RISK_APIS=(
  compute.googleapis.com container.googleapis.com run.googleapis.com
  cloudfunctions.googleapis.com appengine.googleapis.com sqladmin.googleapis.com
  dataproc.googleapis.com dataflow.googleapis.com notebooks.googleapis.com
  aiplatform.googleapis.com cloudbuild.googleapis.com batch.googleapis.com
  composer.googleapis.com spanner.googleapis.com bigtableadmin.googleapis.com
  file.googleapis.com redis.googleapis.com
)
FOUND=false

for project in $AUDIT_PROJECTS; do
  ENABLED=$(gcloud services list --enabled --project="$project" --format="value(config.name)" 2>"$ERR") \
    || { skip_check "$project" "enabled APIs"; continue; }
  for api in "${HIGH_RISK_APIS[@]}"; do
    echo "$ENABLED" | grep -qx "$api" || continue
    echo " $APPROVED_APIS " | grep -q " $project=$api " && continue
    echo "$project: high-risk API enabled: $api"
    FOUND=true
  done
done

if [ "$FOUND" = false ]; then
  echo "No unapproved high-risk APIs enabled"
fi
