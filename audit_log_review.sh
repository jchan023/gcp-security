#!/bin/bash -
#===============================================================================
# Scan Cloud Audit Logs (Admin Activity) across every project for high-risk
# actions commonly associated with insider threats or compromised
# credentials: new/exfiltratable keys, token impersonation, SSH metadata
# backdoors, and tampering with the audit trail itself.
#
# Admin Activity logs are always-on and free in GCP, so this needs no extra
# logging configuration. Lookback window defaults to 24h; override with
# LOOKBACK_HOURS.
#===============================================================================
set -uo pipefail

LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"
SINCE=$(date -u -d "-${LOOKBACK_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ)

# High-risk admin actions to flag. Not exhaustive - tune to your org.
METHODS=(
  "SetIamPolicy"
  "google.iam.admin.v1.CreateServiceAccountKey"
  "google.iam.admin.v1.CreateServiceAccount"
  "google.iam.admin.v1.DeleteServiceAccount"
  "google.iam.credentials.v1.GenerateAccessToken"
  "google.iam.credentials.v1.GenerateIdToken"
  "google.iam.credentials.v1.SignJwt"
  "google.iam.credentials.v1.SignBlob"
  "google.logging.v2.ConfigServiceV2.DeleteSink"
  "google.logging.v2.ConfigServiceV2.UpdateSink"
  "v1.compute.instances.setMetadata"
  "v1.compute.projects.setCommonInstanceMetadata"
)

METHOD_FILTER=""
for m in "${METHODS[@]}"; do
  METHOD_FILTER="${METHOD_FILTER}protoPayload.methodName=\"$m\" OR "
done
METHOD_FILTER="${METHOD_FILTER% OR }"

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  ENTRIES=$(gcloud logging read \
    "logName=\"projects/$project/logs/cloudaudit.googleapis.com%2Factivity\" AND timestamp>=\"$SINCE\" AND ($METHOD_FILTER)" \
    --project="$project" \
    --order=asc \
    --format="value(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName, protoPayload.resourceName)" \
    2>/dev/null)

  if [ -n "$ENTRIES" ]; then
    echo "$ENTRIES" | sed "s/^/$project: /"
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No high-risk admin actions in the last ${LOOKBACK_HOURS}h"
fi
