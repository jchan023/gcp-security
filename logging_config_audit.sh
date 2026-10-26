#!/bin/bash -
#===============================================================================
# Audit the audit trail itself. audit_log_review.sh and
# privilege_escalation_audit.sh only work if logs exist, are retained, and
# haven't been rerouted:
#
#   1. Log sinks: org-level sinks exist (export to a separate destination),
#      and every project/org sink is listed so additions/removals show up as
#      changes. Disabled sinks are flagged.
#   2. Retention: _Default/_Required log bucket retention shorter than
#      MIN_RETENTION_DAYS (default 90) for _Default.
#   3. Data Access logs: key services (IAM, Storage, KMS, Secret Manager,
#      BigQuery) without DATA_READ/DATA_WRITE audit config at the project or
#      org level. These logs are OFF by default, so an attacker reading data
#      leaves no trace.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

MIN_RETENTION_DAYS="${MIN_RETENTION_DAYS:-90}"
DATA_ACCESS_SERVICES=(iam.googleapis.com storage.googleapis.com cloudkms.googleapis.com secretmanager.googleapis.com bigquery.googleapis.com)
FOUND=false

# Echo the services in a policy JSON that have both DATA_READ and DATA_WRITE
# enabled, via a specific service entry or allServices.
covered_services() {
  echo "$1" | jq -r '
    [.auditConfigs[]? | . as $c
       | ([$c.auditLogConfigs[]? | select((.exemptedMembers // []) | length == 0) | .logType] ) as $types
       | select(($types | index("DATA_READ")) and ($types | index("DATA_WRITE")))
       | $c.service] | .[]'
}

check_data_access() { # scope policy_json
  local scope="$1" covered svc
  covered=$(covered_services "$2")
  if echo "$covered" | grep -qx "allServices"; then return; fi
  for svc in "${DATA_ACCESS_SERVICES[@]}"; do
    if ! echo "$covered" | grep -qx "$svc"; then
      echo "$scope: Data Access audit logs (DATA_READ+DATA_WRITE) not fully enabled for $svc"
      FOUND=true
    fi
  done
}

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
for org in $ORGS; do
  SINKS_OK=true
  SINKS=$(gcloud logging sinks list --organization="$org" --format="value(name,destination,disabled)" 2>"$ERR") \
    || { skip_check "org $org" "org log sinks"; SINKS=""; SINKS_OK=false; }
  if [ -z "$SINKS" ] && $SINKS_OK; then
    echo "org $org: no organization-level log sinks (audit logs stay only in each project)"
    FOUND=true
  elif [ -n "$SINKS" ]; then
    while IFS=$'\t' read -r name dest disabled; do
      [ -z "$name" ] && continue
      [ "$disabled" = "True" ] && echo "org $org: sink $name is DISABLED (dest $dest)" && FOUND=true
      echo "org $org: sink $name -> $dest"
      FOUND=true
    done <<< "$SINKS"
  fi
  POLICY=$(gcloud organizations get-iam-policy "$org" --format=json 2>"$ERR") \
    || { skip_check "org $org" "org IAM audit config"; POLICY='{}'; }
  ORG_POLICY_JSON="$POLICY"
  ORG_COVERED=$(covered_services "$POLICY")
done

for project in $AUDIT_PROJECTS; do
  SINKS=$(gcloud logging sinks list --project="$project" --format="value(name,destination,disabled)" 2>"$ERR") \
    || { skip_check "$project" "log sinks"; SINKS=""; }
  while IFS=$'\t' read -r name dest disabled; do
    [ -z "$name" ] && continue
    case "$name" in _Default|_Required) continue ;; esac
    [ "$disabled" = "True" ] && echo "$project: sink $name is DISABLED (dest $dest)"
    echo "$project: sink $name -> $dest"
    FOUND=true
  done <<< "$SINKS"

  RET=$(gcloud logging buckets describe _Default --location=global --project="$project" \
    --format="value(retentionDays)" 2>"$ERR") || { skip_check "$project" "_Default log bucket"; RET=""; }
  if [ -n "$RET" ] && [ "$RET" -lt "$MIN_RETENTION_DAYS" ]; then
    echo "$project: _Default log bucket retention is ${RET}d (< ${MIN_RETENTION_DAYS}d)"
    FOUND=true
  fi

  POLICY=$(gcloud projects get-iam-policy "$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "project IAM audit config"; continue; }
  # Org-level audit configs are inherited, so merge them in before judging.
  MERGED=$(jq -s '{auditConfigs: ((.[0].auditConfigs // []) + (.[1].auditConfigs // []))}' \
    <(echo "$POLICY") <(echo "${ORG_POLICY_JSON:-{\}}") 2>/dev/null)
  check_data_access "$project" "${MERGED:-$POLICY}"
done

if [ "$FOUND" = false ]; then
  echo "No logging gaps found (sinks, retention, Data Access logs)"
fi
