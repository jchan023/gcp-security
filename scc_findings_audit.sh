#!/bin/bash -
#===============================================================================
# Pull ACTIVE Security Command Center findings for every org the active
# identity can see. Surfaces SCC Standard tier's misconfiguration/
# vulnerability coverage (Security Health Analytics, Anomaly Detection,
# Artifact Registry scanning, etc.) alongside the rest of this repo's
# hand-rolled audits.
#
# Standard tier has no active-threat detection (that's Premium/Enterprise
# only) - this catches configuration/vulnerability findings, not the
# audit-log-based behavior audit_log_review.sh and
# privilege_escalation_audit.sh look for. The two are complementary, not
# overlapping.
#
# Defaults to CRITICAL/HIGH severity to keep signal-to-noise reasonable on
# orgs with a lot of open findings; override with MIN_SEVERITIES
# (comma-separated, e.g. "CRITICAL,HIGH,MEDIUM").
#
# --location=global is required: without it, `gcloud scc findings list` hits
# a deprecated v1 API path and errors outright ("This API is no longer
# available. Please use API V2 as an alternative.") even on an org where SCC
# is fully activated and the caller has correct permissions.
#
# Like the rest of this repo, errors (SCC not activated for an org, missing
# permissions) are swallowed via 2>/dev/null and treated the same as "no
# findings" rather than failing loudly - if this comes back clean, verify
# separately that SCC Standard is actually activated on the org.
#===============================================================================
set -uo pipefail

MIN_SEVERITIES="${MIN_SEVERITIES:-CRITICAL,HIGH}"

SEVERITY_FILTER=""
IFS=',' read -ra SEVS <<< "$MIN_SEVERITIES"
for s in "${SEVS[@]}"; do
  SEVERITY_FILTER="${SEVERITY_FILTER}severity=\"$s\" OR "
done
SEVERITY_FILTER="${SEVERITY_FILTER% OR }"

FOUND=false

ORGS=$(gcloud organizations list --format="value(ID)" 2>/dev/null)

if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't query Security Command Center" >&2
  exit 1
fi

for org in $ORGS; do
  HITS=$(gcloud scc findings list "$org" \
    --source=- \
    --location=global \
    --filter="state=\"ACTIVE\" AND ($SEVERITY_FILTER)" \
    --format="value(finding.category, finding.severity, finding.resourceName)" \
    2>/dev/null)

  if [ -n "$HITS" ]; then
    echo "$HITS" | sed "s/^/org $org: /"
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No ACTIVE ${MIN_SEVERITIES} Security Command Center findings found"
fi
