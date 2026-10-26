#!/bin/bash -
#===============================================================================
# Flag enabled ALLOW rules open to the whole internet (0.0.0.0/0 or ::/0) in
# firewall POLICIES - network firewall policies per project and hierarchical
# firewall policies per org. The classic `gcloud compute firewall-rules` list
# used by firewall_public_audit.sh / firewall_egress_audit.sh does not show
# these, and they are evaluated before VPC rules, so an allow here bypasses
# the VPC-rule audits entirely.
#
# Ingress rules are matched on srcIpRanges, egress rules on destIpRanges.
# Folder-level hierarchical policies are not enumerated (only org-attached
# ones); policies not associated with anything are still listed.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.org/download/)" >&2
  exit 1
fi

FOUND=false

# jq filter: enabled allow rules with an open CIDR on the relevant side.
OPEN_ALLOW_JQ='
  .[]? | select((.disabled // false) | not)
       | select(.action == "allow")
       | . as $r
       | (if $r.direction == "EGRESS" then ($r.match.destIpRanges // []) else ($r.match.srcIpRanges // []) end) as $ranges
       | select(any($ranges[]; . == "0.0.0.0/0" or . == "::/0"))
       | [ $r.direction, ($r.priority|tostring), ($ranges|join(",")),
           (($r.match.layer4Configs // []) | map(.ipProtocol + (if (.ports // []) | length > 0 then ":" + (.ports|join("/")) else "" end)) | join(",")) ] | @tsv'

report_rules() { # scope label policy json
  local scope="$1" label="$2" policy="$3" json="$4" hits
  hits=$(echo "$json" | jq -r "$OPEN_ALLOW_JQ" 2>/dev/null)
  [ -z "$hits" ] && return
  while IFS=$'\t' read -r direction priority ranges protos; do
    echo "$scope [$label $policy]: $direction allow $ranges -> ${protos:-all} (priority $priority)"
    FOUND=true
  done <<< "$hits"
}

for project in $(gcloud projects list --format="value(projectId)"); do
  POLICIES=$(gcloud compute network-firewall-policies list --global --project="$project" \
    --format="value(name)" 2>"$ERR") || { skip_check "$project" "network firewall policies"; continue; }
  for policy in $POLICIES; do
    RULES=$(gcloud compute network-firewall-policies rules list --firewall-policy="$policy" \
      --global-firewall-policy --project="$project" --format=json 2>"$ERR") \
      || { skip_check "$project" "network firewall policy $policy rules"; continue; }
    report_rules "$project" "network policy" "$policy" "$RULES"
  done
done

for org in $(gcloud organizations list --format="value(ID)" 2>/dev/null); do
  POLICIES=$(gcloud compute firewall-policies list --organization="$org" \
    --format="value(name)" 2>"$ERR") || { skip_check "org $org" "hierarchical firewall policies"; continue; }
  for policy in $POLICIES; do
    RULES=$(gcloud compute firewall-policies list-rules "$policy" --organization="$org" \
      --format=json 2>"$ERR") \
      || { skip_check "org $org" "hierarchical policy $policy rules"; continue; }
    report_rules "org $org" "hierarchical policy" "$policy" "$RULES"
  done
done

if [ "$FOUND" = false ]; then
  echo "No firewall policy allow rules open to 0.0.0.0/0 or ::/0 found"
fi
