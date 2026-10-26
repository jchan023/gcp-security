#!/bin/bash -
#===============================================================================
# Intrusion detection / prevention coverage (a common compliance requirement:
# PCI DSS 11.x, NIST SI-4, SOC 2 CC6/CC7). For every VPC network in every
# project, report networks with NO IDS/IPS coverage. A network counts as
# covered if ANY of these exist for it:
#
#   - a Cloud IDS endpoint (gcloud ids endpoints) on the network
#   - a packet mirroring policy on the network (feeds a third-party IDS)
#   - an enabled Cloud NGFW rule with action apply_security_profile_group
#     (threat prevention) in a network firewall policy associated with the
#     network
#
# Also reports IDS endpoints that are not in READY state. Organization-level
# (hierarchical) threat-prevention policies are not credited as coverage;
# a network covered only that way will be reported, so verify manually.
# Projects with the Compute API disabled have no networks and are skipped.
# Cloud IDS is billed per endpoint-hour, so "no coverage" is a cost/compliance
# trade-off to accept or remediate, not necessarily an error.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  NETWORKS=$(gcloud compute networks list --project="$project" --format="value(name)" 2>"$ERR") \
    || { skip_check "$project" "networks"; continue; }
  [ -z "$NETWORKS" ] && continue

  COVERED=""

  IDS=$(gcloud ids endpoints list --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "Cloud IDS endpoints"; IDS="[]"; }
  [ -z "$IDS" ] && IDS="[]"
  COVERED="$COVERED $(echo "$IDS" | jq -r '.[]? | .network | split("/") | last')"
  echo "$IDS" | jq -r '.[]? | select(.state != "READY") | [.name, .state] | @tsv' | while IFS=$'\t' read -r n s; do
    echo "$project: Cloud IDS endpoint ${n##*/} is $s (not READY)"
  done > "$ERR.s"
  if [ -s "$ERR.s" ]; then cat "$ERR.s"; FOUND=true; fi
  rm -f "$ERR.s"

  MIRRORS=$(gcloud compute packet-mirrorings list --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "packet mirroring"; MIRRORS="[]"; }
  [ -z "$MIRRORS" ] && MIRRORS="[]"
  COVERED="$COVERED $(echo "$MIRRORS" | jq -r '.[]? | select(.enable != "FALSE") | .network.url | split("/") | last')"

  POLICIES=$(gcloud compute network-firewall-policies list --global --project="$project" --format="value(name)" 2>"$ERR") \
    || { skip_check "$project" "network firewall policies"; POLICIES=""; }
  for policy in $POLICIES; do
    RULES=$(gcloud compute network-firewall-policies rules list --firewall-policy="$policy" \
      --global-firewall-policy --project="$project" --format=json 2>"$ERR") \
      || { skip_check "$project" "rules of policy $policy"; continue; }
    if echo "$RULES" | jq -e '[.[]? | select((.disabled // false | not) and .action == "apply_security_profile_group")] | length > 0' >/dev/null 2>&1; then
      DESC=$(gcloud compute network-firewall-policies describe "$policy" --global --project="$project" --format=json 2>"$ERR") \
        || { skip_check "$project" "policy $policy"; continue; }
      COVERED="$COVERED $(echo "$DESC" | jq -r '.associations[]? | .attachmentTarget | split("/") | last')"
    fi
  done

  for network in $NETWORKS; do
    case " $COVERED " in
      *" $network "*) ;;
      *)
        echo "$project: network $network has no IDS/IPS coverage (no Cloud IDS endpoint, packet mirroring, or NGFW threat-prevention rule)"
        FOUND=true
        ;;
    esac
  done
done

if [ "$FOUND" = false ]; then
  echo "All VPC networks have IDS/IPS coverage"
fi
