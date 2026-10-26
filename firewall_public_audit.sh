#!/bin/bash -
#===============================================================================
# Flag VPC firewall rules that allow ingress from the whole internet
# (0.0.0.0/0 or its IPv6 equivalent ::/0), across every project in the org.
# Rules that also expose management/database ports (SSH, RDP, SQL, Redis,
# Mongo, etc.) - by exact port, port range, or "all ports/all protocols" -
# are flagged as [SENSITIVE PORT], since those get hit by internet-wide
# scanners within minutes of exposure.
#
# Egress rules are covered by firewall_egress_audit.sh and network/
# hierarchical firewall policies by firewall_policies_audit.sh.
#
# Note: filtering server-side (--filter="sourceRanges:0.0.0.0/0") fails
# outright against the Compute API ("Invalid list filter expression") - the
# CIDR's "/" breaks its filter parser. Rules are listed unfiltered instead
# and matched in bash.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

FOUND=false

for project in $AUDIT_PROJECTS; do
  RULES=$(gcloud compute firewall-rules list --project="$project" \
    --format="value(name, direction, disabled, sourceRanges.list(), allowed[].map().firewall_rule().list())" 2>"$ERR") \
    || { skip_check "$project" "firewall rules"; RULES=""; }

  if [ -n "$RULES" ]; then
    while IFS=$'\t' read -r name direction disabled ranges allowed; do
      [ -z "$name" ] && continue
      [ "$direction" = "INGRESS" ] || continue
      [ "$disabled" = "False" ] || continue
      is_open_cidr "$ranges" || continue

      TAG=""
      if exposes_sensitive "$allowed"; then
        TAG="  [SENSITIVE PORT]"
      fi
      echo "$project: $name  $ranges -> $allowed$TAG"
      FOUND=true
    done <<< "$RULES"
  fi
done

if [ "$FOUND" = false ]; then
  echo "No firewall rules open to 0.0.0.0/0 or ::/0 found"
fi
