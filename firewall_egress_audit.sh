#!/bin/bash -
#===============================================================================
# Enumerate every enabled EGRESS VPC firewall rule across every project in the
# org. firewall_public_audit.sh only covers INGRESS from the internet; this
# covers the outbound side:
#   - [ALLOW-ALL EGRESS]: an allow rule to 0.0.0.0/0 or ::/0 - outbound is
#     open to the whole internet.
#   - [DENY]: a custom egress deny rule (informational; shows a lockdown
#     exists).
#   - anything else is listed as-is (restricted destinations).
#
# GCP has an implied allow-all egress rule (priority 65535) that never shows
# up in rule listings. A project with a VPC network but no explicit egress
# rules is therefore open outbound; that is reported as
# [IMPLIED ALLOW-ALL EGRESS] per network, so it isn't mistaken for "locked
# down". Projects with the Compute API disabled have no networks and are
# skipped silently.
#
# Rules are listed unfiltered and matched in bash for the same reason as
# firewall_public_audit.sh ("/" in a CIDR breaks the Compute filter parser).
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  RULES=$(gcloud compute firewall-rules list --project="$project" \
    --format="value(name, network.basename(), direction, disabled, priority, destinationRanges.list(), allowed[].map().firewall_rule().list(), denied[].map().firewall_rule().list())" 2>"$ERR") \
    || { skip_check "$project" "firewall rules"; continue; }

  NETWORKS=$(gcloud compute networks list --project="$project" --format="value(name)" 2>"$ERR") \
    || { skip_check "$project" "networks"; NETWORKS=""; }

  # Networks with at least one enabled explicit egress rule that denies or
  # allows all (0.0.0.0/0 / ::/0) don't need the implied-rule warning below.
  EGRESS_NETWORKS=""

  if [ -n "$RULES" ]; then
    while IFS=$'\t' read -r name network direction disabled priority ranges allowed denied; do
      [ -z "$name" ] && continue
      [ "$direction" = "EGRESS" ] || continue
      [ "$disabled" = "False" ] || continue
      EGRESS_NETWORKS="$EGRESS_NETWORKS $network"

      if [ -n "$denied" ]; then
        echo "$project: $name  egress DENY -> ${ranges:-all} $denied (network $network, priority $priority)  [DENY]"
      elif is_open_cidr "$ranges"; then
        echo "$project: $name  egress $ranges -> $allowed (network $network, priority $priority)  [ALLOW-ALL EGRESS]"
      else
        echo "$project: $name  egress -> $ranges $allowed (network $network, priority $priority)"
      fi
      FOUND=true
    done <<< "$RULES"
  fi

  for network in $NETWORKS; do
    case " $EGRESS_NETWORKS " in
      *" $network "*) ;;
      *)
        echo "$project: network $network has no explicit egress rules - implied allow-all egress applies  [IMPLIED ALLOW-ALL EGRESS]"
        FOUND=true
        ;;
    esac
  done
done

if [ "$FOUND" = false ]; then
  echo "No VPC networks or egress firewall rules found"
fi
