#!/bin/bash -
#===============================================================================
# Network exposure beyond firewall rules (those are firewall_*_audit.sh):
#
#   - VM instances with an external (NAT) IP
#   - Cloud SQL instances with a public IPv4 address, and any authorized
#     network of 0.0.0.0/0
#   - GKE clusters with a public control-plane endpoint, or no master
#     authorized networks
#   - External load balancer backend services with no Cloud Armor policy
#   - VPC peering to a network in a project outside this org
#
# Every sub-check is skipped silently for a project whose API is disabled
# (nothing can exist there); other failures are reported as SKIPPED.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

FOUND=false
PROJECT_IDS=$(gcloud projects list --format="value(projectId)" 2>"$ERR") || { skip_check "org" "list projects"; PROJECT_IDS=""; }

for project in $PROJECT_IDS; do
  VMS=$(gcloud compute instances list --project="$project" \
    --format="value(name,zone.basename(),networkInterfaces[].accessConfigs[].natIP.list())" 2>"$ERR") \
    || { skip_check "$project" "VM instances"; VMS=""; }
  while IFS=$'\t' read -r name zone ips; do
    [ -z "$name" ] || [ -z "$ips" ] && continue
    echo "$project: VM $name ($zone) has external IP $ips"
    FOUND=true
  done <<< "$VMS"

  SQL=$(gcloud sql instances list --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "Cloud SQL"; SQL="[]"; }
  [ -z "$SQL" ] && SQL="[]"
  echo "$SQL" | jq -r '.[]? | .name as $n
      | (if any(.ipAddresses[]?; .type == "PRIMARY") then "\($n)\thas a public IPv4 address" else empty end),
        (.settings.ipConfiguration.authorizedNetworks[]? | select(.value == "0.0.0.0/0") | "\($n)\tauthorizes 0.0.0.0/0")' \
    | while IFS=$'\t' read -r n msg; do echo "$project: Cloud SQL $n $msg"; done > "$ERR.s"
  if [ -s "$ERR.s" ]; then cat "$ERR.s"; FOUND=true; fi
  rm -f "$ERR.s"

  GKE=$(gcloud container clusters list --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "GKE clusters"; GKE="[]"; }
  [ -z "$GKE" ] && GKE="[]"
  echo "$GKE" | jq -r '.[]? | .name as $n
      | (if (.privateClusterConfig.enablePrivateEndpoint // false) | not then "\($n)\thas a public control-plane endpoint" else empty end),
        (if (.masterAuthorizedNetworksConfig.enabled // false) | not then "\($n)\thas no master authorized networks" else empty end)' \
    | while IFS=$'\t' read -r n msg; do echo "$project: GKE cluster $n $msg"; done > "$ERR.g"
  if [ -s "$ERR.g" ]; then cat "$ERR.g"; FOUND=true; fi
  rm -f "$ERR.g"

  BES=$(gcloud compute backend-services list --global --project="$project" \
    --format="value(name,loadBalancingScheme,securityPolicy)" 2>"$ERR") \
    || { skip_check "$project" "backend services"; BES=""; }
  while IFS=$'\t' read -r name scheme policy; do
    [ -z "$name" ] && continue
    case "$scheme" in EXTERNAL*) [ -z "$policy" ] && { echo "$project: external backend service $name has no Cloud Armor policy"; FOUND=true; } ;; esac
  done <<< "$BES"

  PEERS=$(gcloud compute networks peerings list --project="$project" \
    --format="value(name,network.basename(),peerings[].network.list())" 2>"$ERR") \
    || { skip_check "$project" "VPC peerings"; PEERS=""; }
  while IFS=$'\t' read -r name net peer; do
    [ -z "$peer" ] && continue
    peer_proj=$(echo "$peer" | sed -E 's#.*/projects/([^/]+)/.*#\1#')
    echo "$PROJECT_IDS" | grep -qx "$peer_proj" || { echo "$project: network $net peers with $peer_proj (outside this org)"; FOUND=true; }
  done <<< "$PEERS"
done

if [ "$FOUND" = false ]; then
  echo "No external VM IPs, public Cloud SQL/GKE endpoints, unprotected external LBs, or foreign peering found"
fi
