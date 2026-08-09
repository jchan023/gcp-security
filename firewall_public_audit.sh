#!/bin/bash -
#===============================================================================
# Flag VPC firewall rules that allow ingress from 0.0.0.0/0 (the whole
# internet), across every project in the org. Rules that also expose
# common management/database ports (SSH, RDP, SQL, Redis, Mongo, etc.) are
# flagged as [SENSITIVE PORT], since those get hit by internet-wide scanners
# within minutes of exposure.
#===============================================================================
set -uo pipefail

# Not exhaustive - tune to your org.
SENSITIVE_PORTS_REGEX="(^|[^0-9])(22|3389|3306|5432|1433|6379|27017|9200|9092|11211)($|[^0-9])"

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  RULES=$(gcloud compute firewall-rules list --project="$project" \
    --filter="direction=INGRESS AND disabled=false AND sourceRanges:0.0.0.0/0" \
    --format="value(name, allowed[].map().firewall_rule().list())" 2>/dev/null)

  if [ -n "$RULES" ]; then
    while IFS=$'\t' read -r name allowed; do
      [ -z "$name" ] && continue
      TAG=""
      if echo "$allowed" | grep -qE "$SENSITIVE_PORTS_REGEX"; then
        TAG="  [SENSITIVE PORT]"
      fi
      echo "$project: $name  0.0.0.0/0 -> $allowed$TAG"
      FOUND=true
    done <<< "$RULES"
  fi
done

if [ "$FOUND" = false ]; then
  echo "No firewall rules open to 0.0.0.0/0 found"
fi
