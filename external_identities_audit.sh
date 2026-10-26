#!/bin/bash -
#===============================================================================
# Flag IAM members from OUTSIDE the organization, at org, folder and project
# level - consumer Gmail accounts, other companies' domains, and service
# accounts that live in projects outside this org. Nothing enforces this when
# iam.allowedPolicyMemberDomains is unset, and an external member is the
# usual shape of an accidental share or a quiet backdoor.
#
# The org's domain is taken from the organization's display name; override
# with ALLOWED_DOMAINS (space-separated, e.g. "example.com"). Members that
# are Google-managed service agents (gcp-sa-*, *@developer.gserviceaccount.com
# etc. belonging to a project IN the org) are not flagged.
#
# Principals that are legitimately yours but on another domain (e.g. a
# personal Gmail that owns the org) will show up here - accept them in the
# risk register rather than weakening the check.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

FOUND=false
# Membership checks use the WHOLE org (excluded projects still count as inside).
PROJECT_IDS="$ALL_PROJECT_IDS"
PROJECT_NUMBERS="$ALL_PROJECT_NUMBERS"

is_internal_sa() { # service account email
  local email="$1" proj
  case "$email" in
    *@gcp-sa-*.iam.gserviceaccount.com|service-org-*@*.iam.gserviceaccount.com|*@cloudservices.gserviceaccount.com|*@cloudbuild.gserviceaccount.com|*@serverless-robot-prod.iam.gserviceaccount.com|*@container-engine-robot.iam.gserviceaccount.com|*@compute-system.iam.gserviceaccount.com) return 0 ;;
  esac
  proj="${email#*@}"; proj="${proj%%.*}"
  case "$email" in
    *@appspot.gserviceaccount.com) echo "$PROJECT_IDS" | grep -qx "$proj"; return ;;
    *-compute@developer.gserviceaccount.com|*@developer.gserviceaccount.com) echo "$PROJECT_NUMBERS" | grep -qx "${email%%-*}"; return ;;
    service-*@*.iam.gserviceaccount.com|service-*@*.gserviceaccount.com) echo "$PROJECT_NUMBERS" | grep -qx "$(echo "$email" | sed -E 's/^service-([0-9]+)@.*/\1/')"; return ;;
  esac
  echo "$PROJECT_IDS" | grep -qx "$proj"
}

check_policy() { # scope policy_json domains
  local scope="$1" json="$2" domains="$3" role member d ok
  echo "$json" | jq -r '.bindings[]? | .role as $r | .members[]? | [$r, .] | @tsv' | while IFS=$'\t' read -r role member; do
    case "$member" in
      user:*|group:*)
        d="${member#*@}"; ok=false
        for dom in $domains; do [ "$d" = "$dom" ] && ok=true; done
        $ok || echo "$scope: external $member has $role" ;;
      domain:*)
        d="${member#domain:}"; ok=false
        for dom in $domains; do [ "$d" = "$dom" ] && ok=true; done
        $ok || echo "$scope: external domain $d has $role" ;;
      serviceAccount:*)
        is_internal_sa "${member#serviceAccount:}" || echo "$scope: service account from outside the org $member has $role" ;;
    esac
  done
}

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't determine the org domain" >&2
  exit 1
fi

: > "$ERR.hits"
for org in $ORGS; do
  DOMAINS="${ALLOWED_DOMAINS:-$(gcloud organizations describe "$org" --format='value(displayName)' 2>/dev/null)}"
  POLICY=$(gcloud organizations get-iam-policy "$org" --format=json 2>"$ERR") \
    || { skip_check "org $org" "org IAM policy"; POLICY='{}'; }
  check_policy "org $org" "$POLICY" "$DOMAINS" >> "$ERR.hits"

  for folder in $(all_folders "$org"); do
    POLICY=$(gcloud resource-manager folders get-iam-policy "${folder#folders/}" --format=json 2>"$ERR") \
      || { skip_check "org $org" "folder $folder IAM policy"; continue; }
    check_policy "$folder" "$POLICY" "$DOMAINS" >> "$ERR.hits"
  done

  for project in $AUDIT_PROJECTS; do
    POLICY=$(gcloud projects get-iam-policy "$project" --format=json 2>"$ERR") \
      || { skip_check "$project" "project IAM policy"; continue; }
    check_policy "$project" "$POLICY" "$DOMAINS" >> "$ERR.hits"
  done
done
if [ -s "$ERR.hits" ]; then sort -u "$ERR.hits"; FOUND=true; fi
rm -f "$ERR.hits"

if [ "$FOUND" = false ]; then
  echo "No IAM members from outside the organization found"
fi
