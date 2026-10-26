#!/bin/bash -
#===============================================================================
# Service account sprawl and lateral-movement paths (sa_key_age_audit.sh only
# covers key age):
#
#   1. Default compute/App Engine service accounts that still hold
#      roles/editor (or owner) - the legacy default grant that gives every VM
#      project-wide write access.
#   2. Cross-project / external impersonation: members granted
#      tokenCreator, serviceAccountUser, serviceAccountKeyAdmin or
#      workloadIdentityUser ON a service account, where the member is not in
#      the same project (a path to borrow that account's permissions).
#   3. Unused service accounts: enabled accounts with no authentication in
#      UNUSED_DAYS (default 90), from Recommender insights. If insights are
#      unavailable the project is reported SKIPPED, not clean.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

UNUSED_DAYS="${UNUSED_DAYS:-90}"
FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  POLICY=$(gcloud projects get-iam-policy "$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "project IAM policy"; POLICY='{}'; }
  echo "$POLICY" | jq -r '.bindings[]? | select(.role == "roles/editor" or .role == "roles/owner") | .role as $r | .members[]?
      | select(test("^serviceAccount:.*(-compute@developer\\.gserviceaccount\\.com|@appspot\\.gserviceaccount\\.com)$"))
      | [$r, .] | @tsv' | while IFS=$'\t' read -r role member; do
        echo "$project: default service account ${member#serviceAccount:} holds $role"
      done > "$ERR.d"
  if [ -s "$ERR.d" ]; then cat "$ERR.d"; FOUND=true; fi
  rm -f "$ERR.d"

  SAS=$(gcloud iam service-accounts list --project="$project" --format="value(email,disabled)" 2>"$ERR") \
    || { skip_check "$project" "list service accounts"; SAS=""; }
  while IFS=$'\t' read -r sa disabled; do
    [ -z "$sa" ] && continue
    SA_POLICY=$(gcloud iam service-accounts get-iam-policy "$sa" --project="$project" --format=json 2>"$ERR") \
      || { skip_check "$project" "IAM policy of $sa"; continue; }
    echo "$SA_POLICY" | jq -r '.bindings[]?
        | select(.role | test("serviceAccountTokenCreator|serviceAccountUser|serviceAccountKeyAdmin|workloadIdentityUser|iam.serviceAccountAdmin"))
        | .role as $r | .members[]? | [$r, .] | @tsv' | while IFS=$'\t' read -r role member; do
          case "$member" in
            *"@$project.iam.gserviceaccount.com"|"projectEditor:$project"|"projectOwner:$project") continue ;;
          esac
          echo "$project: $sa grants $role to $member"
        done > "$ERR.i"
    if [ -s "$ERR.i" ]; then cat "$ERR.i"; FOUND=true; fi
    rm -f "$ERR.i"
  done <<< "$SAS"

  INSIGHTS=$(gcloud recommender insights list --insight-type=google.iam.serviceAccount.Insight \
    --location=global --project="$project" --format=json 2>"$ERR") \
    || { skip_check "$project" "service account usage insights"; INSIGHTS="[]"; }
  echo "$INSIGHTS" | jq -r --argjson d "$UNUSED_DAYS" '.[]?
      | select(.content.lastAuthenticatedTime != null)
      | [(.content.lastAuthenticatedTime | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601),
         (.targetResources[0] | split("/") | last)] | @tsv' | while IFS=$'\t' read -r last sa; do
        age=$(( ($(date -u +%s) - last) / 86400 ))
        [ "$age" -gt "$UNUSED_DAYS" ] && echo "$project: service account $sa last authenticated ${age}d ago"
      done > "$ERR.u"
  if [ -s "$ERR.u" ]; then cat "$ERR.u"; FOUND=true; fi
  rm -f "$ERR.u"
done

if [ "$FOUND" = false ]; then
  echo "No default-SA editor grants, external impersonation paths, or unused service accounts found"
fi
