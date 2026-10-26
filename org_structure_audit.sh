#!/bin/bash -
#===============================================================================
# Organization structure and top-level admin:
#
#   1. Holders of org-admin-level roles on the organization (organizationAdmin,
#      securityAdmin, policyAdmin, folderAdmin, projectCreator,
#      billing.admin, owner, roleAdmin, orgpolicy admin) - the principals who
#      can change everything beneath. Listed every run so a new holder shows
#      up as a new finding.
#   2. Projects created in the last LOOKBACK_HOURS (default 168) - a new
#      project appearing unexpectedly is worth an alert on its own.
#   3. Projects parented directly on the organization instead of a folder
#      (only reported once folders exist in the org, since before that every
#      project is naturally unparented).
#   4. Projects not in ACTIVE lifecycle state (pending deletion) - verify that
#      deletion was intentional.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

LOOKBACK_HOURS="${LOOKBACK_HOURS:-168}"
FOUND=false

if date --version >/dev/null 2>&1; then
  SINCE=$(date -u -d "-${LOOKBACK_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ)
else
  SINCE=$(date -u -v-"${LOOKBACK_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)
fi

ADMIN_ROLES_REGEX='^roles/(resourcemanager\.(organizationAdmin|folderAdmin|projectCreator)|orgpolicy\.policyAdmin|iam\.(securityAdmin|organizationRoleAdmin)|billing\.(admin|creator)|owner)$'

ORGS=$(gcloud organizations list --format="value(ID)" 2>"$ERR")
if [ -z "$ORGS" ]; then
  echo "No organizations visible to the active identity - can't audit org structure" >&2
  exit 1
fi

for org in $ORGS; do
  POLICY=$(gcloud organizations get-iam-policy "$org" --format=json 2>"$ERR") \
    || { skip_check "org $org" "org IAM policy"; POLICY='{}'; }
  echo "$POLICY" | jq -r --arg re "$ADMIN_ROLES_REGEX" '.bindings[]? | select(.role | test($re)) | .role as $r | .members[]? | [$r, .] | @tsv' \
    | while IFS=$'\t' read -r role member; do echo "org $org: $role -> $member"; done > "$ERR.a"
  if [ -s "$ERR.a" ]; then cat "$ERR.a"; FOUND=true; fi
  rm -f "$ERR.a"

  HAS_FOLDERS=$(all_folders "$org" | head -1)

  PROJECTS=$(echo "$ALL_PROJECTS_JSON" | jq -r '.[] | [.projectId, .createTime, .lifecycleState, (.parent.type // "")] | @tsv' | drop_excluded)
  while IFS=$'\t' read -r pid created state ptype; do
    [ -z "$pid" ] && continue
    ts="${created%%.*}"; ts="${ts%Z}Z"
    # ISO-8601 UTC timestamps sort lexically, no date parsing needed.
    if [[ "$ts" > "$SINCE" ]]; then
      echo "$pid: project created $created (within the last ${LOOKBACK_HOURS}h)"
      FOUND=true
    fi
    if [ -n "$HAS_FOLDERS" ] && [ "$ptype" = "organization" ]; then
      echo "$pid: sits directly under the organization, not in a folder"
      FOUND=true
    fi
    if [ -n "$state" ] && [ "$state" != "ACTIVE" ]; then
      echo "$pid: lifecycle state $state"
      FOUND=true
    fi
  done <<< "$PROJECTS"
done

if [ "$FOUND" = false ]; then
  echo "No org-admin holders, new projects, or structure issues found"
fi
