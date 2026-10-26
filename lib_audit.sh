#!/bin/bash -
#===============================================================================
# Shared helpers, sourced by the audit scripts (not run on its own).
#
# The audit scripts used to send every gcloud error to /dev/null, which made a
# permission denial or API failure look identical to "no findings". Capture
# stderr into $ERR instead and call skip_check after a failed command:
#
#   OUT=$(gcloud ... 2>"$ERR") || { skip_check "$project" "label"; OUT=""; }
#
# skip_check stays quiet when a PROJECT-scoped failure just means the API is
# disabled there (nothing can exist in it to audit). Org-scoped checks
# (scope "org <id>" or "billing...") never get that pass: a disabled Cloud Asset/SCC API at
# org level means the check has no coverage at all. Any other failure prints a
# "<project>: SKIPPED (<label>): <reason>" line and sets FOUND=true, so the
# check shows up as a finding instead of a false all-clear.
#===============================================================================

ERR=$(mktemp)
EXCLUDED_FILE="$ERR.excluded"
trap 'rm -f "$ERR" "$EXCLUDED_FILE"' EXIT

skip_check() {
  local scope="$1" label="$2"
  case "$scope" in
    org\ *|billing*) ;;
    *)
      if grep -qiE 'SERVICE_DISABLED|has not been used in project|is not enabled|API \[.*\] not enabled' "$ERR"; then
        return 0
      fi
      ;;
  esac
  echo "$scope: SKIPPED ($label): $(tr '\n' ' ' < "$ERR" | tr -s ' ' | cut -c1-200)"
  FOUND=true
}

# True (exit 0) if a comma-separated allow list from firewall_rule() - e.g.
# "tcp:22,tcp:8000-9000,icmp" - exposes a sensitive management/database port.
# Matches exact ports, port ranges that span one, protocol-only entries
# (tcp/udp with no ports = every port) and "all".
SENSITIVE_PORTS="22 3389 3306 5432 1433 6379 27017 9200 9092 11211"
exposes_sensitive() {
  echo "$1" | tr ',' '\n' | awk -v ports="$SENSITIVE_PORTS" '
    BEGIN { n = split(ports, P, " ") }
    {
      t = $0
      if (t == "all" || t == "tcp" || t == "udp" || t == "sctp") { found = 1; next }
      if (match(t, /^(tcp|udp|sctp):/)) {
        r = substr(t, RLENGTH + 1)
        if (index(r, "-")) { split(r, a, "-"); lo = a[1]; hi = a[2] } else { lo = r; hi = r }
        for (i = 1; i <= n; i++) if (P[i] + 0 >= lo + 0 && P[i] + 0 <= hi + 0) found = 1
      }
    }
    END { exit found ? 0 : 1 }'
}

# Matches the IPv4 and IPv6 "whole internet" CIDRs.
# Ranges come from a comma-separated list() so match whole comma-delimited items.
OPEN_CIDR_REGEX='(^|[, ])(0\.0\.0\.0/0|::/0)([, ]|$)'
is_open_cidr() { echo "$1" | grep -qE "$OPEN_CIDR_REGEX"; }

# Print every folder ID (as "folders/<id>") under an org, recursively.
all_folders() {
  local org="$1" queue next f
  queue=$(gcloud resource-manager folders list --organization="$org" --format="value(name)" 2>"$ERR") \
    || { skip_check "org $org" "list folders"; return; }
  while [ -n "$queue" ]; do
    next=""
    for f in $queue; do
      echo "$f"
      next="$next $(gcloud resource-manager folders list --folder="${f#folders/}" --format="value(name)" 2>/dev/null)"
    done
    queue=$(echo "$next" | xargs)
  done
}

need_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required (https://jqlang.org/download/)" >&2
    exit 1
  fi
}

#===============================================================================
# Project scoping. Loaded ONCE when this file is sourced, so every script
# audits the same set of projects. Nothing here (or anywhere in the repo)
# names a project - scope comes from patterns and labels at run time:
#
#   EXCLUDE_NAME_REGEX  display-name regex to skip (default '^Untitled project$',
#                       the auto-created Apps Script/Workspace projects). "none"
#                       disables it.
#   EXCLUDE_ID_REGEX    project-ID regex to skip (default none), e.g. '^sys-[0-9]+$'
#   AUDIT_ONLY_SCOPED   "true" = audit only projects carrying a scope_* label
#                       (scope_pci=true, scope_iso27001=true, scope_soc2=true)
#
# Sets AUDIT_PROJECTS (what to iterate), ALL_PROJECT_IDS / ALL_PROJECT_NUMBERS
# (the whole org, for "is this principal inside the org" checks), and writes
# every skipped project's ID and number to $EXCLUDED_FILE so org-wide results
# can drop them with drop_excluded.
#===============================================================================
need_jq
EXCLUDE_NAME_REGEX="${EXCLUDE_NAME_REGEX:-^Untitled project\$}"
[ "$EXCLUDE_NAME_REGEX" = "none" ] && EXCLUDE_NAME_REGEX=""
EXCLUDE_ID_REGEX="${EXCLUDE_ID_REGEX:-}"
[ "$EXCLUDE_ID_REGEX" = "none" ] && EXCLUDE_ID_REGEX=""
AUDIT_ONLY_SCOPED="${AUDIT_ONLY_SCOPED:-false}"

if ! ALL_PROJECTS_JSON=$(gcloud projects list --format=json 2>"$ERR"); then
  echo "org: SKIPPED (list projects): $(tr '\n' ' ' < "$ERR" | cut -c1-200)"
  exit 0
fi
[ -z "$ALL_PROJECTS_JSON" ] && ALL_PROJECTS_JSON="[]"

_SELECT='((.name // "") | test($nre) | not) as $n_ok
  | (if $ire == "" then true else (.projectId | test($ire) | not) end) as $i_ok
  | (if $only == "true" then ((.labels // {}) | keys | any(startswith("scope_"))) else true end) as $s_ok'
[ -z "$EXCLUDE_NAME_REGEX" ] && EXCLUDE_NAME_REGEX='(?!)'   # a regex that matches nothing
_JQARGS=(--arg nre "$EXCLUDE_NAME_REGEX" --arg ire "$EXCLUDE_ID_REGEX" --arg only "$AUDIT_ONLY_SCOPED")

AUDIT_PROJECTS=$(echo "$ALL_PROJECTS_JSON" | jq -r "${_JQARGS[@]}" ".[] | $_SELECT | select(\$n_ok and \$i_ok and \$s_ok) | .projectId")
echo "$ALL_PROJECTS_JSON" | jq -r "${_JQARGS[@]}" ".[] | $_SELECT | select((\$n_ok and \$i_ok and \$s_ok) | not) | .projectId, .projectNumber" > "$EXCLUDED_FILE"
ALL_PROJECT_IDS=$(echo "$ALL_PROJECTS_JSON" | jq -r '.[].projectId')
ALL_PROJECT_NUMBERS=$(echo "$ALL_PROJECTS_JSON" | jq -r '.[].projectNumber')

# Remove lines that mention an excluded project (by ID or number) from stdin.
drop_excluded() {
  if [ -s "$EXCLUDED_FILE" ]; then grep -vFf "$EXCLUDED_FILE"; else cat; fi
}
