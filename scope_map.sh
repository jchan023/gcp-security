#!/bin/bash -
#===============================================================================
# Build the compliance-scope map used to tag findings in the email:
# { "<project-id>": ["pci", "iso27001", ...], ... }
#
# Membership comes from two places, merged:
#   1. Project labels  scope_<framework>=true  (e.g. scope_pci=true,
#      scope_iso27001=true, scope_soc2=true). Preferred - the scope lives on
#      the project itself, so nothing about it is stored in this repo.
#   2. AUDIT_SCOPE_MAP (an Actions secret), one framework per line:
#        pci=project-a project-b
#        iso27001=project-c project-d
#      Use this where you can't or don't want to label the projects.
#
# Writes JSON to the path in $1 (default .scope/scope.json). This file holds
# real project IDs: it is never committed, never uploaded as an artifact, and
# never printed.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"

OUT="${1:-.scope/scope.json}"
mkdir -p "$(dirname "$OUT")"

LABELS=$(echo "$ALL_PROJECTS_JSON" | jq '
  [.[] | select(.labels != null)
       | {id: .projectId,
          fw: [.labels | to_entries[] | select(.key | startswith("scope_")) | select(.value == "true") | .key | sub("^scope_"; "")]}
       | select(.fw | length > 0)]')

MAP=$(echo "${AUDIT_SCOPE_MAP:-}" | jq -R -s '
  [split("\n")[] | select(test("^\\s*[A-Za-z0-9_-]+\\s*=")) | capture("^\\s*(?<fw>[A-Za-z0-9_-]+)\\s*=(?<ids>.*)$")
    | .fw as $fw | .ids | split(" ") | map(select(. != "")) | map({id: ., fw: [$fw]})] | add // []')

jq -n --argjson a "$LABELS" --argjson b "$MAP" '
  ($a + $b) | group_by(.id) | map({key: .[0].id, value: ([.[].fw[]] | map(ascii_downcase) | unique)}) | from_entries' > "$OUT"

echo "scope map written: $(jq 'length' "$OUT") project(s) in scope" >&2
