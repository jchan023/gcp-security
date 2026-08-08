#!/bin/bash -
#===============================================================================
# Get the IAM policy (who has access to what) for every project in the
# current GCP org. Writes two outputs:
#   - output.txt          raw, human-readable policy dump (as before)
#   - access_summary.csv  one row per project/role/member, for spreadsheet
#                          review, diffing over time, or grepping for a
#                          specific principal/role across the whole org
#===============================================================================
set -uo pipefail

OUTFILE="output.txt"
SUMMARY_FILE="access_summary.csv"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for access_summary.csv (https://jqlang.org/download/)" >&2
  exit 1
fi

for f in "$OUTFILE" "$SUMMARY_FILE"; do
  if [ -e "$f" ]; then
    read -r -p "$f already exists. Overwrite? [y/N] " REPLY
    case "$REPLY" in
      [yY]|[yY][eE][sS]) ;;
      *) echo "Aborted."; exit 1 ;;
    esac
  fi
done

echo "IAM LIST" > "$OUTFILE"
echo "project,role,member" > "$SUMMARY_FILE"

while read -r project; do
  echo "================ $project ==============" >> "$OUTFILE"
  gcloud projects get-iam-policy "$project" >> "$OUTFILE"

  gcloud projects get-iam-policy "$project" --format=json 2>/dev/null \
    | jq -r --arg project "$project" \
      '.bindings[]? as $b | $b.members[] | [$project, $b.role, .] | @csv' \
    >> "$SUMMARY_FILE"
done < <(gcloud projects list --format="value(projectId)")

echo "Done. Raw policies in $OUTFILE, summary in $SUMMARY_FILE"

OWNER_EDITOR_COUNT=$(grep -c -E ',"roles/(owner|editor)",' "$SUMMARY_FILE" || true)
echo "Owner/editor bindings across org: $OWNER_EDITOR_COUNT"
