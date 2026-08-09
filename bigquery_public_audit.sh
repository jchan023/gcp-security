#!/bin/bash -
#===============================================================================
# Flag BigQuery datasets with allUsers/allAuthenticatedUsers access - a
# common way sensitive data gets silently exposed, since dataset-level
# sharing doesn't show up in project IAM policy checks.
#===============================================================================
set -uo pipefail

if ! command -v bq >/dev/null 2>&1; then
  echo "bq CLI is required (part of the Cloud SDK - run 'gcloud components install bq')" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.org/download/)" >&2
  exit 1
fi

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  DATASETS=$(bq ls --project_id="$project" --format=json 2>/dev/null | jq -r '.[].datasetReference.datasetId')

  for dataset in $DATASETS; do
    HITS=$(bq show --format=prettyjson "${project}:${dataset}" 2>/dev/null | \
      jq -r '.access[]? | select(.specialGroup=="allUsers" or .specialGroup=="allAuthenticatedUsers") | [.role, .specialGroup] | @tsv')

    if [ -n "$HITS" ]; then
      echo "$HITS" | sed "s/^/$project [dataset $dataset]: /"
      FOUND=true
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No public (allUsers/allAuthenticatedUsers) BigQuery dataset access found"
fi
