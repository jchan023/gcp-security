#!/bin/bash -
#===============================================================================
# Flag BigQuery datasets with allUsers/allAuthenticatedUsers access - a
# common way sensitive data gets silently exposed, since dataset-level
# sharing doesn't show up in project IAM policy checks.
#
# BigQuery's dataset ACL API represents these two differently: only
# allAuthenticatedUsers shows up under the legacy `specialGroup` field -
# allUsers only shows up under `iamMember`. Both are checked below.
#
# --headless is required on every bq call: on a fresh environment (e.g. a
# GitHub Actions runner, which starts clean every run) bq's first invocation
# prints an interactive setup/welcome prompt to stdout, which breaks the
# JSON parsing below.
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
  DATASETS=$(bq --headless ls --project_id="$project" --format=json 2>/dev/null | jq -r '.[].datasetReference.datasetId')

  for dataset in $DATASETS; do
    HITS=$(bq --headless show --format=prettyjson "${project}:${dataset}" 2>/dev/null | \
      jq -r '.access[]? |
        select(.specialGroup=="allAuthenticatedUsers" or .iamMember=="allUsers" or .iamMember=="allAuthenticatedUsers") |
        [.role, (.specialGroup // .iamMember)] | @tsv')

    if [ -n "$HITS" ]; then
      echo "$HITS" | sed "s/^/$project [dataset $dataset]: /"
      FOUND=true
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No public (allUsers/allAuthenticatedUsers) BigQuery dataset access found"
fi
