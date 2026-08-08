#!/bin/bash -
#===============================================================================
# Flag project-level and GCS bucket-level IAM bindings granted to allUsers or
# allAuthenticatedUsers ("public on the internet") across every project in
# the org.
#===============================================================================
set -uo pipefail

FOUND=false

for project in $(gcloud projects list --format="value(projectId)"); do
  # Project-level public bindings
  PROJECT_HITS=$(gcloud projects get-iam-policy "$project" \
    --flatten="bindings[].members" \
    --filter="bindings.members:allUsers OR bindings.members:allAuthenticatedUsers" \
    --format="value(bindings.role, bindings.members)" 2>/dev/null)

  if [ -n "$PROJECT_HITS" ]; then
    echo "$PROJECT_HITS" | sed "s/^/$project [project IAM]: /"
    FOUND=true
  fi

  # Bucket-level public bindings
  BUCKETS=$(gcloud storage buckets list --project="$project" \
    --format="value(name)" 2>/dev/null)

  for bucket in $BUCKETS; do
    BUCKET_HITS=$(gcloud storage buckets get-iam-policy "gs://$bucket" \
      --flatten="bindings[].members" \
      --filter="bindings.members:allUsers OR bindings.members:allAuthenticatedUsers" \
      --format="value(bindings.role, bindings.members)" 2>/dev/null)

    if [ -n "$BUCKET_HITS" ]; then
      echo "$BUCKET_HITS" | sed "s/^/$project [bucket gs:\/\/$bucket]: /"
      FOUND=true
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "No public (allUsers/allAuthenticatedUsers) bindings found"
fi
