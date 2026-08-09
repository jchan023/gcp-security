#!/bin/bash -
#===============================================================================
# Removes everything setup_fixtures.sh planted. Matches only "fixture-"
# prefixed resources (and the two fixture buckets/dataset), so it's safe to
# run without disturbing anything else in the project.
#
# Usage:
#   PROJECT_ID=my-test-project ./testing/teardown_fixtures.sh
#===============================================================================
set -uo pipefail

PROJECT_ID="${PROJECT_ID:?Set PROJECT_ID to your test project}"

echo "Removing fixtures from $PROJECT_ID ..."

# API keys
for uid in $(gcloud services api-keys list --project="$PROJECT_ID" \
  --filter="displayName:fixture-" --format="value(uid)" 2>/dev/null); do
  gcloud services api-keys delete "$uid" --project="$PROJECT_ID" --quiet
done

# Firewall rule
gcloud compute firewall-rules delete fixture-open-mgmt-ports \
  --project="$PROJECT_ID" --quiet 2>/dev/null || true

# IAM bindings
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:fixture-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role=roles/owner --condition=None --quiet 2>/dev/null || true

# Buckets (force-delete, they only hold fixture data)
gcloud storage rm --recursive "gs://fixture-uniform-public-${PROJECT_ID}" --quiet 2>/dev/null || true
gcloud storage rm --recursive "gs://fixture-finegrained-${PROJECT_ID}" --quiet 2>/dev/null || true

# BigQuery dataset
bq --headless rm -r -f --project_id="$PROJECT_ID" "${PROJECT_ID}:fixture_public_dataset" 2>/dev/null || true

# Service account (also invalidates its key)
gcloud iam service-accounts delete "fixture-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project="$PROJECT_ID" --quiet 2>/dev/null || true

rm -f /tmp/fixture-sa-key.json /tmp/fixture-object.txt

echo "Done."
