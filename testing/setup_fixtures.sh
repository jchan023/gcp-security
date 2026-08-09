#!/bin/bash -
#===============================================================================
# Plants deliberately-misconfigured resources in a TEST project so every
# audit script in this repo has something to find. Everything it creates is
# prefixed "fixture-" so teardown_fixtures.sh can find and remove it again
# without touching anything else in the project.
#
# DO NOT run this against a real/production project - it intentionally
# creates public buckets, an open-to-the-internet firewall rule, an
# unrestricted API key, and an owner grant. Use a disposable test project.
#
# Usage:
#   PROJECT_ID=my-test-project I_UNDERSTAND=yes ./testing/setup_fixtures.sh
#===============================================================================
set -uo pipefail

PROJECT_ID="${PROJECT_ID:?Set PROJECT_ID to your disposable test project}"

if [ "${I_UNDERSTAND:-}" != "yes" ]; then
  echo "This creates intentionally-public/insecure resources (open firewall rule," >&2
  echo "public bucket, unrestricted API key, owner grant) in project '$PROJECT_ID'." >&2
  echo "Only run this against a throwaway test project." >&2
  echo "Re-run with I_UNDERSTAND=yes to proceed." >&2
  exit 1
fi

echo "Planting fixtures in $PROJECT_ID ..."

# --- gcloud_unreskeys.sh: API key with no restrictions ----------------------
gcloud services api-keys create \
  --display-name="fixture-unrestricted-key" \
  --project="$PROJECT_ID"

# --- sa_key_age_audit.sh: a user-managed SA key -----------------------------
# Can't backdate creation time, so this won't look "stale" by default - test
# it with MAX_KEY_AGE_DAYS=0 to flag any key regardless of age.
gcloud iam service-accounts create fixture-sa \
  --display-name="fixture-sa (audit test fixture)" \
  --project="$PROJECT_ID" 2>/dev/null || true

gcloud iam service-accounts keys create /tmp/fixture-sa-key.json \
  --iam-account="fixture-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project="$PROJECT_ID"

# --- firewall_public_audit.sh: SSH/RDP open to the world --------------------
gcloud compute firewall-rules create fixture-open-mgmt-ports \
  --project="$PROJECT_ID" \
  --network=default \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22,tcp:3389 \
  --source-ranges=0.0.0.0/0

# Note: there's no fixture here for public_access_audit.sh's project-level
# IAM check. Google now hard-rejects allUsers/allAuthenticatedUsers as
# project-level IAM policy members (PROJECT_SET_IAM_DISALLOWED_MEMBER_TYPE) -
# that grant simply can't be created anymore on a project like this one.
# The bucket-level public binding below still exercises the other half of
# that script.

# --- public_access_audit.sh + gcs_public_objects_audit.sh: buckets ---------
# Bucket 1: uniform access, public via IAM binding (caught by
# public_access_audit.sh).
gcloud storage buckets create "gs://fixture-uniform-public-${PROJECT_ID}" \
  --project="$PROJECT_ID" --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding "gs://fixture-uniform-public-${PROJECT_ID}" \
  --member=allUsers --role=roles/storage.objectViewer

# Bucket 2: fine-grained (non-uniform) access with a public object ACL
# (caught by gcs_public_objects_audit.sh, invisible to the IAM-binding check).
gcloud storage buckets create "gs://fixture-finegrained-${PROJECT_ID}" \
  --project="$PROJECT_ID" --no-uniform-bucket-level-access
echo "fixture object contents" > /tmp/fixture-object.txt
gcloud storage cp /tmp/fixture-object.txt "gs://fixture-finegrained-${PROJECT_ID}/fixture-object.txt"
gcloud storage objects update "gs://fixture-finegrained-${PROJECT_ID}/fixture-object.txt" \
  --add-acl-grant=entity=allUsers,role=READER

# --- bigquery_public_audit.sh: public dataset -------------------------------
# allUsers has to be granted via the `iamMember` field, not the legacy
# `specialGroup` field (specialGroup only accepts allAuthenticatedUsers and
# the project*/projectReaders-style groups) - bq rejects allUsers under
# specialGroup outright. Also writes the patch to a real temp file rather
# than piping through process substitution, which `bq update --source` does
# not reliably read.
bq --headless mk --dataset --project_id="$PROJECT_ID" "${PROJECT_ID}:fixture_public_dataset"
BQ_PATCH="$(mktemp)"
bq --headless show --format=prettyjson "${PROJECT_ID}:fixture_public_dataset" | grep -v '^WARNING:' | \
  jq '{access: (.access + [{"role":"READER","iamMember":"allUsers"}])}' > "$BQ_PATCH"
bq --headless update --project_id="$PROJECT_ID" --source="$BQ_PATCH" "${PROJECT_ID}:fixture_public_dataset"
rm -f "$BQ_PATCH"

# --- privileged_roles_audit.sh: primitive owner grant -----------------------
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:fixture-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role=roles/owner \
  --condition=None >/dev/null

echo "Done. Note:"
echo "  - audit_log_review.sh / privilege_escalation_audit.sh need audit logs to"
echo "    catch up (usually seconds-to-minutes) before the SetIamPolicy calls above show up."
echo "  - org_policy_audit.sh needs no fixture - a fresh project has no org policy"
echo "    overrides set, so it flags 'not enforced' out of the box."
echo "  - scc_findings_audit.sh depends on SCC's own scan cadence (not instant) -"
echo "    give it time before expecting the fixtures above to show up as findings."
echo "  - [SELF-GRANT] detection in privilege_escalation_audit.sh isn't planted here"
echo "    on purpose - it requires activating fixture-sa's own key and having it"
echo "    grant itself roles/owner, which means a real owner-capable key sitting"
echo "    on disk. Do that manually and briefly if you want to test that specific path."
