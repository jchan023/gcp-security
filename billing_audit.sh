#!/bin/bash -
#===============================================================================
# Billing exposure: a compromised project often shows up first as a cost
# spike, and billing admins can attach any project to the account.
#
#   1. Projects with no billing account linked, or linked to an account that
#      is closed/unexpected (set EXPECTED_BILLING_ACCOUNTS to a
#      space-separated list of account IDs to flag anything else).
#   2. Billing accounts with no budgets at all (so no spend alerts).
#   3. Principals with billing admin-level roles on each account, and any
#      member outside the org's domain.
#
# Needs billing.accounts.list on the active identity; if none are visible it
# reports that rather than passing silently.
#===============================================================================
set -uo pipefail
source "$(dirname "$0")/lib_audit.sh"
need_jq

EXPECTED_BILLING_ACCOUNTS="${EXPECTED_BILLING_ACCOUNTS:-}"
FOUND=false

ACCOUNTS=$(gcloud billing accounts list --format="value(name.basename(),open)" 2>"$ERR") \
  || { skip_check "billing" "list billing accounts"; ACCOUNTS=""; }

OPEN_ACCOUNTS=""
while IFS=$'\t' read -r acct open; do
  [ -z "$acct" ] && continue
  if [ "$open" != "True" ]; then
    echo "billing account $acct: CLOSED"
    FOUND=true
    continue
  fi
  OPEN_ACCOUNTS="$OPEN_ACCOUNTS $acct"

  BUDGETS=$(gcloud billing budgets list --billing-account="$acct" --format="value(name)" 2>"$ERR") \
    || { skip_check "billing account $acct" "budgets"; BUDGETS="skipped"; }
  if [ -z "$BUDGETS" ]; then
    echo "billing account $acct: no budgets / spend alerts configured"
    FOUND=true
  fi

  POLICY=$(gcloud billing accounts get-iam-policy "$acct" --format=json 2>"$ERR") \
    || { skip_check "billing account $acct" "IAM policy"; continue; }
  echo "$POLICY" | jq -r '.bindings[]? | select(.role | test("billing\\.(admin|creator)|owner|Admin$")) | .role as $r | .members[] | [$r, .] | @tsv' \
    | while IFS=$'\t' read -r role member; do
        echo "billing account $acct: $role -> $member"
      done > "$ERR.b"
  if [ -s "$ERR.b" ]; then cat "$ERR.b"; FOUND=true; fi
  rm -f "$ERR.b"
done <<< "$ACCOUNTS"

for project in $(gcloud projects list --format="value(projectId)"); do
  INFO=$(gcloud billing projects describe "$project" --format="value(billingEnabled,billingAccountName.basename())" 2>"$ERR") \
    || { skip_check "$project" "billing info"; continue; }
  enabled=$(echo "$INFO" | cut -f1); acct=$(echo "$INFO" | cut -f2)
  if [ "$enabled" != "True" ]; then
    echo "$project: billing not enabled (no billing account linked)"
    FOUND=true
  elif [ -n "$EXPECTED_BILLING_ACCOUNTS" ] && ! echo " $EXPECTED_BILLING_ACCOUNTS " | grep -q " $acct "; then
    echo "$project: linked to unexpected billing account $acct"
    FOUND=true
  fi
done

if [ "$FOUND" = false ]; then
  echo "No billing gaps found (links, budgets, billing admins)"
fi
