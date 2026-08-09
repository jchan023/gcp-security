# gcp-security

Scripts for auditing Google Cloud IAM, API key hygiene, and suspicious
activity across every project in an org. Mostly loops.

## What's here

### Configuration audits (point-in-time state)

| Script | What it does |
| --- | --- |
| [`gcloud_unreskeys.sh`](gcloud_unreskeys.sh) | Flags API keys that have **no restrictions** (no API restriction, no application restriction). Unrestricted keys are one of the most common ways GCP credentials get abused after a leak. |
| [`sa_key_age_audit.sh`](sa_key_age_audit.sh) | Flags user-managed **service account keys** older than `MAX_KEY_AGE_DAYS` (default 90). Long-lived SA keys are stale credentials waiting to be leaked. |
| [`public_access_audit.sh`](public_access_audit.sh) | Flags project- and **bucket-level IAM bindings** granted to `allUsers` or `allAuthenticatedUsers` — i.e. anything exposed to the public internet. |
| [`privileged_roles_audit.sh`](privileged_roles_audit.sh) | Flags members holding primitive **`roles/owner`/`roles/editor`**, and lists any custom roles in use for manual review. |
| [`project_access.sh`](project_access.sh) | Dumps the full IAM policy for every project to `output.txt`, plus a `project,role,member` CSV (`access_summary.csv`) for spreadsheet review, diffing over time, or grepping for a principal/role across the whole org. |

### Activity audits (behavior over a time window)

These read Cloud Audit Logs instead of current IAM state, so they can catch
**insider threats and compromised credentials in the act** — not just bad
configuration sitting around.

| Script | What it does |
| --- | --- |
| [`audit_log_review.sh`](audit_log_review.sh) | Scans Admin Activity logs for high-risk actions in the last `LOOKBACK_HOURS` (default 24): IAM policy changes, new/deleted service accounts and keys, token/JWT impersonation (`GenerateAccessToken`, `SignJwt`, `SignBlob`), SSH-key/startup-script metadata edits, and **audit log sink tampering** (an attacker or insider covering their tracks). |
| [`privilege_escalation_audit.sh`](privilege_escalation_audit.sh) | Parses `SetIamPolicy` audit log entries for grants of `roles/owner`, `roles/editor`, or any `*Admin` role, showing who granted what to whom. Flags `[SELF-GRANT]` when a principal grants itself the privileged role — the sharpest single insider-threat signal available in IAM audit logs. |

All seven loop through every project in whatever org/folder the active
`gcloud` identity can see, and are strictly read-only.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install), authenticated (`gcloud auth login`)
- [`jq`](https://jqlang.org/download/) — needed for `project_access.sh`'s CSV summary and `privilege_escalation_audit.sh`
- An identity with at least (ideally a dedicated read-only auditor service account):
  - `resourcemanager.projects.list` at the org/folder level, to enumerate projects
  - `serviceusage.apiKeys.list`, for `gcloud_unreskeys.sh`
  - `iam.serviceAccounts.list` / `iam.serviceAccountKeys.list`, for `sa_key_age_audit.sh`
  - `resourcemanager.projects.getIamPolicy` and `storage.buckets.{list,getIamPolicy}`, for `public_access_audit.sh`
  - `resourcemanager.projects.getIamPolicy`, for `privileged_roles_audit.sh` and `project_access.sh`
  - `logging.logEntries.list`, for `audit_log_review.sh` and `privilege_escalation_audit.sh` (Admin Activity logs — always-on, no extra logging config needed)
  - The predefined `roles/viewer` + `roles/iam.securityReviewer` + `roles/logging.viewer` roles cover all of the above.
- Bash

## Usage

```bash
./gcloud_unreskeys.sh                              # unrestricted API keys
MAX_KEY_AGE_DAYS=60 ./sa_key_age_audit.sh           # stale service account keys (default 90d)
./public_access_audit.sh                            # public IAM bindings (projects + buckets)
./privileged_roles_audit.sh                         # owner/editor + custom role bindings
./project_access.sh                                 # full IAM dump -> output.txt + access_summary.csv

LOOKBACK_HOURS=72 ./audit_log_review.sh             # high-risk admin actions (default 24h)
LOOKBACK_HOURS=72 ./privilege_escalation_audit.sh   # owner/editor/Admin role grants, flags self-grants
```

All scripts operate on whatever projects `gcloud projects list` returns for
the currently active account/config, so double-check `gcloud config list`
before running against anything sensitive.

## Running on a schedule (CI)

[`.github/workflows/gcp-security-audit.yml`](.github/workflows/gcp-security-audit.yml)
runs all six flag-raising audits daily via GitHub Actions and fails the run
(uploading results as a build artifact) if anything is found, so drift and
suspicious activity show up without anyone having to remember to run these
by hand.

It authenticates via [Workload Identity
Federation](https://github.com/google-github-actions/auth#setup) (no long-lived
key in GitHub) — set these repo secrets to enable it:

- `GCP_WORKLOAD_IDENTITY_PROVIDER` — full WIF provider resource name
- `GCP_SERVICE_ACCOUNT` — email of a read-only auditor service account (see
  permissions above) that the WIF pool is allowed to impersonate

Trigger it manually any time from the Actions tab, or wait for the daily run.
The audit-log scripts default to a 24h lookback to match the daily cadence —
if you widen the schedule, widen `LOOKBACK_HOURS` in the workflow to match,
or you'll have gaps between runs.

## Notes

- None of these scripts modify anything — they're read-only/audit scripts.
- `output.txt` and `access_summary.csv` are git-ignored; both contain
  sensitive IAM data, so don't commit or share them outside your org.
- The activity audits only see what's in Cloud Audit Logs, which have a
  [400-day retention limit](https://cloud.google.com/logging/quotas) by
  default — for real insider-threat investigations, also export logs to a
  [log sink](https://cloud.google.com/logging/docs/export) (BigQuery or GCS)
  for longer retention and richer querying.
