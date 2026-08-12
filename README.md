# gcp-security

[![GCP Security Audit](https://github.com/jchan023/gcp-security/actions/workflows/gcp-security-audit.yml/badge.svg)](https://github.com/jchan023/gcp-security/actions/workflows/gcp-security-audit.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
| [`firewall_public_audit.sh`](firewall_public_audit.sh) | Flags **VPC firewall rules** open to `0.0.0.0/0`, and separately flags the ones that also expose sensitive ports (SSH, RDP, SQL, Redis, Mongo, etc.) — the ones internet-wide scanners find within minutes. |
| [`gcs_public_objects_audit.sh`](gcs_public_objects_audit.sh) | Flags **GCS exposure below the IAM-binding level**: buckets without Public Access Prevention enforced, buckets still using fine-grained (non-uniform) access, and individual public object ACLs on those buckets. |
| [`bigquery_public_audit.sh`](bigquery_public_audit.sh) | Flags **BigQuery datasets** shared with `allUsers`/`allAuthenticatedUsers` — dataset-level sharing that project IAM checks don't see. |
| [`org_policy_audit.sh`](org_policy_audit.sh) | Flags projects where key **boolean org policy constraints** (SA key creation/upload, OS Login, Shielded VM, serial port access, uniform bucket access, default SA auto-grants) aren't enforced — catches project-level exceptions that silently override an org/folder-level policy. |

### Activity audits (behavior over a time window)

These read Cloud Audit Logs instead of current IAM state, so they can catch
**insider threats and compromised credentials in the act** — not just bad
configuration sitting around.

| Script | What it does |
| --- | --- |
| [`audit_log_review.sh`](audit_log_review.sh) | Scans Admin Activity logs for high-risk actions in the last `LOOKBACK_HOURS` (default 24): IAM policy changes, new/deleted service accounts and keys, token/JWT impersonation (`GenerateAccessToken`, `SignJwt`, `SignBlob`), SSH-key/startup-script metadata edits, and **audit log sink tampering** (an attacker or insider covering their tracks). |
| [`privilege_escalation_audit.sh`](privilege_escalation_audit.sh) | Parses `SetIamPolicy` audit log entries for grants of `roles/owner`, `roles/editor`, or any `*Admin` role, showing who granted what to whom. Flags `[SELF-GRANT]` when a principal grants itself the privileged role — the sharpest single insider-threat signal available in IAM audit logs. |

### External findings (Security Command Center)

Unlike the other scripts, this one doesn't loop projects itself — it queries
Security Command Center directly, which already aggregates findings across
the whole org.

| Script | What it does |
| --- | --- |
| [`scc_findings_audit.sh`](scc_findings_audit.sh) | Pulls `ACTIVE` findings (default `CRITICAL`/`HIGH` severity, override with `MIN_SEVERITIES`) from **Security Command Center** for every org the active identity can see. SCC Standard tier is free and covers misconfiguration/vulnerability detection (Security Health Analytics, Anomaly Detection, Artifact Registry scanning) that complements, not overlaps, the audit-log-based scripts above — Standard tier has no active-threat detection (that's Premium/Enterprise only). |

All twelve loop through every project (or, for `scc_findings_audit.sh`, every
org) in whatever org/folder the active `gcloud` identity can see, and are
strictly read-only.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install), authenticated (`gcloud auth login`)
- [`jq`](https://jqlang.org/download/) — needed for `project_access.sh`'s CSV summary, `privilege_escalation_audit.sh`, and `bigquery_public_audit.sh`
- `bq` CLI (bundled with the Cloud SDK — `gcloud components install bq`), for `bigquery_public_audit.sh`
- An identity with at least (ideally a dedicated read-only auditor service account):
  - `resourcemanager.projects.list` at the org/folder level, to enumerate projects
  - `serviceusage.apiKeys.list`, for `gcloud_unreskeys.sh`
  - `iam.serviceAccounts.list` / `iam.serviceAccountKeys.list`, for `sa_key_age_audit.sh`
  - `resourcemanager.projects.getIamPolicy` and `storage.buckets.{list,getIamPolicy}`, for `public_access_audit.sh`
  - `resourcemanager.projects.getIamPolicy`, for `privileged_roles_audit.sh` and `project_access.sh`
  - `logging.logEntries.list`, for `audit_log_review.sh` and `privilege_escalation_audit.sh` (Admin Activity logs — always-on, no extra logging config needed)
  - `compute.firewalls.list`, for `firewall_public_audit.sh`
  - `storage.buckets.get` and `storage.objects.{list,get}`, for `gcs_public_objects_audit.sh` (object ACL visibility needs legacy bucket/object reader access, not just the Storage Object Viewer role - and `roles/storage.legacyBucketReader`/`legacyObjectReader` can only be bound at the project or bucket level, not the org, so the object-ACL check in this script is a blind spot for an org-wide auditor SA unless granted per-project)
  - `bigquery.datasets.get`, for `bigquery_public_audit.sh`
  - `orgpolicy.policy.get`, for `org_policy_audit.sh`
  - `resourcemanager.organizations.get` and `securitycenter.findings.list`, for `scc_findings_audit.sh` — also requires [Security Command Center](https://console.cloud.google.com/security/command-center) to actually be activated on the org (Standard tier is free)
  - The predefined `roles/viewer` + `roles/iam.securityReviewer` + `roles/logging.viewer` roles cover the original seven scripts; add `roles/storage.objectViewer` (org-grantable, but no ACL visibility - see note above), `roles/bigquery.metadataViewer`, `roles/orgpolicy.policyViewer`, and `roles/securitycenter.findingsViewer` for the five new ones.
- Bash

## Usage

```bash
./gcloud_unreskeys.sh                              # unrestricted API keys
MAX_KEY_AGE_DAYS=60 ./sa_key_age_audit.sh           # stale service account keys (default 90d)
./public_access_audit.sh                            # public IAM bindings (projects + buckets)
./privileged_roles_audit.sh                         # owner/editor + custom role bindings
./project_access.sh                                 # full IAM dump -> output.txt + access_summary.csv
./firewall_public_audit.sh                          # firewall rules open to 0.0.0.0/0
./gcs_public_objects_audit.sh                       # PAP/uniform-access gaps + public object ACLs
./bigquery_public_audit.sh                          # public BigQuery dataset access
./org_policy_audit.sh                               # security-relevant org policy drift

LOOKBACK_HOURS=72 ./audit_log_review.sh             # high-risk admin actions (default 24h)
LOOKBACK_HOURS=72 ./privilege_escalation_audit.sh   # owner/editor/Admin role grants, flags self-grants

MIN_SEVERITIES=CRITICAL,HIGH,MEDIUM ./scc_findings_audit.sh  # SCC findings (default CRITICAL,HIGH)
```

All scripts operate on whatever projects `gcloud projects list` returns for
the currently active account/config, so double-check `gcloud config list`
before running against anything sensitive.

## Running on a schedule (CI)

[`.github/workflows/gcp-security-audit.yml`](.github/workflows/gcp-security-audit.yml)
runs all eleven flag-raising audits daily via GitHub Actions and fails the run
(uploading results as a build artifact) if anything is found, so drift and
suspicious activity show up without anyone having to remember to run these
by hand.

It authenticates via [Workload Identity
Federation](https://github.com/google-github-actions/auth#setup) (no long-lived
key in GitHub) — set these repo secrets to enable it:

- `GCP_WORKLOAD_IDENTITY_PROVIDER` — full WIF provider resource name
- `GCP_SERVICE_ACCOUNT` — email of a read-only auditor service account (see
  permissions above) that the WIF pool is allowed to impersonate

Every run also emails a categorized findings summary so a run and its
results are visible without opening GitHub. The body is split into four
sections:

- **New Findings** — findings not seen in any prior run
- **Existing Findings** — findings seen before, with the date first observed
- **Drift** — [`org_policy_audit.sh`](org_policy_audit.sh)'s output
  specifically (policy state, shown as-is rather than new/existing-tracked)
- **All Clear** — checks that came back clean

New-vs-existing tracking needs a history file that survives across runs.
That can't be committed to the repo (findings history — project IDs, IAM
emails, misconfiguration details — would then be public, since this repo
is), so it's kept in a [GitHub Actions
cache](https://docs.github.com/actions/writing-workflows/choosing-what-your-workflow-does/caching-dependencies-to-speed-up-workflows)
instead ([`.github/scripts/build_email_report.py`](.github/scripts/build_email_report.py)
builds it). A finding that disappears and later comes back is treated as
new again, not resurrected with its old first-seen date.

Set these two additional repo secrets to enable the email step:

- `MAIL_USERNAME` — a Gmail address to send from
- `MAIL_PASSWORD` — a Gmail [App
  Password](https://myaccount.google.com/apppasswords) for that address, **not**
  the account password (Google requires 2-Step Verification to be enabled to
  generate one)

The recipient address is hardcoded to `jchan023@gmail.com` in the workflow —
change it there if needed. If these two secrets aren't set, the email step
fails but doesn't block the rest of the run (findings still show up in the
Actions log and the uploaded artifact either way).

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

## License

[MIT](LICENSE)
