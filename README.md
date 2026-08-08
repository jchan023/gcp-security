# gcp-iam

Small scripts for auditing Google Cloud IAM and API key hygiene across every
project in an org. Mostly loops, if we're being honest.

## What's here

| Script | What it does |
| --- | --- |
| [`gcloud_unreskeys.sh`](gcloud_unreskeys.sh) | Flags API keys that have **no restrictions** (no API restriction, no application restriction). Unrestricted keys are one of the most common ways GCP credentials get abused after a leak. |
| [`sa_key_age_audit.sh`](sa_key_age_audit.sh) | Flags user-managed **service account keys** older than `MAX_KEY_AGE_DAYS` (default 90). Long-lived SA keys are stale credentials waiting to be leaked. |
| [`public_access_audit.sh`](public_access_audit.sh) | Flags project- and **bucket-level IAM bindings** granted to `allUsers` or `allAuthenticatedUsers` — i.e. anything exposed to the public internet. |
| [`privileged_roles_audit.sh`](privileged_roles_audit.sh) | Flags members holding primitive **`roles/owner`/`roles/editor`**, and lists any custom roles in use for manual review. |
| [`project_access.sh`](project_access.sh) | Dumps the full IAM policy for every project to `output.txt`, plus a `project,role,member` CSV (`access_summary.csv`) for spreadsheet review, diffing over time, or grepping for a principal/role across the whole org. |

All five loop through every project in whatever org/folder the active
`gcloud` identity can see, and are strictly read-only.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install), authenticated (`gcloud auth login`)
- [`jq`](https://jqlang.org/download/) — only needed for `project_access.sh`'s CSV summary
- An identity with at least (ideally a dedicated read-only auditor service account):
  - `resourcemanager.projects.list` at the org/folder level, to enumerate projects
  - `serviceusage.apiKeys.list`, for `gcloud_unreskeys.sh`
  - `iam.serviceAccounts.list` / `iam.serviceAccountKeys.list`, for `sa_key_age_audit.sh`
  - `resourcemanager.projects.getIamPolicy` and `storage.buckets.{list,getIamPolicy}`, for `public_access_audit.sh`
  - `resourcemanager.projects.getIamPolicy`, for `privileged_roles_audit.sh` and `project_access.sh`
  - The predefined `roles/viewer` + `roles/iam.securityReviewer` roles cover all of the above.
- Bash

## Usage

```bash
./gcloud_unreskeys.sh                          # unrestricted API keys
MAX_KEY_AGE_DAYS=60 ./sa_key_age_audit.sh       # stale service account keys (default 90d)
./public_access_audit.sh                        # public IAM bindings (projects + buckets)
./privileged_roles_audit.sh                     # owner/editor + custom role bindings
./project_access.sh                             # full IAM dump -> output.txt + access_summary.csv
```

All scripts operate on whatever projects `gcloud projects list` returns for
the currently active account/config, so double-check `gcloud config list`
before running against anything sensitive.

## Running on a schedule (CI)

[`.github/workflows/gcp-iam-audit.yml`](.github/workflows/gcp-iam-audit.yml)
runs all four flag-raising audits daily via GitHub Actions and fails the run
(uploading results as a build artifact) if anything is found, so drift shows
up without anyone having to remember to run these by hand.

It authenticates via [Workload Identity
Federation](https://github.com/google-github-actions/auth#setup) (no long-lived
key in GitHub) — set these repo secrets to enable it:

- `GCP_WORKLOAD_IDENTITY_PROVIDER` — full WIF provider resource name
- `GCP_SERVICE_ACCOUNT` — email of a read-only auditor service account (see
  permissions above) that the WIF pool is allowed to impersonate

Trigger it manually any time from the Actions tab, or wait for the daily run.

## Notes

- None of these scripts modify anything — they're read-only/audit scripts.
- `output.txt` and `access_summary.csv` are git-ignored; both contain
  sensitive IAM data, so don't commit or share them outside your org.
