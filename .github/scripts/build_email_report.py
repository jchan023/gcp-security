#!/usr/bin/env python3
"""
Builds the categorized findings email body: New Findings, Existing Findings
(with first-seen date), Drift, All Clear.

"Drift" is org_policy_drift.txt specifically (org_policy_audit.sh's output) -
policy state, shown as-is rather than run through new/existing tracking.
Every other findings/*.txt file with real findings has each line tracked
individually in a history file (restored/saved via GitHub Actions cache
across runs, since a public repo can't have this committed - see README) so
a finding that's been open for a week doesn't get re-announced as new every
single day.

A findings/*.txt file whose entire content is a single "No ..." line counts
as All Clear for that check.
"""
import json
import os
import re
from datetime import date

FINDINGS_DIR = "findings"
HISTORY_PATH = ".findings-history/history.json"
DRIFT_FILE = "org_policy_drift.txt"
SCOPE_PATH = ".scope/scope.json"

TODAY = date.today().isoformat()

CONSTRAINT_RE = re.compile(r"(constraints/[\w.]+)")

# Short human-readable context for each constraint org_policy_audit.sh
# checks, so a drift line isn't just a bare constraint ID in the email.
# Keep in sync with the CONSTRAINTS list in org_policy_audit.sh.
CONSTRAINT_DESCRIPTIONS = {
    "constraints/iam.disableServiceAccountKeyCreation":
        "Blocks creating new user-managed SA keys - stale/leaked keys are a common credential-abuse vector.",
    "constraints/iam.disableServiceAccountKeyUpload":
        "Blocks uploading externally-created public keys for service accounts.",
    "constraints/iam.automaticIamGrantsForDefaultServiceAccounts":
        "Stops default service accounts from auto-getting broad roles (e.g. Editor) on project creation.",
    "constraints/compute.requireOsLogin":
        "Requires OS Login for SSH instead of metadata-based SSH keys, tying VM access to IAM.",
    "constraints/compute.requireShieldedVm":
        "Requires Shielded VM (secure boot, vTPM, integrity monitoring) on new Compute instances.",
    "constraints/compute.disableSerialPortAccess":
        "Blocks serial console access to VMs - an alternate, less-audited path into a running instance.",
    "constraints/storage.uniformBucketLevelAccess":
        "Requires IAM-only bucket access, disabling legacy per-object ACLs that can grant access invisibly to IAM checks.",
    "constraints/storage.publicAccessPrevention":
        "Blocks buckets/objects from ever being made public (allUsers/allAuthenticatedUsers), regardless of IAM or ACL grants.",
    "constraints/sql.restrictPublicIp":
        "Blocks Cloud SQL instances from getting a public IP address.",
    "constraints/sql.restrictAuthorizedNetworks":
        "Blocks Cloud SQL authorized-network entries (e.g. 0.0.0.0/0) that open the database to the internet.",
    "constraints/compute.skipDefaultNetworkCreation":
        "Stops new projects from auto-creating the default VPC with its permissive pre-made firewall rules.",
    "constraints/compute.vmExternalIpAccess":
        "List constraint: limits which VMs may have an external IP. Unset means any VM can be given a public address.",
    "constraints/iam.allowedPolicyMemberDomains":
        "List constraint: limits IAM grants to approved domains/orgs. Unset means anyone (any Google account) can be granted access.",
}


def describe_drift_line(line):
    match = CONSTRAINT_RE.search(line)
    if not match:
        return line
    description = CONSTRAINT_DESCRIPTIONS.get(match.group(1))
    if not description:
        return line
    return f"{line}\n    {description}"


def load_scope():
    """{project-id: [framework, ...]} from scope_map.sh, or {} if not built.

    Holds real project IDs, so it lives outside findings/ (never uploaded)
    and is only used here to tag lines in the emailed report."""
    if os.path.exists(SCOPE_PATH):
        with open(SCOPE_PATH) as f:
            return json.load(f)
    return {}


def scope_tags(line, scope_re, scope):
    """Frameworks (sorted) for every in-scope project mentioned in the line."""
    if not scope_re:
        return []
    frameworks = set()
    for pid in scope_re.findall(line):
        frameworks.update(scope.get(pid, []))
    return sorted(frameworks)


def load_history():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return {}


def save_history(history):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2, sort_keys=True)


def section(title, items):
    if not items:
        return f"{title}\n(none)\n"
    body = "\n".join(f"- {i}" for i in items)
    return f"{title}\n{body}\n"


def main():
    history = load_history()
    scope = load_scope()
    scope_re = (
        re.compile("|".join(re.escape(p) for p in sorted(scope, key=len, reverse=True)))
        if scope else None
    )
    by_framework = {}
    new_items, existing_items, drift_items, clear_items = [], [], [], []
    seen_keys = set()

    for fname in sorted(os.listdir(FINDINGS_DIR)):
        if not fname.endswith(".txt"):
            continue
        check = fname[:-4]
        with open(os.path.join(FINDINGS_DIR, fname)) as f:
            content = f.read().strip()
        if not content:
            continue
        lines = content.splitlines()

        if len(lines) == 1 and lines[0].startswith("No "):
            clear_items.append(f"{check}: {lines[0]}")
            continue

        if fname == DRIFT_FILE:
            drift_items.extend(describe_drift_line(f"{check}: {line}") for line in lines)
            continue

        for line in lines:
            key = f"{check}|{line}"
            seen_keys.add(key)
            tags = scope_tags(line, scope_re, scope)
            tag = f"  [{', '.join(t.upper() for t in tags)}]" if tags else ""
            for t in tags:
                by_framework[t] = by_framework.get(t, 0) + 1
            if key in history:
                existing_items.append(f"{check}: {line}{tag}  (first seen {history[key]})")
            else:
                history[key] = TODAY
                new_items.append(f"{check}: {line}{tag}")

    # Drop history entries for findings that no longer appear at all - if
    # one comes back later it correctly shows as new again, rather than
    # resurrecting a stale first-seen date.
    history = {k: v for k, v in history.items() if k in seen_keys}
    save_history(history)

    scope_lines = [
        f"{fw.upper()}: {n} finding line(s) on in-scope projects" for fw, n in sorted(by_framework.items())
    ]
    if scope and not scope_lines:
        scope_lines = ["No findings on in-scope projects"]
    report = "\n".join([
        section("By Compliance Scope", scope_lines) if scope else "",
        section("New Findings", new_items),
        section("Existing Findings", existing_items),
        section("Drift", drift_items),
        section("All Clear", clear_items),
    ])
    print(report)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"new_count={len(new_items)}\n")
            f.write(f"existing_count={len(existing_items)}\n")
            f.write(f"drift_count={len(drift_items)}\n")


if __name__ == "__main__":
    main()
