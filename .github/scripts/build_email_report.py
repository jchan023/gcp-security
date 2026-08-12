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
from datetime import date

FINDINGS_DIR = "findings"
HISTORY_PATH = ".findings-history/history.json"
DRIFT_FILE = "org_policy_drift.txt"

TODAY = date.today().isoformat()


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
            drift_items.extend(f"{check}: {line}" for line in lines)
            continue

        for line in lines:
            key = f"{check}|{line}"
            seen_keys.add(key)
            if key in history:
                existing_items.append(f"{check}: {line}  (first seen {history[key]})")
            else:
                history[key] = TODAY
                new_items.append(f"{check}: {line}")

    # Drop history entries for findings that no longer appear at all - if
    # one comes back later it correctly shows as new again, rather than
    # resurrecting a stale first-seen date.
    history = {k: v for k, v in history.items() if k in seen_keys}
    save_history(history)

    report = "\n".join([
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
