#!/bin/bash -
#===============================================================================
# Shared helpers, sourced by the audit scripts (not run on its own).
#
# The audit scripts used to send every gcloud error to /dev/null, which made a
# permission denial or API failure look identical to "no findings". Capture
# stderr into $ERR instead and call skip_check after a failed command:
#
#   OUT=$(gcloud ... 2>"$ERR") || { skip_check "$project" "label"; OUT=""; }
#
# skip_check stays quiet when a PROJECT-scoped failure just means the API is
# disabled there (nothing can exist in it to audit). Org-scoped checks
# (scope "org <id>") never get that pass: a disabled Cloud Asset/SCC API at
# org level means the check has no coverage at all. Any other failure prints a
# "<project>: SKIPPED (<label>): <reason>" line and sets FOUND=true, so the
# check shows up as a finding instead of a false all-clear.
#===============================================================================

ERR=$(mktemp)
trap 'rm -f "$ERR"' EXIT

skip_check() {
  local scope="$1" label="$2"
  case "$scope" in
    org\ *) ;;
    *)
      if grep -qiE 'SERVICE_DISABLED|has not been used in project|is not enabled|API \[.*\] not enabled' "$ERR"; then
        return 0
      fi
      ;;
  esac
  echo "$scope: SKIPPED ($label): $(tr '\n' ' ' < "$ERR" | tr -s ' ' | cut -c1-200)"
  FOUND=true
}

# True (exit 0) if a comma-separated allow list from firewall_rule() - e.g.
# "tcp:22,tcp:8000-9000,icmp" - exposes a sensitive management/database port.
# Matches exact ports, port ranges that span one, protocol-only entries
# (tcp/udp with no ports = every port) and "all".
SENSITIVE_PORTS="22 3389 3306 5432 1433 6379 27017 9200 9092 11211"
exposes_sensitive() {
  echo "$1" | tr ',' '\n' | awk -v ports="$SENSITIVE_PORTS" '
    BEGIN { n = split(ports, P, " ") }
    {
      t = $0
      if (t == "all" || t == "tcp" || t == "udp" || t == "sctp") { found = 1; next }
      if (match(t, /^(tcp|udp|sctp):/)) {
        r = substr(t, RLENGTH + 1)
        if (index(r, "-")) { split(r, a, "-"); lo = a[1]; hi = a[2] } else { lo = r; hi = r }
        for (i = 1; i <= n; i++) if (P[i] + 0 >= lo + 0 && P[i] + 0 <= hi + 0) found = 1
      }
    }
    END { exit found ? 0 : 1 }'
}

# Matches the IPv4 and IPv6 "whole internet" CIDRs.
# Ranges come from a comma-separated list() so match whole comma-delimited items.
OPEN_CIDR_REGEX='(^|[, ])(0\.0\.0\.0/0|::/0)([, ]|$)'
is_open_cidr() { echo "$1" | grep -qE "$OPEN_CIDR_REGEX"; }
