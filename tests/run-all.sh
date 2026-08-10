#!/usr/bin/env bash
# Run every Warp Gate suite. Exits non-zero if any suite fails.
# Deliberately does not pipe anything through head or tail: a truncated result
# would read as absence.

set -u
cd "$(dirname "$0")/.." || exit 2

# Two suites are deliberately absent, both because they drive a LIVE DEPLOYMENT over the
# real network and are run by hand against a URL:
#
#   tests/public-e2e.mjs       the full two-peer lifecycle over the public path
#   tests/cdn-injection.test.mjs   whether the CDN modifies the gate document, and whether
#                                  the CSP stops what it injects
#
# Do not add either to the list below. This runner is meant to pass offline, and a suite
# that needs the internet turns "no network" into a product failure. See deploy/NOTES.md
# for where they belong: the deploy sequence, before and after.
# `legal` was missing from this list until 2026-08-10 and had therefore never run here.
# It was not an exclusion, it was an omission: the file exists, passes 24/24 offline and
# needs no network. That is the failure mode this list has, so the completeness of the list
# is now checked below rather than trusted.
suites=(crypto qr qrdecode size signalling http suggest download browser mesh games gameplay saswords pwa motion legal securecontext)

# Deliberately not run, and therefore deliberately not a gap. Anything in tests/ that is
# neither here nor above is an omission and stops the run.
excluded=(cdn-injection)

# A suite nobody runs reports nothing and reads exactly like a suite that passes. Compared
# with comm rather than a grep per file, because a grep that finds nothing and a grep that
# was never reached print the same thing.
have=$(printf '%s\n' tests/*.test.mjs | sed 's|^tests/||; s|\.test\.mjs$||' | sort)
listed=$(printf '%s\n' "${suites[@]}" "${excluded[@]}" | sort)
missing=$(comm -23 <(printf '%s\n' "$have") <(printf '%s\n' "$listed"))
absent=$(comm -13 <(printf '%s\n' "$have") <(printf '%s\n' "$listed"))
if [ -n "$missing" ]; then
  printf 'RUNNER INCOMPLETE: test files that are neither run nor excluded:\n%s\n' "$missing"
  exit 2
fi
if [ -n "$absent" ]; then
  printf 'RUNNER STALE: named suites with no test file:\n%s\n' "$absent"
  exit 2
fi
failed=()

for suite in "${suites[@]}"; do
  printf '\n=========== %s ===========\n' "$suite"
  if node "tests/${suite}.test.mjs"; then
    printf 'SUITE OK   %s\n' "$suite"
  else
    printf 'SUITE BAD  %s\n' "$suite"
    failed+=("$suite")
  fi
done

printf '\n===================================\n'
if [ ${#failed[@]} -eq 0 ]; then
  printf 'ALL SUITES PASSED (%d/%d)\n' "${#suites[@]}" "${#suites[@]}"
  exit 0
fi
printf 'FAILED SUITES: %s\n' "${failed[*]}"
exit 1
