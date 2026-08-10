#!/usr/bin/env bash
# Run every Warp Gate suite. Exits non-zero if any suite fails.
# Deliberately does not pipe anything through head or tail: a truncated result
# would read as absence.

set -u
cd "$(dirname "$0")/.." || exit 2

# public-e2e is deliberately absent: it drives a live deployment over the real network
# and is run by hand against a URL, not as part of a local run.
suites=(crypto qr signalling http download browser mesh)
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
