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
# that needs the internet turns "no network" into a product failure. They belong in the
# deploy sequence instead, run against the live instance before and after it ships.
# `legal` was missing from this list until 2026-08-10 and had therefore never run here.
# It was not an exclusion, it was an omission: the file exists, passes 24/24 offline and
# needs no network. That is the failure mode this list has, so the completeness of the list
# is now checked below rather than trusted.
# `batchui` and `disconnect` were added to tests/ and never added here, so from the day they
# were written until 2026-08-10 the guard below aborted the whole runner with RUNNER INCOMPLETE
# and exit 2 BEFORE a single suite ran. The guard did its job: the failure was loud. What it
# shows is that adding a suite is two edits, not one, and that a runner which refuses to run is
# the correct behaviour rather than a nuisance to be worked around.
suites=(crypto qr qrdecode size signalling http suggest download outbound drain browser mesh games gameplay saswords pwa motion legal securecontext batchui disconnect)

# Deliberately not run, and therefore deliberately not a gap. Anything in tests/ that is
# neither here nor above is an omission and stops the run.
excluded=(cdn-injection)

# Runnable tests that are not tests/*.test.mjs, each with the command that calls it.
# This roster exists because the guard below used to glob tests/*.test.mjs ONLY, which
# made tests/stress/ (15 files, 166 checks) and extension/extension.test.mjs structurally
# invisible: both sat broken for their whole lives without this runner noticing.
extra_names=(stress extension)
extra_cmds=('bash tests/stress/run.sh' 'node extension/extension.test.mjs')

# Live-deployment suites run by hand against a URL, enumerated so a new tests/*.mjs that
# is neither a .test.mjs nor named here stops the run instead of joining them silently.
manual=(public-e2e)

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

# The same question for the files the old glob could not see. Every runnable test in the
# repo must have a caller; a file with none reports nothing, which reads as passing.
plain=$(printf '%s\n' tests/*.mjs | grep -v '\.test\.mjs$' | sed 's|^tests/||; s|\.mjs$||' | sort)
manual_listed=$(printf '%s\n' "${manual[@]}" | sort)
plain_missing=$(comm -23 <(printf '%s\n' "$plain") <(printf '%s\n' "$manual_listed"))
if [ -n "$plain_missing" ]; then
  printf 'RUNNER INCOMPLETE: tests/*.mjs with no caller and no exclusion:\n%s\n' "$plain_missing"
  exit 2
fi

# Every stress file must be reachable from the stress runner this script calls. The
# runner enumerates by glob today; if it ever goes back to a hand-kept roster, a file
# the roster omits has no caller and stops the run here. The glob has to appear in the
# for-statement that runs the files: it also appears in the runner's own error text, and
# matching it there once let a gutted roster pass this guard.
stress_orphans=''
if ! grep -qE '^[[:space:]]*for[[:space:]].*[[:space:]]in[[:space:]].*tests/stress/\*\.mjs' tests/stress/run.sh; then
  for f in tests/stress/*.mjs; do
    grep -qF "$(basename "$f")" tests/stress/run.sh || stress_orphans="${stress_orphans}${f}
"
  done
fi
if [ -n "$stress_orphans" ]; then
  printf 'RUNNER INCOMPLETE: stress files tests/stress/run.sh never names:\n%s' "$stress_orphans"
  exit 2
fi

# The stress runner itself must be on the extra-runner roster: verifying its internal
# completeness above means nothing if nothing here ever calls it. Deleting the stress
# entry from extra_cmds used to trip no guard at all, which is the tests/*.test.mjs-only
# seam again, one level up.
if [ -e tests/stress/run.sh ]; then
  stress_called=0
  for cmd in "${extra_cmds[@]}"; do
    case "$cmd" in *tests/stress/run.sh*) stress_called=1;; esac
  done
  if [ "$stress_called" -ne 1 ]; then
    printf 'RUNNER INCOMPLETE: tests/stress/run.sh exists but nothing here calls it\n'
    exit 2
  fi
fi

# And every extension test must be on the extra-runner roster above.
ext_orphans=''
for f in extension/*.test.mjs; do
  [ -e "$f" ] || continue
  hit=0
  for cmd in "${extra_cmds[@]}"; do
    case "$cmd" in *"$f"*) hit=1;; esac
  done
  [ "$hit" -eq 1 ] || ext_orphans="${ext_orphans}${f}
"
done
if [ -n "$ext_orphans" ]; then
  printf 'RUNNER INCOMPLETE: extension test files with no caller:\n%s' "$ext_orphans"
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

for i in "${!extra_names[@]}"; do
  printf '\n=========== %s ===========\n' "${extra_names[$i]}"
  if ${extra_cmds[$i]}; then
    printf 'SUITE OK   %s\n' "${extra_names[$i]}"
  else
    printf 'SUITE BAD  %s\n' "${extra_names[$i]}"
    failed+=("${extra_names[$i]}")
  fi
done

total=$(( ${#suites[@]} + ${#extra_names[@]} ))
printf '\n===================================\n'
if [ ${#failed[@]} -eq 0 ]; then
  printf 'ALL SUITES PASSED (%d/%d)\n' "$total" "$total"
  exit 0
fi
printf 'FAILED SUITES: %s (%d/%d passed)\n' "${failed[*]}" "$(( total - ${#failed[@]} ))" "$total"
exit 1
