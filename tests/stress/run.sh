#!/usr/bin/env bash
# Exploratory stress suite. Each file boots its own server, browser and gate on its own
# ports, so they are run one at a time: two headless browsers moving hundreds of
# megabytes at once measures the machine, not the product.
#
# Expect failures. These scripts exist to find breakage, not to gate a build.
set -u
cd "$(dirname "$0")/../.."

fail=0
found=0
for t in tests/stress/*.mjs; do
  [ -e "$t" ] || continue
  found=$((found + 1))
  printf '\n===== %s =====\n' "$(basename "$t" .mjs)"
  node "$t" || fail=1
done
if [ "$found" -eq 0 ]; then
  printf 'BAD  tests/stress/*.mjs matched nothing: the runner ran no suites\n'
  exit 2
fi
printf '\n%d stress files run\n' "$found"
exit "$fail"
