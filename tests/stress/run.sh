#!/usr/bin/env bash
# Exploratory stress suite. Each file boots its own server, browser and gate on its own
# ports, so they are run one at a time: two headless browsers moving hundreds of
# megabytes at once measures the machine, not the product.
#
# Expect failures. These scripts exist to find breakage, not to gate a build.
set -u
cd "$(dirname "$0")/../.."

fail=0
for t in smoke units composer-cost images weird messages large over-limit \
         concurrency misc giant-image repro-read-error-hang repro-chat-blocked; do
  printf '\n===== %s =====\n' "$t"
  node "tests/stress/$t.mjs" || fail=1
done
exit "$fail"
