#!/usr/bin/env bash
# Deterministic source identity for distribution builds without a .git checkout.
set -euo pipefail
cd "$(dirname "$0")/.."
{
  find api bazel patches source tools -type f -print0
  printf '%s\0' BUILD WORKSPACE .bazelrc .bazelversion envoy.bazelrc
} | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c 1-40
