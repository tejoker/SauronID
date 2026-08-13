#!/usr/bin/env bash
# Thin wrapper. The check itself lives in transparent-zk/verify.sh because that
# directory is published on its own to a public mirror: customers reproduce the
# guest image IDs by running the identical script, so there is one
# implementation rather than a CI copy and a customer copy that can drift.
set -euo pipefail
exec bash "$(cd "$(dirname "$0")/../.." && pwd)/transparent-zk/verify.sh" "$@"
