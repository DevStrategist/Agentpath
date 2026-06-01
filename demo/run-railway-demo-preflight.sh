#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
STATE="$(mktemp /tmp/keyring-railway-preflight-XXXXXX.json)"
trap 'rm -f "$STATE"' EXIT
say() { printf '%s\n' "$*"; }
check() {
  if "$@" >/dev/null 2>&1; then
    say "PASS $*"
  else
    say "FAIL $*"
    fail=1
  fi
}

say "KEYRING Railway demo preflight"
say "This checks readiness only. It does not install shims or mutate pf."
say ""

check command -v railway
if command -v keyring >/dev/null 2>&1; then
  say "PASS command -v keyring"
else
  check test -x ./bin/keyring
fi

KEYRING_STATE="$STATE" node -e "require('./src/core').ensureAccessRule('railway'); console.log('PASS access rule ok')" || fail=1
KEYRING_STATE="$STATE" node bin/keyring slack status || fail=1
KEYRING_STATE="$STATE" node bin/keyring access show --cli railway || fail=1

say ""
if [ "$fail" -eq 0 ]; then
  say "Preflight passed."
  say "Next: run sudo keyring install once, then use the dashboard or keyring gate add/install for real blocking."
  exit 0
fi

say "Preflight failed."
say "Install or configure the missing pieces above before the real Railway blocking demo."
exit 1
