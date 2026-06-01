#!/usr/bin/env bash
# Verify that macOS pf can filter outbound TCP by uid on THIS Mac.
# Non-destructive: creates a throwaway user, loads a tiny pf anchor, tests, tears everything down.
# Run with sudo. Exits 0 if uid filtering works (architecture green-lit) and 1 if not.
set -u
[[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash $0"; exit 2; }
[[ "$(uname)" == "Darwin" ]] || { echo "macOS only (use jail.sh on Linux)"; exit 2; }

USER_NAME="pfverify_$RANDOM"
ANCHOR=pfverify
ANCHOR_FILE="/etc/pf.anchors/$ANCHOR"
CONF_FILE="/etc/pf.$ANCHOR.conf"
CLEAN_PORT=8765   # picked arbitrarily; we never bind it, just use as a known-loopback target

cleanup() {
  echo
  echo "--- cleanup ---"
  pfctl -a "$ANCHOR" -F all 2>/dev/null || true
  rm -f "$ANCHOR_FILE" "$CONF_FILE"
  if id "$USER_NAME" >/dev/null 2>&1; then
    dscl . -delete "/Users/$USER_NAME" 2>/dev/null || true
    echo "  deleted user $USER_NAME"
  fi
  # Reload main pf.conf to drop our anchor reference
  pfctl -f /etc/pf.conf 2>/dev/null || true
}
trap cleanup EXIT

echo "=== KEYRING pf-user verification spike ==="
echo "this proves whether 'block out ... user X' actually drops packets for that uid."
echo

# 1) create throwaway user (no password, no home, no login shell needed)
NEXT_UID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1)
NEW_UID=$(( NEXT_UID + 1 ))
dscl . -create "/Users/$USER_NAME" >/dev/null
dscl . -create "/Users/$USER_NAME" UserShell /bin/sh >/dev/null
dscl . -create "/Users/$USER_NAME" UniqueID "$NEW_UID" >/dev/null
dscl . -create "/Users/$USER_NAME" PrimaryGroupID 20 >/dev/null
echo "[1/4] created throwaway user $USER_NAME (uid=$NEW_UID)"

# 2) baseline: that user CAN reach the internet right now (no rules loaded yet)
if sudo -u "$USER_NAME" curl -fsS -m 5 -o /dev/null https://example.com/ 2>/dev/null; then
  echo "[2/4] baseline OK: $USER_NAME can reach example.com"
else
  echo "[2/4] baseline FAILED: $USER_NAME couldn't reach example.com with no rules loaded. Network issue, not pf."
  exit 1
fi

# 3) install a pf anchor that blocks ALL egress for this uid
cat > "$ANCHOR_FILE" <<EOF
# pfverify — drop everything for uid $NEW_UID
block drop out quick proto tcp from any to any user $NEW_UID
block drop out quick proto udp from any to any user $NEW_UID
EOF
cat > "$CONF_FILE" <<EOF
anchor "$ANCHOR"
load anchor "$ANCHOR" from "$ANCHOR_FILE"
EOF
pfctl -f "$CONF_FILE" >/dev/null 2>&1
pfctl -E >/dev/null 2>&1 || true
echo "[3/4] loaded pf anchor 'pfverify' blocking uid=$NEW_UID"
pfctl -a "$ANCHOR" -s rules 2>/dev/null | sed 's/^/      /'

# 4) the test: that user should NO LONGER be able to reach the internet.
# Check by exit status, not parsed http_code — curl prints "000" AND exits non-zero
# on blocked connections, and combining those with `||` produces garbled output.
echo
echo "[4/4] testing: sudo -u $USER_NAME curl https://example.com  (should fail)"
if sudo -u "$USER_NAME" curl -fsS -m 7 -o /dev/null https://example.com/ 2>/dev/null; then
  echo "      → curl SUCCEEDED (pf did NOT block the connection)"
  echo
  echo "❌ FAIL — pf did not block the jailed uid."
  echo "   uid-based pf rules are unreliable on this macOS version."
  echo "   recommendation: fall back to the Docker-network jail backend."
  exit 1
else
  echo "      → curl failed as expected"
  echo
  echo "✅ PASS — macOS pf uid filtering WORKS on this machine."
  echo "   architecture green-lit: keyring-jail uid will be reliably gated."
  exit 0
fi
