#!/usr/bin/env bash
# Remove the KEYRING shim for a CLI binary and restore the original.
#
# Usage:
#   sudo KEYRING_STATE=/path/to/.keyring-state.json bash jail/uninstall-shim.sh <cli-name> [bin-path]
# If <bin-path> is omitted, we try to read it from KEYRING_STATE.

set -u
[[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash $0 $*"; exit 2; }

CLI_NAME="${1:?usage: $0 <cli-name> [bin-path]}"
BIN_PATH="${2:-}"
SUDOERS_FILE="/etc/sudoers.d/keyring-shim-${CLI_NAME}"

# infer bin path from state if not provided
if [[ -z "$BIN_PATH" ]]; then
  STATE="${KEYRING_STATE:-$(cd "$(dirname "$0")/.." && pwd)/.keyring-state.json}"
  if [[ -f "$STATE" ]]; then
    BIN_PATH=$(node -e "
      const s=JSON.parse(require('fs').readFileSync('$STATE','utf8'));
      const g=(s.gatedClis||{})['$CLI_NAME'];
      process.stdout.write(g && g.binPath ? g.binPath : '');
    " 2>/dev/null)
  fi
fi
[[ -n "$BIN_PATH" ]] || { echo "could not infer bin path. pass it as 2nd arg."; exit 1; }
REAL_PATH="${BIN_PATH}.keyring-real"

# sanity: shim looks like ours
if [[ -f "$BIN_PATH" ]] && ! head -1 "$BIN_PATH" 2>/dev/null | grep -q "KEYRING shim" \
   && ! head -3 "$BIN_PATH" 2>/dev/null | grep -q "KEYRING shim"; then
  echo "warning: $BIN_PATH doesn't look like a KEYRING shim. refusing to overwrite."
  echo "         (head -3 $BIN_PATH if you want to inspect.)"
  exit 1
fi
[[ -e "$REAL_PATH" ]] || { echo "no original binary at $REAL_PATH — nothing to restore."; exit 1; }

# atomic-ish: remove shim, restore real
rm -f "$BIN_PATH"
mv "$REAL_PATH" "$BIN_PATH"
chown root:wheel "$BIN_PATH" 2>/dev/null || true
chmod 755 "$BIN_PATH"
rm -f "$SUDOERS_FILE"

# update KEYRING state
STATE="${KEYRING_STATE:-$(cd "$(dirname "$0")/.." && pwd)/.keyring-state.json}"
if [[ -f "$STATE" ]]; then
  node -e "
    const fs=require('fs');
    const p='$STATE';
    const s=JSON.parse(fs.readFileSync(p,'utf8'));
    if (s.gatedClis && s.gatedClis['$CLI_NAME']) {
      s.gatedClis['$CLI_NAME'].enforcement = 'registered';
      delete s.gatedClis['$CLI_NAME'].realPath;
      delete s.gatedClis['$CLI_NAME'].shimmedAt;
      fs.writeFileSync(p, JSON.stringify(s, null, 2));
    }
  " 2>/dev/null
fi

echo "✅ $CLI_NAME shim removed."
echo "  $BIN_PATH restored from $REAL_PATH"
echo "  sudoers entry $SUDOERS_FILE removed"
echo
echo "the gate is still registered in KEYRING (enforcement: registered)."
echo "to fully unregister:  keyring gate remove --name $CLI_NAME"
