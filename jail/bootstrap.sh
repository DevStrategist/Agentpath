#!/usr/bin/env bash
# KEYRING one-time bootstrap. After this runs, KEYRING can manage the jail and
# install/uninstall binary shims with NO further sudo prompts.
#
# Installs:
#   /usr/local/libexec/keyring-helper          — the privileged single entry point
#   /etc/sudoers.d/keyring                      — NOPASSWD entry for SUDO_USER → helper
#   /etc/pf.anchors/keyring                     — empty stub (rules added by `jail-up`)
#   /etc/pf.keyring.conf                        — loader for the anchor
#   user/group "keyring-jail"                   — the jail uid
#
# Usage:
#   sudo bash jail/bootstrap.sh
# To remove everything:
#   keyring uninstall      (which invokes the helper's self-uninstall verb)

set -u
[[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash $0"; exit 2; }
[[ "$(uname)" == "Darwin" ]] || { echo "macOS only — use jail.sh on Linux"; exit 2; }

INVOKING_USER="${SUDO_USER:-${USER:-}}"
[[ -n "$INVOKING_USER" && "$INVOKING_USER" != "root" ]] || {
  echo "couldn't determine the invoking user. set SUDO_USER explicitly:"
  echo "  sudo SUDO_USER=\$USER bash $0"
  exit 1
}
id "$INVOKING_USER" >/dev/null 2>&1 || { echo "user '$INVOKING_USER' not found"; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_HELPER="$REPO_DIR/bin/keyring-helper"
DST_HELPER="/usr/local/libexec/keyring-helper"
SUDOERS_FILE="/etc/sudoers.d/keyring"
JAIL_USER="keyring-jail"
JAIL_GROUP="keyring-jail"

echo "==> KEYRING bootstrap"
echo "    invoking user: $INVOKING_USER"
echo "    repo:          $REPO_DIR"

# 1) install helper
[[ -f "$SRC_HELPER" ]] || { echo "helper not found at $SRC_HELPER"; exit 1; }
mkdir -p /usr/local/libexec
install -m 0755 -o root -g wheel "$SRC_HELPER" "$DST_HELPER"
echo "    installed:     $DST_HELPER"

# 2) write sudoers entry (NOPASSWD, scoped to this user + exactly this helper path)
TMP_SUDOERS=$(mktemp)
cat > "$TMP_SUDOERS" <<EOF
# Installed by KEYRING bootstrap. Lets '$INVOKING_USER' invoke the keyring helper
# as root without a password prompt. Helper validates all inputs and only touches
# KEYRING-owned files. Remove via: keyring uninstall
$INVOKING_USER ALL=(root) NOPASSWD: $DST_HELPER
EOF
chmod 440 "$TMP_SUDOERS"
if ! visudo -c -f "$TMP_SUDOERS" >/dev/null; then
  rm -f "$TMP_SUDOERS"
  echo "sudoers entry failed validation — aborting."; exit 1
fi
mv "$TMP_SUDOERS" "$SUDOERS_FILE"
echo "    installed:     $SUDOERS_FILE  ($INVOKING_USER → $DST_HELPER)"

# 3) create the jail user/group via the helper itself (single source of truth)
"$DST_HELPER" jail-status >/dev/null    # also creates the log file with right perms

if ! id "$JAIL_USER" >/dev/null 2>&1; then
  # ensure_user is normally called as part of jail-up; we run it standalone here so
  # the system is ready even if the user never calls jail-up.
  NEXT_UID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1)
  NEW_UID=$(( NEXT_UID + 1 ))
  NEXT_GID=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | tail -1)
  NEW_GID=$(( NEXT_GID + 1 ))
  dscl . -create "/Groups/$JAIL_GROUP" >/dev/null
  dscl . -create "/Groups/$JAIL_GROUP" PrimaryGroupID "$NEW_GID" >/dev/null
  dscl . -create "/Groups/$JAIL_GROUP" RealName "KEYRING jailed processes" >/dev/null
  dscl . -create "/Users/$JAIL_USER" >/dev/null
  dscl . -create "/Users/$JAIL_USER" UserShell /bin/sh >/dev/null
  dscl . -create "/Users/$JAIL_USER" RealName "KEYRING jail" >/dev/null
  dscl . -create "/Users/$JAIL_USER" UniqueID "$NEW_UID" >/dev/null
  dscl . -create "/Users/$JAIL_USER" PrimaryGroupID "$NEW_GID" >/dev/null
  dscl . -create "/Users/$JAIL_USER" NFSHomeDirectory /var/empty >/dev/null
  echo "    created user:  $JAIL_USER (uid=$NEW_UID gid=$NEW_GID)"
else
  echo "    user exists:   $JAIL_USER"
fi

# 4) pre-create log file so the helper can write
touch /var/log/keyring-helper.log
chmod 644 /var/log/keyring-helper.log

# 5) put `keyring` on PATH via a symlink in /usr/local/bin (already in sudo secure_path).
#    Idempotent. Refuses to overwrite a foreign `keyring` (e.g. Python's keyring tool).
SRC_CLI="$REPO_DIR/bin/keyring"
DST_CLI="/usr/local/bin/keyring"
mkdir -p /usr/local/bin
SYMLINK_NOTE=""
if [[ -L "$DST_CLI" ]]; then
  current=$(readlink "$DST_CLI")
  if [[ "$current" == "$SRC_CLI" ]]; then
    SYMLINK_NOTE="symlink:     $DST_CLI → $SRC_CLI (already correct)"
  else
    ln -sf "$SRC_CLI" "$DST_CLI"
    SYMLINK_NOTE="symlink:     $DST_CLI → $SRC_CLI (replaced previous: $current)"
  fi
elif [[ -e "$DST_CLI" ]]; then
  SYMLINK_NOTE="⚠️  $DST_CLI exists and is NOT a KEYRING symlink — left alone.
                  invoke as: $SRC_CLI  (or move the conflicting binary)"
else
  ln -s "$SRC_CLI" "$DST_CLI"
  SYMLINK_NOTE="symlink:     $DST_CLI → $SRC_CLI"
fi
echo "    $SYMLINK_NOTE"

# 6) Bundle the code to /usr/local/lib/keyring so keyring-proxy uid can read it
#    without needing traversal access to the user's home (macOS Sonoma TCC protects
#    /Users/<name> from ACL grants, so the helper can't open up traversal there).
install -d -m 755 -o root -g wheel /usr/local/lib/keyring
install -d -m 755 -o root -g wheel /usr/local/lib/keyring/bin
install -d -m 755 -o root -g wheel /usr/local/lib/keyring/src
install -d -m 755 -o root -g wheel /usr/local/lib/keyring/public
install -m 755 -o root -g wheel "$REPO_DIR/bin/keyring" /usr/local/lib/keyring/bin/keyring
for f in "$REPO_DIR/src"/*.js; do
  install -m 644 -o root -g wheel "$f" "/usr/local/lib/keyring/src/$(basename "$f")"
done
[[ -f "$REPO_DIR/public/dashboard.html" ]] && install -m 644 -o root -g wheel "$REPO_DIR/public/dashboard.html" /usr/local/lib/keyring/public/dashboard.html
echo "    bundled:     /usr/local/lib/keyring/ (so keyring-proxy uid can load the proxy)"

# 7) Shared state dir — both axiom (CLI/dashboard) and keyring-proxy (egress proxy)
#    need r/w access to the same state file. /var/lib/keyring with sticky-world-write
#    is the simplest path for a single-user mac demo; for a multi-user deployment
#    use a shared group instead.
install -d -m 777 /var/lib/keyring   # not sticky — both axiom and keyring-proxy
                                      # need to rename/replace files in here
echo "    state dir:   /var/lib/keyring (777, shared between axiom + keyring-proxy)"
# Migrate any pre-existing state from the repo dir on first install
if [[ -f "$REPO_DIR/.keyring-state.json" && ! -f /var/lib/keyring/state.json ]]; then
  cp "$REPO_DIR/.keyring-state.json" /var/lib/keyring/state.json
  echo "    migrated:    $REPO_DIR/.keyring-state.json → /var/lib/keyring/state.json"
fi
touch /var/lib/keyring/state.json 2>/dev/null
chmod 666 /var/lib/keyring/state.json 2>/dev/null || true
chown "${INVOKING_USER}:staff" /var/lib/keyring/state.json 2>/dev/null || true

echo
echo "✅ KEYRING installed."
echo
echo "from now on, $INVOKING_USER can run privileged KEYRING operations without"
echo "a password prompt. \`keyring\` is on PATH (via $DST_CLI)."
echo
echo "test it:"
echo "  keyring jail status                # no prompt"
echo
echo "bring the jail up (pf actively gates the keyring-jail uid):"
echo "  keyring jail up"
echo
echo "gate a CLI:"
echo "  keyring gate add --name railway"
echo "  keyring gate install --name railway"
echo
echo "remove everything later:"
echo "  keyring uninstall"
