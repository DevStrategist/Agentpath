// Discovers CLI tools installed on this machine by walking common bin dirs.
// Cheap (~stat once per file) — no caching needed for a few hundred entries.
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();

// Allowed-prefix list (user-installed tooling, not core OS) keeps the scan
// focused on things you'd actually want to gate. Adding /usr/bin or /bin
// floods the list with POSIX standard tools that don't make network calls.
const SCAN_DIRS = [
  '/opt/homebrew/bin',
  '/usr/local/bin',
  path.join(HOME, '.cargo/bin'),
  path.join(HOME, '.local/bin'),
  path.join(HOME, '.deno/bin'),
  path.join(HOME, '.bun/bin'),
  path.join(HOME, '.volta/bin'),
  path.join(HOME, '.pyenv/shims')
];

// Drop the few non-network shells that commonly land in Homebrew prefixes —
// gating these would only confuse users.
const NEVER_INTERESTING = new Set([
  'bash', 'sh', 'zsh', 'fish', 'dash', 'tcsh', 'ksh',
  'tmux', 'screen', 'less', 'more', 'nano', 'vi', 'vim', 'nvim', 'emacs', 'ed',
  'cat', 'ls', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'pwd', 'echo', 'touch',
  'man', 'info', 'env', 'true', 'false', 'tee', 'cut', 'sort', 'uniq', 'wc',
  'grep', 'egrep', 'fgrep', 'find', 'xargs', 'awk', 'sed', 'date',
  'chmod', 'chown', 'chgrp', 'stat', 'file', 'which', 'whereis',
  'tar', 'gzip', 'gunzip', 'zip', 'unzip', 'bzip2', 'xz', 'zstd'
]);

function scan() {
  const out = [];
  for (const dir of SCAN_DIRS) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { continue; }                                  // dir doesn't exist
    for (const e of entries) {
      if (!e.isFile() && !e.isSymbolicLink()) continue;
      if (e.name.startsWith('.')) continue;
      if (NEVER_INTERESTING.has(e.name)) continue;
      const full = path.join(dir, e.name);
      let stat;
      try { stat = fs.statSync(full); }                      // follows symlinks
      catch (err) { continue; }
      if (!stat.isFile()) continue;
      if (!(stat.mode & 0o111)) continue;                    // not executable
      if (e.name.endsWith('.keyring-real')) continue;        // hide our own moved-aside binaries
      out.push({ name: e.name, path: full, source: dir });
    }
  }
  // Dedupe by name — many tools install to multiple prefixes; first one wins.
  const seen = new Map();
  for (const c of out) {
    if (!seen.has(c.name)) seen.set(c.name, c);
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { scan, SCAN_DIRS };
