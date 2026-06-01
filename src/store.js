// Tiny JSON-file state store (atomic-ish writes). No external deps.
const fs = require('fs');
const path = require('path');
// Default location: /var/lib/keyring/state.json (shared between all KEYRING processes
// regardless of which uid runs them). Falls back to ./.keyring-state.json if the shared
// dir doesn't exist (i.e. the user hasn't run `sudo keyring install` yet — keeps demos
// runnable without root).
const SHARED_STATE = '/var/lib/keyring/state.json';
function pickStatePath() {
  if (process.env.KEYRING_STATE) return process.env.KEYRING_STATE;
  try { fs.accessSync('/var/lib/keyring', fs.constants.W_OK); return SHARED_STATE; }
  catch (e) { return path.join(process.cwd(), '.keyring-state.json'); }
}
const STATE = pickStatePath();
function load() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); }
  catch (e) { return { tasks: {}, grants: {}, approvals: {}, audit: [], gatedClis: {}, accessRules: {} }; }
}
function save(s) {
  const tmp = STATE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
  fs.renameSync(tmp, STATE);
}
function update(fn) { const s = load(); const r = fn(s); save(s); return r; }
module.exports = { load, save, update, STATE };
