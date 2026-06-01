// Grants, tasks, host-scope, attenuation, task-binding, audit.
const crypto = require('crypto');
const { load, update } = require('./store');
const SECRET = process.env.KEYRING_SIGNING_SECRET || 'dev-insecure-secret';
const now = () => Date.now();
const VALID_DIRECT = new Set(['blocked', 'unblocked']);
const VALID_PROXY = new Set(['requires_approval', 'allowed', 'denied']);

function sign(g) {
  return crypto.createHmac('sha256', SECRET)
    .update(JSON.stringify({ grantId: g.grantId, taskId: g.taskId, allowHosts: g.allowHosts, exp: g.exp }))
    .digest('hex');
}

// --- tasks ---
function createTask(id, ttlSec) {
  return update(s => {
    s.tasks[id] = { id, status: 'active', createdAt: now(), exp: ttlSec ? now() + ttlSec * 1000 : null };
    return s.tasks[id];
  });
}
function cancelTask(id) {
  return update(s => { if (s.tasks[id]) s.tasks[id].status = 'cancelled'; return s.tasks[id]; });
}
function getTask(id) {
  const t = load().tasks[id];
  if (t && t.status === 'active' && t.exp && now() > t.exp) return { ...t, status: 'expired' };
  return t;
}

// --- host pattern coverage (no TLS decryption needed; host comes from SNI/CONNECT) ---
function coveredBy(parent, child) {
  if (parent === child) return true;
  if (parent.startsWith('*.')) {
    const base = parent.slice(2);          // railway.com
    const suf = parent.slice(1);           // .railway.com
    if (child === base) return true;
    if (child.endsWith(suf)) return true;  // concrete host under the wildcard
  }
  return false;
}
function hostAllowed(grant, host) { return !!grant && grant.allowHosts.some(p => coveredBy(p, host)); }
function isSubset(parentHosts, childHosts) {
  return childHosts.every(c => parentHosts.some(p => coveredBy(p, c)));
}

// --- grants ---
function setGrant(taskId, allowHosts, exp) {
  return update(s => {
    const g = { grantId: 'g_' + crypto.randomBytes(4).toString('hex'), taskId, allowHosts, parentGrantId: null, exp: exp || null };
    g.sig = sign(g);
    s.grants[taskId] = g;
    return g;
  });
}
function deriveGrant(taskId, childHosts) {
  return update(s => {
    const parent = s.grants[taskId];
    if (!parent) throw new Error('no_parent_grant');
    if (!isSubset(parent.allowHosts, childHosts)) throw new Error('scope_widen_blocked');
    const g = { grantId: 'g_' + crypto.randomBytes(4).toString('hex'), taskId, allowHosts: childHosts, parentGrantId: parent.grantId, exp: parent.exp };
    g.sig = sign(g);
    s.grants[taskId] = g;
    return g;
  });
}
function getGrant(taskId) { return load().grants[taskId]; }
function verifyGrant(g) {
  if (!g) return false;
  if (sign(g) !== g.sig) return false;          // tamper check
  if (g.exp && now() > g.exp) return false;     // expiry
  return true;
}

// --- gated CLIs (per-binary universal mode: every invocation must go via KEYRING) ---
// Sensible per-CLI defaults for what config dirs the agent needs read-access to.
// Used when --config-paths isn't specified at `gate add` time.
const DEFAULT_CONFIG_PATHS = {
  railway: ['.railway'],
  gh:      ['.config/gh'],
  aws:     ['.aws'],
  gcloud:  ['.config/gcloud'],
  doctl:   ['.config/doctl'],
  fly:     ['.fly'],
  heroku:  ['.netrc'],
  vercel:  ['.local/share/com.vercel.cli', '.vercel']
};

// Known network destinations per CLI. Used when the dashboard auto-creates a
// default grant covering whatever the user has currently gated, so the proxy
// will actually permit the traffic those CLIs need.
const DEFAULT_ALLOW_HOSTS = {
  railway: ['*.railway.com'],
  gh:      ['api.github.com', 'objects.githubusercontent.com', 'codeload.github.com'],
  aws:     ['*.amazonaws.com'],
  gcloud:  ['*.googleapis.com', '*.googleusercontent.com'],
  doctl:   ['api.digitalocean.com'],
  fly:     ['api.fly.io', '*.fly.dev'],
  heroku:  ['api.heroku.com'],
  vercel:  ['api.vercel.com', '*.vercel.app'],
  netlify: ['api.netlify.com'],
  stripe:  ['api.stripe.com'],
  npm:     ['registry.npmjs.org']
};
function defaultAllowHostsForGatedClis(gatedNames) {
  const out = new Set();
  for (const n of gatedNames) {
    for (const h of (DEFAULT_ALLOW_HOSTS[n] || [])) out.add(h);
  }
  return [...out];
}
function addGate(name, opts = {}) {
  return update(s => {
    if (!s.gatedClis) s.gatedClis = {};
    if (s.gatedClis[name]) throw new Error('gate_already_exists');
    s.gatedClis[name] = {
      name,
      binPath: opts.binPath || null,
      realPath: opts.realPath || null,
      configPaths: opts.configPaths || DEFAULT_CONFIG_PATHS[name] || [],
      enforcement: opts.enforcement || 'registered',
      addedAt: now()
    };
    return s.gatedClis[name];
  });
}
function listGates() {
  const g = load().gatedClis || {};
  return Object.values(g);
}
function getGate(name) {
  return (load().gatedClis || {})[name];
}
function removeGate(name) {
  return update(s => {
    if (!s.gatedClis || !s.gatedClis[name]) throw new Error('gate_not_found');
    const removed = s.gatedClis[name];
    delete s.gatedClis[name];
    return removed;
  });
}
function updateGate(name, patch) {
  return update(s => {
    if (!s.gatedClis || !s.gatedClis[name]) throw new Error('gate_not_found');
    Object.assign(s.gatedClis[name], patch);
    return s.gatedClis[name];
  });
}

// --- access rules (demo-friendly controls for direct CLI egress) ---
function ensureAccessRule(cli, opts = {}) {
  return update(s => {
    if (!s.accessRules) s.accessRules = {};
    if (!s.accessRules[cli]) {
      s.accessRules[cli] = {
        cli,
        enforcement: opts.enforcement || 'real',
        direct: opts.direct || 'blocked',
        proxy: opts.proxy || 'requires_approval',
        hosts: opts.hosts || defaultAllowHostsForGatedClis([cli]),
        lastChangedBy: opts.by || 'system',
        lastChangedSource: opts.source || 'system',
        updatedAt: now()
      };
    }
    return s.accessRules[cli];
  });
}
function getAccessRule(cli) {
  return (load().accessRules || {})[cli] || null;
}
function listAccessRules() {
  return Object.values(load().accessRules || {});
}
function setAccessRule(cli, patch = {}) {
  if (patch.direct && !VALID_DIRECT.has(patch.direct)) throw new Error('invalid_direct_access_state');
  if (patch.proxy && !VALID_PROXY.has(patch.proxy)) throw new Error('invalid_proxy_access_state');
  return update(s => {
    if (!s.accessRules) s.accessRules = {};
    const prev = s.accessRules[cli] || {
      cli,
      enforcement: 'real',
      direct: 'blocked',
      proxy: 'requires_approval',
      hosts: defaultAllowHostsForGatedClis([cli])
    };
    const next = {
      ...prev,
      enforcement: patch.enforcement || prev.enforcement,
      direct: patch.direct || prev.direct,
      proxy: patch.proxy || prev.proxy,
      hosts: patch.hosts || prev.hosts,
      lastChangedBy: patch.by || 'unknown',
      lastChangedSource: patch.source || 'unknown',
      updatedAt: now()
    };
    s.accessRules[cli] = next;
    if (!s.audit) s.audit = [];
    if (patch.direct && patch.direct !== prev.direct) {
      s.audit.push({
        ts: Date.now(),
        taskId: patch.taskId || null,
        host: null,
        cli,
        decision: patch.direct === 'blocked' ? 'blocked' : 'unblocked',
        reason: patch.direct === 'blocked' ? 'direct_access_blocked' : 'direct_access_unblocked',
        approver: patch.by || 'unknown',
        source: patch.source || 'unknown'
      });
      if (s.audit.length > 500) s.audit = s.audit.slice(-500);
    }
    return next;
  });
}

// --- audit ---
function addAudit(ev) {
  return update(s => {
    s.audit.push({ ts: Date.now(), ...ev });
    if (s.audit.length > 500) s.audit = s.audit.slice(-500);
    return ev;
  });
}
function getAudit(taskId) {
  const a = load().audit;
  return taskId ? a.filter(e => e.taskId === taskId) : a;
}

module.exports = {
  createTask, cancelTask, getTask,
  setGrant, deriveGrant, getGrant, verifyGrant,
  hostAllowed, isSubset, coveredBy,
  addGate, listGates, getGate, removeGate, updateGate,
  defaultAllowHostsForGatedClis,
  ensureAccessRule, getAccessRule, listAccessRules, setAccessRule,
  addAudit, getAudit
};
