# Railway Access Control Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit Railway direct-access block/unblock controls that work through CLI, dashboard, Slack, proxy checks, and tests.

**Architecture:** Keep the existing real macOS shim and `pf` enforcement as the real blocking backend. Add a small access-rule layer in `core.js`; have CLI, server, Slack, and proxy consume that shared state so the demo has one understandable Railway rule. Keep simulated mode as state and test coverage only; the existing safe `npm run demo` remains deterministic.

**Tech Stack:** Node.js CommonJS modules, built-in `http`/`https`, shell helper scripts, macOS `pf`, existing JSON state store.

---

### Task 1: Access Rule Core

**Files:**
- Modify: `src/store.js`
- Modify: `src/core.js`
- Modify: `test/core.test.js`

- [ ] **Step 1: Write failing tests**

Add tests to `test/core.test.js` after the gated CLI tests:

```js
ok('access rule defaults to blocked railway real mode', (() => {
  const rule = core.ensureAccessRule('railway');
  return rule.cli === 'railway' &&
    rule.enforcement === 'real' &&
    rule.direct === 'blocked' &&
    rule.proxy === 'requires_approval';
})());
ok('access unblock records actor and audit', (() => {
  const before = core.getAudit().length;
  const rule = core.setAccessRule('railway', { direct: 'unblocked', by: 'test-user', source: 'unit' });
  const audit = core.getAudit().slice(before);
  return rule.direct === 'unblocked' &&
    rule.lastChangedBy === 'test-user' &&
    audit.some(e => e.reason === 'direct_access_unblocked' && e.cli === 'railway');
})());
ok('access block records actor and audit', (() => {
  const rule = core.setAccessRule('railway', { direct: 'blocked', by: 'test-user', source: 'unit' });
  const latest = core.getAudit().slice(-1)[0];
  return rule.direct === 'blocked' &&
    latest.reason === 'direct_access_blocked' &&
    latest.decision === 'blocked';
})());
ok('access rule rejects invalid direct state', (() => {
  try { core.setAccessRule('railway', { direct: 'open' }); return false; }
  catch (e) { return e.message === 'invalid_direct_access_state'; }
})());
```

- [ ] **Step 2: Run tests to verify RED**

Run: `npm test`

Expected: fail because `core.ensureAccessRule` is not defined.

- [ ] **Step 3: Implement access-rule state**

In `src/store.js`, add `accessRules: {}` to the default state returned by `load()`.

In `src/core.js`, add:

```js
const VALID_DIRECT = new Set(['blocked', 'unblocked']);
const VALID_PROXY = new Set(['requires_approval', 'allowed', 'denied']);

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
```

Export `ensureAccessRule`, `getAccessRule`, `listAccessRules`, and `setAccessRule`.

- [ ] **Step 4: Run tests to verify GREEN**

Run: `npm test`

Expected: all tests pass.

### Task 2: CLI Access Commands

**Files:**
- Modify: `src/cli.js`
- Modify: `test/core.test.js`

- [ ] **Step 1: Write failing tests**

Add lightweight command-shape coverage to `test/core.test.js`:

```js
ok('access rule can be set to simulated mode', (() => {
  const rule = core.setAccessRule('railway', { enforcement: 'simulated', direct: 'blocked', by: 'unit', source: 'test' });
  return rule.enforcement === 'simulated' && rule.direct === 'blocked';
})());
```

- [ ] **Step 2: Run tests to verify RED or existing GREEN**

Run: `npm test`

Expected: pass if Task 1 already supports `enforcement`; otherwise fail until Task 1 is complete.

- [ ] **Step 3: Implement CLI commands**

In `src/cli.js`, add an `access` case before `gate`:

```js
case 'access': {
  const cli = flags.cli || flags.name || 'railway';
  if (sub === 'show') {
    ok(core.getAccessRule(cli) || core.ensureAccessRule(cli));
  } else if (sub === 'list') {
    ok(core.listAccessRules());
  } else if (sub === 'block') {
    ok(core.setAccessRule(cli, { direct: 'blocked', by: flags.by || process.env.USER || 'cli', source: 'cli' }));
  } else if (sub === 'unblock') {
    ok(core.setAccessRule(cli, { direct: 'unblocked', by: flags.by || process.env.USER || 'cli', source: 'cli' }));
  } else if (sub === 'mode') {
    if (!flags.enforcement || !['real', 'simulated'].includes(flags.enforcement)) die('usage: keyring access mode --cli railway --enforcement real|simulated');
    ok(core.setAccessRule(cli, { enforcement: flags.enforcement, by: flags.by || process.env.USER || 'cli', source: 'cli' }));
  } else {
    die('usage: keyring access show|list|block|unblock|mode --cli <name>');
  }
  break;
}
```

Update help text to include:

```text
access controls:
  access show --cli railway              show one access rule
  access list                            list access rules
  access block --cli railway             block direct CLI egress
  access unblock --cli railway           unblock direct CLI egress
  access mode --cli railway --enforcement real|simulated
```

- [ ] **Step 4: Verify CLI manually**

Run:

```bash
KEYRING_STATE=/tmp/keyring-cli-access.json node bin/keyring access block --cli railway --by tester
KEYRING_STATE=/tmp/keyring-cli-access.json node bin/keyring access show --cli railway
KEYRING_STATE=/tmp/keyring-cli-access.json node bin/keyring access unblock --cli railway --by tester
```

Expected: JSON shows `direct` as `blocked`, then `unblocked`.

### Task 3: Server, Dashboard, and Slack Rule Controls

**Files:**
- Modify: `src/server.js`
- Modify: `src/slack.js`
- Modify: `public/dashboard.html`

- [ ] **Step 1: Write failing Slack tests**

Add to `test/core.test.js`:

```js
const slack = require('../src/slack');
ok('slack access blocks include block and unblock actions', (() => {
  const blocks = slack.accessRuleBlocks({ cli: 'railway', direct: 'blocked', enforcement: 'real' }, { dashboardUrl: 'http://localhost:3000' });
  const actions = blocks.flatMap(b => b.elements || []).map(e => e.action_id).filter(Boolean);
  return actions.includes('access_block') && actions.includes('access_unblock');
})());
```

- [ ] **Step 2: Run tests to verify RED**

Run: `npm test`

Expected: fail because `slack.accessRuleBlocks` is not defined.

- [ ] **Step 3: Add Slack block builders**

In `src/slack.js`, add `accessRuleBlocks(rule, ctx = {})` and `notifyAccessRule(rule, ctx = {})`. Blocks include a header, current `direct` state, enforcement mode, optional dashboard link, and two buttons with action IDs `access_block` and `access_unblock` whose value is the CLI name.

Export both functions.

- [ ] **Step 4: Add server access endpoints**

In `src/server.js`, add:

```js
if (req.method === 'GET' && u.pathname === '/api/access-rules') {
  return send(res, 200, core.listAccessRules());
}
if (req.method === 'GET' && u.pathname.match(/^\/api\/access-rules\/[^/]+$/)) {
  const name = decodeURIComponent(u.pathname.split('/')[3]);
  return send(res, 200, core.getAccessRule(name) || core.ensureAccessRule(name));
}
if (req.method === 'POST' && u.pathname.match(/^\/api\/access-rules\/[^/]+\/(block|unblock)$/)) {
  const parts = u.pathname.split('/');
  const name = decodeURIComponent(parts[3]);
  const action = parts[4];
  const body = JSON.parse((await readBody(req)) || '{}');
  const rule = core.setAccessRule(name, {
    direct: action === 'block' ? 'blocked' : 'unblocked',
    by: body.by || 'dashboard',
    source: body.source || 'dashboard'
  });
  return send(res, 200, rule);
}
if (req.method === 'POST' && u.pathname.match(/^\/api\/access-rules\/[^/]+\/notify$/)) {
  const name = decodeURIComponent(u.pathname.split('/')[3]);
  const rule = core.getAccessRule(name) || core.ensureAccessRule(name);
  const r = await slack.notifyAccessRule(rule, { dashboardUrl: process.env.KEYRING_DASHBOARD_URL || undefined });
  return send(res, r.ok ? 200 : 500, r.ok ? r : { error: r.error });
}
```

In Slack interactivity handling, recognize `access_block` and `access_unblock`, update the access rule with `source: 'slack'`, and update the Slack message using `response_url`.

- [ ] **Step 5: Add dashboard display**

In `public/dashboard.html`, add a Railway Access Control card that fetches `/api/access-rules/railway`, renders direct state, enforcement mode, and buttons for block/unblock plus "Notify Slack". Use existing button styles and `banner()`.

- [ ] **Step 6: Run tests**

Run: `npm test`

Expected: all tests pass.

### Task 4: Proxy and Demo Verification

**Files:**
- Modify: `src/proxy.js`
- Modify: `package.json`
- Create: `demo/run-railway-demo-preflight.sh`

- [ ] **Step 1: Write failing proxy-related test**

Add to `test/core.test.js`:

```js
ok('blocked access rule is visible to proxy checks', (() => {
  core.setAccessRule('railway', { direct: 'blocked', by: 'unit', source: 'test' });
  const rule = core.getAccessRule('railway');
  return rule.direct === 'blocked' && rule.proxy === 'requires_approval';
})());
```

- [ ] **Step 2: Run tests**

Run: `npm test`

Expected: pass after Task 1; this anchors the proxy-facing API.

- [ ] **Step 3: Add proxy context**

In `src/proxy.js`, identify the CLI from `x-keyring-cli` or infer `railway` when the host matches a Railway allow pattern. Include access-rule state in Slack context and audit denied proxy requests as `railway_access_disabled` only if the rule has `proxy: 'denied'`. Do not deny normal approved proxy requests just because `direct` is `blocked`; that is the expected demo state.

- [ ] **Step 4: Add real demo preflight script**

Create `demo/run-railway-demo-preflight.sh` that checks:

```bash
command -v railway
command -v keyring || test -x ./bin/keyring
node -e "require('./src/core').ensureAccessRule('railway'); console.log('access rule ok')"
node bin/keyring slack status
node bin/keyring access show --cli railway
```

The script prints next-step guidance and does not install shims or mutate `pf`.

- [ ] **Step 5: Add package script**

In `package.json`, add:

```json
"demo:railway:preflight": "bash demo/run-railway-demo-preflight.sh"
```

- [ ] **Step 6: Final verification**

Run:

```bash
npm test
npm run demo
npm run demo:railway:preflight
```

Expected: tests pass, safe demo passes, preflight either passes or stops with clear actionable missing dependency output.
