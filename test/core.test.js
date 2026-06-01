// Minimal assertions for the moat: attenuation + task-binding + scope.
process.env.KEYRING_STATE = '/tmp/keyring-test-' + Date.now() + '.json';
const fs = require('fs');
const path = require('path');
const core = require('../src/core');
const slack = require('../src/slack');
const invoker = require('../src/invoker');
const env = require('../src/env');
let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log('  PASS', name); } else { fail++; console.log('  FAIL', name); } };

core.createTask('t1');
core.setGrant('t1', ['*.railway.com', 'api.openai.com']);
const g = core.getGrant('t1');

ok('grant verifies', core.verifyGrant(g));
ok('tamper detected', (() => { const bad = { ...g, allowHosts: [...g.allowHosts, 'evil.com'] }; return !core.verifyGrant(bad); })());

ok('allowed: concrete under wildcard', core.hostAllowed(g, 'backboard.railway.com'));
ok('allowed: exact host', core.hostAllowed(g, 'api.openai.com'));
ok('denied: host not in scope', !core.hostAllowed(g, 'api.github.com'));

// attenuation
ok('narrow ok (subset)', (() => { try { core.deriveGrant('t1', ['backboard.railway.com']); return true; } catch (e) { return false; } })());
core.setGrant('t1', ['*.railway.com']); // reset parent
ok('widen blocked', (() => { try { core.deriveGrant('t1', ['*.com']); return false; } catch (e) { return e.message === 'scope_widen_blocked'; } })());
ok('widen blocked (new host)', (() => { try { core.deriveGrant('t1', ['evil.com']); return false; } catch (e) { return e.message === 'scope_widen_blocked'; } })());

// task-binding
core.cancelTask('t1');
ok('task reads cancelled', core.getTask('t1').status === 'cancelled');

core.createTask('t2', 0.001); // ~1ms ttl

// --- gated CLIs ---
ok('gate add records cli', (() => {
  const g = core.addGate('railway', { binPath: '/opt/homebrew/bin/railway' });
  return g.name === 'railway' && g.binPath === '/opt/homebrew/bin/railway' && g.enforcement === 'registered';
})());
ok('gate list returns added', core.listGates().some(g => g.name === 'railway'));
ok('gate show returns one', core.getGate('railway')?.name === 'railway');
ok('gate add duplicate throws', (() => {
  try { core.addGate('railway', { binPath: '/x' }); return false; }
  catch (e) { return e.message === 'gate_already_exists'; }
})());
ok('gate update merges patch', (() => {
  core.updateGate('railway', { enforcement: 'shimmed', realPath: '/opt/homebrew/bin/railway.keyring-real' });
  const g = core.getGate('railway');
  return g.enforcement === 'shimmed' && g.realPath.endsWith('.keyring-real');
})());
ok('gate remove deletes', (() => {
  core.removeGate('railway');
  return !core.getGate('railway');
})());
ok('gate remove missing throws', (() => {
  try { core.removeGate('not-a-thing'); return false; }
  catch (e) { return e.message === 'gate_not_found'; }
})());

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
ok('access rule can be set to simulated mode', (() => {
  const rule = core.setAccessRule('railway', { enforcement: 'simulated', direct: 'blocked', by: 'unit', source: 'test' });
  return rule.enforcement === 'simulated' && rule.direct === 'blocked';
})());
ok('slack access blocks include block and unblock actions', (() => {
  const blocks = slack.accessRuleBlocks({ cli: 'railway', direct: 'blocked', enforcement: 'real' }, { dashboardUrl: 'http://localhost:3000' });
  const actions = blocks.flatMap(b => b.elements || []).map(e => e.action_id).filter(Boolean);
  return actions.includes('access_block') && actions.includes('access_unblock');
})());
ok('slack access blocks explain approval prompt choices in require mode', (() => {
  const blocks = slack.accessRuleBlocks(
    { cli: 'railway', direct: 'blocked', proxy: 'requires_approval', enforcement: 'real' },
    { dashboardUrl: 'https://keyring.example' }
  );
  const body = JSON.stringify(blocks);
  return body.includes('Next Railway proxy use will ask') &&
    body.includes('Allow for 10 mins') &&
    body.includes('Allow forever') &&
    body.includes('Deny');
})());
ok('slack access blocks include signed proxy control links', (() => {
  const blocks = slack.accessRuleBlocks(
    { cli: 'railway', direct: 'blocked', proxy: 'requires_approval', enforcement: 'real' },
    { dashboardUrl: 'https://keyring.example' }
  );
  const body = JSON.stringify(blocks);
  return body.includes('/api/slack/decision') &&
    body.includes('Require approval') &&
    body.includes('Block KEYRING Railway') &&
    body.includes('Allow forever');
})());
ok('slack proxy control links carry the current rule version', (() => {
  const blocks = slack.accessRuleBlocks(
    { cli: 'railway', direct: 'blocked', proxy: 'requires_approval', enforcement: 'real', updatedAt: 12345 },
    { dashboardUrl: 'https://keyring.example' }
  );
  return JSON.stringify(blocks).includes('version=12345');
})());
ok('slack decision tokens verify only for the signed rule version', (() => {
  const token = slack.signDecision('railway', 'allow_forever', '12345');
  return slack.verifyDecisionToken('railway', 'allow_forever', token, '12345') &&
    !slack.verifyDecisionToken('railway', 'allow_forever', token, '67890') &&
    !slack.verifyDecisionToken('railway', 'allow_forever', token);
})());
ok('blocked access rule is visible to proxy checks', (() => {
  core.setAccessRule('railway', { direct: 'blocked', by: 'unit', source: 'test' });
  const rule = core.getAccessRule('railway');
  return rule.direct === 'blocked' && rule.proxy === 'requires_approval';
})());
ok('proxy access can be denied and audited', (() => {
  const before = core.getAudit().length;
  const rule = core.setAccessRule('railway', { proxy: 'denied', by: 'unit', source: 'test' });
  const audit = core.getAudit().slice(before);
  return rule.proxy === 'denied' &&
    audit.some(e => e.reason === 'proxy_access_denied' && e.cli === 'railway' && e.decision === 'denied');
})());
ok('proxy access can be returned to approval mode', (() => {
  const rule = core.setAccessRule('railway', { proxy: 'requires_approval', by: 'unit', source: 'test' });
  const latest = core.getAudit().slice(-1)[0];
  return rule.proxy === 'requires_approval' &&
    latest.reason === 'proxy_access_requires_approval';
})());
ok('temporary proxy grant is active until expiry', (() => {
  const rule = core.grantProxyAccess('railway', { durationMs: 600000, by: 'slack-user', source: 'unit' });
  return rule.proxy === 'allowed' &&
    rule.proxyGrant.exp > Date.now() &&
    core.proxyGrantActive(rule);
})());
ok('forever proxy grant has no expiry', (() => {
  const rule = core.grantProxyAccess('railway', { durationMs: null, by: 'slack-user', source: 'unit' });
  return rule.proxy === 'allowed' &&
    rule.proxyGrant.exp === null &&
    core.proxyGrantActive(rule);
})());
ok('expired proxy grant is inactive', (() => {
  const rule = core.grantProxyAccess('railway', { durationMs: 1, by: 'slack-user', source: 'unit' });
  return !core.proxyGrantActive(rule, Date.now() + 10);
})());
ok('denying future proxy approvals blocks KEYRING path', (() => {
  const rule = core.denyProxyGrant('railway', { by: 'slack-user', source: 'unit' });
  const latest = core.getAudit().slice(-1)[0];
  return rule.proxy === 'denied' &&
    rule.proxyGrant === null &&
    latest.reason === 'proxy_access_denied';
})());
ok('slack approval blocks use signed links instead of interactive actions', (() => {
  const blocks = slack.approvalBlocks(
    { id: 'ap_test', taskId: 't', host: 'backboard.railway.com' },
    { cli: 'railway', dashboardUrl: 'https://keyring.example' }
  );
  const body = JSON.stringify(blocks);
  return body.includes('/api/slack/decision') &&
    body.includes('Allow for 10 mins') &&
    body.includes('Allow forever') &&
    !body.includes('"action_id":"allow_10m"');
})());
ok('slack proxy use blocks use a signed deny-future link', (() => {
  const blocks = slack.proxyUseBlocks(
    { cli: 'railway', proxy: 'allowed', direct: 'blocked' },
    { host: 'backboard.railway.com', taskId: 'default', dashboardUrl: 'https://keyring.example' }
  );
  const body = JSON.stringify(blocks);
  return body.includes('/api/slack/decision') &&
    body.includes('Deny future approvals') &&
    !body.includes('"action_id":"deny_future"');
})());
ok('slack decision tokens verify only for the signed decision', (() => {
  const token = slack.signDecision('ap_test', 'allow_10m');
  return slack.verifyDecisionToken('ap_test', 'allow_10m', token) &&
    !slack.verifyDecisionToken('ap_test', 'deny', token);
})());
ok('slack decision handler rejects missing pending approval before granting', (() => {
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  const staleCheck = serverSource.indexOf('if (id && !before)');
  const grant = serverSource.indexOf('core.grantProxyAccess((before && before.cli) || cli');
  return staleCheck >= 0 && grant >= 0 && staleCheck < grant;
})());
ok('slack decision handler requires a current version for cli allow links', (() => {
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  return serverSource.includes('version !== String(currentRule.updatedAt)') &&
    serverSource.includes('stale Slack control link');
})());
ok('slack decision GET renders confirmation without mutating state', (() => {
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  return serverSource.includes('Confirm KEYRING Slack decision') &&
    serverSource.includes("if (req.method === 'POST' && u.pathname === '/api/slack/decision')") &&
    !serverSource.includes("if (req.method === 'GET' && u.pathname === '/api/slack/decision') {\n    const decision = u.searchParams.get('decision')");
})());
ok('install wrapper resolves invoking user when sudo env is missing', (() => {
  const user = invoker.resolveInvokingUser({ USER: 'root', LOGNAME: 'root' }, () => 'axiom');
  return user === 'axiom';
})());
ok('install wrapper skips nested sudo when already root', (() => {
  const invocation = invoker.bootstrapInvocation('/tmp/bootstrap.sh', 'axiom', true);
  return invocation.cmd === 'bash' &&
    invocation.args[0] === '/tmp/bootstrap.sh' &&
    invocation.env.SUDO_USER === 'axiom';
})());
ok('helper syncs successful CLI auth config changes back to invoking user', (() => {
  const helper = fs.readFileSync(path.join(__dirname, '..', 'bin', 'keyring-helper'), 'utf8');
  return helper.includes('sync_back_configs') &&
    helper.includes('config-sync-back') &&
    helper.includes('cp -R "$src" "$dst"');
})());
ok('helper does not delete real auth config when temp config is absent', (() => {
  const helper = fs.readFileSync(path.join(__dirname, '..', 'bin', 'keyring-helper'), 'utf8');
  return !helper.includes('elif [[ -e "$dst" ]]');
})());
ok('helper preserves railway auth config when sandbox only writes notices', (() => {
  const helper = fs.readFileSync(path.join(__dirname, '..', 'bin', 'keyring-helper'), 'utf8');
  return helper.includes('preserve_railway_auth_config') &&
    helper.includes('auth_like_config "$dst/config.json"') &&
    helper.includes('! auth_like_config "$src/config.json"');
})());
ok('keyring run preflights denied proxy state before launching real cli', (() => {
  const cliSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'cli.js'), 'utf8');
  return cliSource.includes('railway_access_disabled_preflight') &&
    cliSource.includes("accessRule.proxy === 'denied'");
})());
ok('keyring run asks Slack before launching railway when approval is required', (() => {
  const cliSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'cli.js'), 'utf8');
  const preflight = cliSource.indexOf('await ensureRailwayProxyApproval');
  const launch = cliSource.indexOf("'run',\n        invoker, configPaths");
  return preflight >= 0 &&
    cliSource.includes('KEYRING waiting for Slack approval before launching railway') &&
    launch >= 0 &&
    preflight < launch;
})());
ok('proxy waits long enough for Slack confirmation flow', (() => {
  const proxySource = fs.readFileSync(path.join(__dirname, '..', 'src', 'proxy.js'), 'utf8');
  return proxySource.includes("KEYRING_APPROVAL_TIMEOUT || '300000'");
})());
ok('env parser reads simple dotenv keys without comments', (() => {
  const parsed = env.parseDotEnv('SLACK_BOT_TOKEN=xoxb-test\n# comment\nSLACK_APPROVAL_CHANNEL=C123\nEMPTY=\n');
  return parsed.SLACK_BOT_TOKEN === 'xoxb-test' &&
    parsed.SLACK_APPROVAL_CHANNEL === 'C123' &&
    parsed.EMPTY === '';
})());
ok('env parser strips matching quotes', (() => {
  const parsed = env.parseDotEnv("KEYRING_DASHBOARD_URL=\"https://example.com\"\nSLACK_SIGNING_SECRET='abc'\n");
  return parsed.KEYRING_DASHBOARD_URL === 'https://example.com' &&
    parsed.SLACK_SIGNING_SECRET === 'abc';
})());
ok('env path resolution tolerates inaccessible cwd', (() => {
  return env.defaultDotEnvPath(() => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); }) === null;
})());

setTimeout(() => {
  ok('task expires by ttl', core.getTask('t2').status === 'expired');
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}, 30);
