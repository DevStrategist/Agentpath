// Minimal assertions for the moat: attenuation + task-binding + scope.
process.env.KEYRING_STATE = '/tmp/keyring-test-' + Date.now() + '.json';
const core = require('../src/core');
const slack = require('../src/slack');
const invoker = require('../src/invoker');
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

setTimeout(() => {
  ok('task expires by ttl', core.getTask('t2').status === 'expired');
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}, 30);
