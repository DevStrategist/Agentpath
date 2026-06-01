// Minimal assertions for the moat: attenuation + task-binding + scope.
process.env.KEYRING_STATE = '/tmp/keyring-test-' + Date.now() + '.json';
const core = require('../src/core');
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

setTimeout(() => {
  ok('task expires by ttl', core.getTask('t2').status === 'expired');
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}, 30);
