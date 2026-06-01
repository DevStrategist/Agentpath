// Audit + approval HTTP server, the Slack interactivity endpoint, and a tiny dashboard.
// Deploy this (e.g. Vercel/Fly/Render) so Slack can reach /api/slack/interactivity.
const http = require('http');
const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const core = require('./core');
const ap = require('./approver');
const slack = require('./slack');
const PORT = parseInt(process.env.PORT || process.env.KEYRING_SERVER_PORT || '3000', 10);
const HELPER = '/usr/local/libexec/keyring-helper';
const net = require('net');
const os = require('os');
const { spawn, spawnSync } = require('child_process');
const PROXY_PID_FILE = path.join(os.tmpdir(), 'keyring-proxy.pid');
const PROXY_LOG_FILE = path.join(os.tmpdir(), 'keyring-proxy.log');
const DEFAULT_PROXY_PORT = parseInt(process.env.KEYRING_PROXY_PORT || '8080', 10);
const DEFAULT_TASK = 'default';

function probePort(port) {
  return new Promise(resolve => {
    const s = net.createConnection({ host: '127.0.0.1', port, timeout: 500 });
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('error', () => { s.destroy(); resolve(false); });
    s.on('timeout', () => { s.destroy(); resolve(false); });
  });
}
function readPidFile() {
  try {
    const pid = parseInt(fs.readFileSync(PROXY_PID_FILE, 'utf8').trim(), 10);
    if (!pid) return null;
    process.kill(pid, 0); // signal 0 = check alive
    return pid;
  } catch (e) { return null; }
}
function killPid(pid) { try { process.kill(pid, 'SIGTERM'); return true; } catch (e) { return false; } }

// Returns the union of known hosts for all currently-gated CLIs.
function gatedHosts() {
  return core.defaultAllowHostsForGatedClis(core.listGates().map(g => g.name))
    // Strip wildcards (pf needs concrete hostnames for DNS resolution); fall back to
    // common subdomains where known.
    .flatMap(h => h.startsWith('*.') ? KNOWN_WILDCARD_EXPANSIONS[h] || [] : [h]);
}
// For wildcards like *.railway.com that can't be A-resolved as-is, expand to specific
// hostnames our gated CLIs actually hit. Curated per provider.
const KNOWN_WILDCARD_EXPANSIONS = {
  '*.railway.com': ['backboard.railway.com', 'containers.railway.com'],
  '*.amazonaws.com': ['ec2.amazonaws.com', 's3.amazonaws.com', 'sts.amazonaws.com'],
  '*.googleapis.com': ['compute.googleapis.com', 'iam.googleapis.com', 'storage.googleapis.com', 'cloudresourcemanager.googleapis.com'],
  '*.googleusercontent.com': [], // CDN; covered only if user adds concrete hosts
  '*.fly.dev': [], // user-specific
  '*.vercel.app': []
};

// Returns the set of concrete hostnames currently needed by some OTHER shimmed gate
// (i.e. hosts we must keep in the kernel block table even if 'excludeName' is being torn down).
function hostsStillNeededExcept(excludeName) {
  return new Set(
    core.listGates()
      .filter(g => g.name !== excludeName && g.enforcement === 'shimmed')
      .flatMap(g => core.defaultAllowHostsForGatedClis([g.name]))
      .flatMap(h => h.startsWith('*.') ? KNOWN_WILDCARD_EXPANSIONS[h] || [] : [h])
  );
}
function hostsFor(name) {
  return core.defaultAllowHostsForGatedClis([name])
    .flatMap(h => h.startsWith('*.') ? KNOWN_WILDCARD_EXPANSIONS[h] || [] : [h]);
}
function helper(...args) {
  const r = spawnSync('sudo', ['-n', HELPER, ...args], { encoding: 'utf8' });
  if (r.error) return { ok: false, error: 'helper_exec_failed' };
  if (r.status !== 0 && /a password is required/i.test(r.stderr || '')) return { ok: false, error: 'not_installed' };
  try { const j = JSON.parse((r.stdout || '').trim()); return j.ok ? { ok: true, data: j } : { ok: false, error: j.error || 'helper_error' }; }
  catch (e) { return { ok: false, error: 'helper_bad_output' }; }
}

function send(res, code, body, type) {
  res.writeHead(code, { 'content-type': type || 'application/json' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => r(d)); });
}

const server = http.createServer(async (req, res) => {
  const t0 = Date.now();
  const u = new URL(req.url, 'http://localhost');
  // Minimal access log so deployed instances can see traffic in `railway logs`.
  res.on('finish', () => process.stderr.write(`${new Date().toISOString()} ${req.method} ${u.pathname} → ${res.statusCode} (${Date.now() - t0}ms)\n`));
  if (req.method === 'GET' && u.pathname === '/') {
    return send(res, 200, fs.readFileSync(path.join(__dirname, '..', 'public', 'dashboard.html'), 'utf8'), 'text/html');
  }
  if (req.method === 'GET' && u.pathname === '/api/audit') {
    return send(res, 200, core.getAudit(u.searchParams.get('taskId') || undefined));
  }
  if (req.method === 'GET' && u.pathname === '/api/pending') {
    return send(res, 200, ap.listPending(u.searchParams.get('taskId') || undefined));
  }
  if (req.method === 'GET' && u.pathname === '/api/gates') {
    return send(res, 200, core.listGates());
  }
  if (req.method === 'GET' && u.pathname === '/api/discovered-clis') {
    const scanner = require('./scanner');
    const gates = Object.fromEntries(core.listGates().map(g => [g.name, g]));
    const found = scanner.scan().map(c => {
      const g = gates[c.name];
      return {
        name: c.name,
        path: c.path,
        source: c.source,
        gated: !!g,
        enforcement: g ? g.enforcement : null,
        configPaths: g ? g.configPaths : undefined
      };
    });
    return send(res, 200, {
      host: require('os').hostname(),
      scannedDirs: scanner.SCAN_DIRS,
      count: found.length,
      gatedCount: found.filter(f => f.gated).length,
      items: found
    });
  }
  if (req.method === 'POST' && u.pathname === '/api/gates') {
    const body = JSON.parse((await readBody(req)) || '{}');
    if (!body.name) return send(res, 400, { error: 'name_required' });
    try { return send(res, 200, core.addGate(body.name, { binPath: body.binPath || null })); }
    catch (e) { return send(res, 400, { error: e.message }); }
  }
  if (req.method === 'POST' && u.pathname.match(/^\/api\/gates\/[^/]+\/install$/)) {
    const name = decodeURIComponent(u.pathname.split('/')[3]);
    const g = core.getGate(name);
    if (!g) return send(res, 404, { error: 'gate_not_found' });
    if (!g.binPath) return send(res, 400, { error: 'gate_missing_bin_path' });
    const invoker = process.env.USER;
    const port = String(process.env.KEYRING_PROXY_PORT || '8080');
    const r = helper('shim-install', name, g.binPath, port, invoker);
    if (!r.ok) return send(res, 500, { error: r.error });
    core.updateGate(name, { enforcement: 'shimmed', realPath: r.data.real, shimmedAt: Date.now() });
    // Also add this CLI's known destination hosts to the pf block table so any process
    // (not just the shimmed binary) is blocked from reaching them except via the proxy.
    const hosts = core.defaultAllowHostsForGatedClis([name])
      .flatMap(h => h.startsWith('*.') ? KNOWN_WILDCARD_EXPANSIONS[h] || [] : [h]);
    const blockResults = hosts.map(h => {
      const rr = helper('add-host-block', h);
      return { host: h, ok: rr.ok, ips: rr.ok ? rr.data.ips : [], error: rr.error };
    });
    // Refresh the proxy's grant to include these hosts (so traffic isn't refused by host-not-in-scope)
    const allGatedHosts = gatedHosts();
    if (allGatedHosts.length) {
      let task = core.getTask(DEFAULT_TASK);
      if (!task || task.status !== 'active') task = core.createTask(DEFAULT_TASK);
      core.setGrant(DEFAULT_TASK, allGatedHosts);
    }
    return send(res, 200, { ...core.getGate(name), blockResults });
  }
  if (req.method === 'POST' && u.pathname.match(/^\/api\/gates\/[^/]+\/uninstall$/)) {
    const name = decodeURIComponent(u.pathname.split('/')[3]);
    const g = core.getGate(name);
    if (!g) return send(res, 404, { error: 'gate_not_found' });
    const r = helper('shim-uninstall', name, g.binPath);
    if (!r.ok) return send(res, 500, { error: r.error });
    core.updateGate(name, { enforcement: 'registered', realPath: null });
    // The gate just went from shimmed → registered, so its IPs should no longer be in
    // the block table unless another shimmed gate still needs them.
    const stillNeeded = hostsStillNeededExcept(name);  // computed AFTER the enforcement change
    const toUnblock = hostsFor(name).filter(h => !stillNeeded.has(h));
    const unblockResults = toUnblock.map(h => {
      const rr = helper('remove-host-block', h);
      return { host: h, ok: rr.ok, removed: rr.ok ? rr.data.removed : 0, error: rr.error };
    });
    return send(res, 200, { ...core.getGate(name), unblockResults });
  }
  if (req.method === 'GET' && u.pathname === '/api/proxy/health') {
    const status = helper('proxy-status');
    const listening = await probePort(DEFAULT_PROXY_PORT);
    const ipList = helper('list-host-blocks');
    return send(res, 200, {
      pid: status.ok ? status.data.pid : null,
      listening, port: DEFAULT_PROXY_PORT, task: DEFAULT_TASK,
      proxyUser: status.ok ? status.data.user : null,
      shimsExist: core.listGates().some(g => g.enforcement === 'shimmed'),
      blockedIpCount: ipList.ok ? (ipList.data.ips || []).length : 0,
      blockedIps: ipList.ok ? ipList.data.ips : []
    });
  }
  if (req.method === 'POST' && u.pathname === '/api/proxy/start') {
    // Ensure a default task + grant exist covering all currently-gated CLIs.
    let task = core.getTask(DEFAULT_TASK);
    if (!task || task.status !== 'active') task = core.createTask(DEFAULT_TASK);
    const hosts = gatedHosts();
    if (hosts.length) core.setGrant(DEFAULT_TASK, hosts);
    // Helper spawns the proxy as keyring-proxy uid (the ONLY uid pf permits to reach
    // gated destination IPs).
    const r = helper('proxy-start', DEFAULT_TASK, String(DEFAULT_PROXY_PORT));
    if (!r.ok) return send(res, 500, { error: r.error });
    // Also add the gated hosts to the pf block table so they're enforced at the kernel.
    const blockResults = [];
    for (const h of hosts) {
      const rr = helper('add-host-block', h);
      blockResults.push({ host: h, ok: rr.ok, ips: rr.ok ? (rr.data.ips || []) : [], error: rr.error });
    }
    // Wait for proxy to bind
    let listening = false;
    for (let i = 0; i < 12; i++) { await new Promise(r => setTimeout(r, 200)); if (await probePort(DEFAULT_PROXY_PORT)) { listening = true; break; } }
    return send(res, listening ? 200 : 500, {
      ok: listening, pid: r.data.pid, port: DEFAULT_PROXY_PORT, runningAs: r.data.running_as,
      grantedHosts: hosts, blockResults
    });
  }
  if (req.method === 'POST' && u.pathname === '/api/proxy/stop') {
    const r = helper('proxy-stop');
    return send(res, r.ok ? 200 : 500, r.ok ? r.data : { error: r.error });
  }
  if (req.method === 'POST' && u.pathname === '/api/proxy/refresh-blocks') {
    // Re-resolve all gated hostnames and update the pf table. Called periodically
    // by the server, and on-demand from the dashboard if CDN IPs rotated.
    const hosts = gatedHosts();
    const out = hosts.map(h => {
      const rr = helper('add-host-block', h);
      return { host: h, ok: rr.ok, ips: rr.ok ? rr.data.ips : [], error: rr.error };
    });
    return send(res, 200, { refreshed: out.length, hosts: out });
  }
  if (req.method === 'GET' && u.pathname === '/api/jail') {
    const r = helper('jail-status');
    return send(res, 200, r.ok ? { installed: true, ...r.data } : { installed: false, error: r.error });
  }
  if (req.method === 'POST' && u.pathname === '/api/jail/up') {
    const port = String(process.env.KEYRING_PROXY_PORT || '8080');
    const r = helper('jail-up', port);
    return send(res, r.ok ? 200 : 500, r.ok ? r.data : { error: r.error });
  }
  if (req.method === 'POST' && u.pathname === '/api/jail/down') {
    const r = helper('jail-down');
    return send(res, r.ok ? 200 : 500, r.ok ? r.data : { error: r.error });
  }
  if (req.method === 'DELETE' && u.pathname.startsWith('/api/gates/')) {
    const name = decodeURIComponent(u.pathname.slice('/api/gates/'.length));
    const g = core.getGate(name);
    if (g && g.enforcement === 'shimmed') {
      return send(res, 409, { error: 'shim_installed_uninstall_first', hint: `sudo bash jail/uninstall-shim.sh ${name}` });
    }
    try {
      const stillNeeded = hostsStillNeededExcept(name);
      const removed = core.removeGate(name);
      // Belt-and-suspenders cleanup: even if uninstall was called first (and already
      // unblocked), re-check here in case the gate was in 'registered' state with stale IPs.
      const toUnblock = hostsFor(name).filter(h => !stillNeeded.has(h));
      const unblockResults = toUnblock.map(h => {
        const rr = helper('remove-host-block', h);
        return { host: h, ok: rr.ok, removed: rr.ok ? rr.data.removed : 0 };
      });
      return send(res, 200, { ...removed, unblockResults });
    }
    catch (e) { return send(res, 404, { error: e.message }); }
  }
  if (req.method === 'POST' && (u.pathname === '/api/approve' || u.pathname === '/api/deny')) {
    const body = JSON.parse((await readBody(req)) || '{}');
    const status = u.pathname.endsWith('approve') ? 'approved' : 'denied';
    const before = ap.getApproval(body.id);
    const resolved = ap.resolve(body.id, status, body.approver || 'dashboard');
    // If the same approval was surfaced in Slack, update that message too so both UIs stay in sync.
    if (resolved && before && before.slack && slack.isEnabled()) {
      slack.update(before.slack, resolved, status, resolved.approver, {}).catch(() => {});
    }
    return send(res, 200, resolved);
  }
  if (req.method === 'POST' && u.pathname === '/api/slack/interactivity') {
    const raw = await readBody(req);
    const okSig = slack.verifySignature(raw, req.headers['x-slack-request-timestamp'], req.headers['x-slack-signature']);
    if (!okSig) return send(res, 401, { error: 'bad_signature' });
    const payload = JSON.parse(querystring.parse(raw).payload || '{}');
    const action = (payload.actions || [])[0] || {};
    const status = action.action_id === 'allow' ? 'approved' : 'denied';
    const who = '@' + ((payload.user && payload.user.username) || 'slack');
    const before = ap.getApproval(action.value);
    // If already resolved (race against dashboard), don't double-resolve — just acknowledge.
    if (before && before.status !== 'pending') {
      return send(res, 200, { text: `Already ${before.status} by ${before.approver}` });
    }
    const resolved = ap.resolve(action.value, status, who);
    // If this Railway instance doesn't know the approval (state isn't shared with the
    // local proxy yet), synthesize a minimal record so we can still acknowledge in Slack.
    const display = resolved || {
      id: action.value,
      taskId: payload.actions[0]?.value || 'unknown',
      host: '(state not shared with this server)'
    };
    const target = payload.response_url ? { responseUrl: payload.response_url } : (before && before.slack) || {};
    if (target.responseUrl || target.channel) {
      slack.update(target, display, status, who, {}).catch(e => process.stderr.write(`slack.update failed: ${e.message}\n`));
    }
    return send(res, 200, ''); // empty 200 is the Slack convention when we'll update via response_url
  }
  send(res, 404, { error: 'not_found' });
});
server.listen(PORT, () => process.stderr.write(`[KEYRING] dashboard + approval server on :${PORT}\n`));

// Periodically re-resolve gated hostnames and refresh the pf block table. Catches
// CDN IP rotations. Quiet on success; logs failures to stderr.
const REFRESH_INTERVAL_MS = parseInt(process.env.KEYRING_BLOCK_REFRESH_MS || '300000', 10); // 5 min
setInterval(() => {
  const hosts = gatedHosts();
  if (!hosts.length) return;
  let updated = 0;
  for (const h of hosts) {
    const r = helper('add-host-block', h);
    if (r.ok) updated++;
    else process.stderr.write(`[KEYRING] refresh-blocks: ${h} → ${r.error}\n`);
  }
  if (updated) process.stderr.write(`[KEYRING] refresh-blocks: ${updated}/${hosts.length} hosts re-resolved\n`);
}, REFRESH_INTERVAL_MS).unref();
