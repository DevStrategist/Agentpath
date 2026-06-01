// The heart of option 1: an HTTP CONNECT proxy that gates by DESTINATION HOST.
// It never decrypts traffic — it sees only host:port from the CONNECT line, then allows or
// refuses the tunnel based on the task's grant (host allowlist), task status, and human approval.
const http = require('http');
const net = require('net');
const core = require('./core');
const ap = require('./approver');
const slack = require('./slack');

const TASK = process.env.KEYRING_TASK;
const TIMEOUT = parseInt(process.env.KEYRING_APPROVAL_TIMEOUT || '60000', 10);
const AUTO = process.env.KEYRING_AUTO_APPROVE === '1';
const PORT = parseInt(process.env.KEYRING_PROXY_PORT || '8080', 10);

function inferCli(host, headers = {}) {
  if (headers['x-keyring-cli']) return headers['x-keyring-cli'];
  return host === 'railway.com' || host.endsWith('.railway.com') ? 'railway' : undefined;
}

function refuse(sock, code, reason) {
  try { sock.write(`HTTP/1.1 ${code} ${reason}\r\n\r\n`); } catch (e) {}
  sock.destroy();
}

const server = http.createServer((req, res) => {
  res.writeHead(405, { 'content-type': 'text/plain' });
  res.end('KEYRING is a CONNECT proxy. Configure your agent: HTTPS_PROXY=http://host:' + PORT + '\n');
});

server.on('connect', async (req, clientSocket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr || '443', 10);
  const taskId = TASK;
  const cli = inferCli(host, req.headers);
  const accessRule = cli ? (core.getAccessRule(cli) || core.ensureAccessRule(cli)) : null;

  // 1) task-binding: task must be active (catches cancelled/expired even if previously approved)
  const task = core.getTask(taskId);
  if (!task || task.status !== 'active') {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'task_not_active' });
    return refuse(clientSocket, 403, 'Task Not Active');
  }
  // 2) grant integrity
  const grant = core.getGrant(taskId);
  if (!core.verifyGrant(grant)) {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'invalid_grant' });
    return refuse(clientSocket, 403, 'Invalid Grant');
  }
  // 3) scope: destination host must be in the grant's allowlist
  if (!core.hostAllowed(grant, host)) {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'host_not_in_scope' });
    return refuse(clientSocket, 403, 'Host Not In Scope');
  }
  if (accessRule && accessRule.proxy === 'denied') {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'railway_access_disabled', cli, accessDirect: accessRule.direct });
    return refuse(clientSocket, 403, 'Railway Access Disabled');
  }
  // 4) human approval. Most hosts cache per (task, host); Railway demo mode asks fresh
  // for every proxied connection so the human sees each CLI access attempt.
  const freshApproval = core.requiresFreshProxyApproval(accessRule);
  let appr = freshApproval ? null : ap.findApproval(taskId, host);
  if (appr && appr.status === 'denied') {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'approval_denied', approver: appr.approver });
    return refuse(clientSocket, 403, 'Denied By Human');
  }
  if (!appr || appr.status === 'pending') {
    const pending = appr || ap.createPending(taskId, host);

    // Build rich context once so Slack and stderr both have it.
    const recent = core.getAudit(taskId);
    const ctx = {
      cli,
      accessRule,
      freshApproval,
      invoker: process.env.SUDO_USER || process.env.USER || undefined,
      allowHosts: grant.allowHosts,
      recentApproved: recent.filter(e => e.decision === 'allowed').length,
      recentDenied: recent.filter(e => e.decision === 'denied').length,
      dashboardUrl: process.env.KEYRING_DASHBOARD_URL || undefined
    };

    // Fire Slack notification (best-effort) and persist the message id on the approval.
    slack.notify(pending, ctx).then(r => {
      if (r && r.ok) ap.attachSlackTarget(pending.id, r.channel, r.ts);
      else if (r && r.error && r.error !== 'slack_disabled') {
        process.stderr.write(`[KEYRING] slack notify failed: ${r.error}\n`);
      }
    }).catch(e => process.stderr.write(`[KEYRING] slack notify threw: ${e.message}\n`));

    process.stderr.write(`\n[KEYRING] approval needed: ${pending.id}  task=${taskId} host=${host}\n          approve:  keyring approve --id ${pending.id}\n`);
    if (AUTO) ap.resolve(pending.id, 'approved', 'auto');
    const result = await ap.waitFor(pending.id, TIMEOUT);

    // Whatever happens — denied, approved-elsewhere, timed-out — replace the Slack
    // message so the buttons can't be clicked again on a stale request.
    if (slack.isEnabled()) {
      const full = ap.getApproval(pending.id);
      const target = full && full.slack;
      if (target && target.channel && target.ts) {
        const status = result.status === 'approved' ? 'approved'
                     : result.status === 'denied'   ? 'denied'
                     : 'denied'; // timeout/other → visually denied
        const approver = result.approver || (result.status === 'timeout' ? 'timeout' : 'unknown');
        slack.update(target, pending, status, approver, ctx).catch(() => {});
      }
    }

    if (result.status !== 'approved') {
      core.addAudit({ taskId, host, decision: 'denied', reason: result.status === 'timeout' ? 'approval_timeout' : 'approval_denied', approver: result.approver });
      return refuse(clientSocket, 403, 'Not Approved');
    }
    appr = result;
  }
  // re-check task after the wait (it may have been cancelled while we waited)
  const t2 = core.getTask(taskId);
  if (!t2 || t2.status !== 'active') {
    core.addAudit({ taskId, host, decision: 'denied', reason: 'task_not_active' });
    return refuse(clientSocket, 403, 'Task Not Active');
  }

  // 5) open the tunnel — bytes are piped opaquely; KEYRING never sees inside TLS
  const upstream = net.connect(port, host, () => {
    core.addAudit({ taskId, host, decision: 'allowed', reason: 'approved', approver: appr.approver });
    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-agent: keyring\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on('error', () => refuse(clientSocket, 502, 'Upstream Error'));
  clientSocket.on('error', () => upstream.destroy());
});

server.listen(PORT, () => {
  process.stderr.write(`[KEYRING] policy egress proxy listening on :${PORT}  (enforcing task=${TASK})\n`);
  if (!process.env.SLACK_BOT_TOKEN) process.stderr.write(`[KEYRING] local approver mode (no SLACK_BOT_TOKEN). Approve with: keyring approve --id <id>\n`);
});
