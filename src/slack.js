// Slack adapter — Block Kit approval messages with full context, lifecycle updates,
// transient-error retry, and a built-in test command. No SDK; uses built-in https.
//
// If SLACK_BOT_TOKEN is unset, notify() / update() are no-ops and KEYRING falls back
// to the local CLI/dashboard approver.
const https = require('https');
const crypto = require('crypto');

const SLACK_API = 'slack.com';

function decisionSecret() {
  return process.env.KEYRING_LINK_SECRET ||
    process.env.SLACK_SIGNING_SECRET ||
    process.env.KEYRING_SIGNING_SECRET ||
    'dev-insecure-secret';
}
function signDecision(subject, decision, version) {
  const signed = [subject, decision];
  if (version !== undefined && version !== null && version !== '') signed.push(String(version));
  return crypto.createHmac('sha256', decisionSecret())
    .update(signed.join(':'))
    .digest('hex');
}
function verifyDecisionToken(subject, decision, token, version) {
  if (!subject || !decision || !token) return false;
  const expected = signDecision(subject, decision, version);
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token)); }
  catch (e) { return false; }
}
function decisionLink(dashboardUrl, params) {
  if (!dashboardUrl) return null;
  const base = dashboardUrl.replace(/\/+$/, '');
  const subject = params.id || params.cli;
  const token = signDecision(subject, params.decision, params.version);
  const q = new URLSearchParams({ decision: params.decision, token });
  if (params.id) q.set('id', params.id);
  if (params.cli) q.set('cli', params.cli);
  if (params.version !== undefined && params.version !== null) q.set('version', String(params.version));
  return `${base}/api/slack/decision?${q.toString()}`;
}

function approvalLinksText(pending, ctx = {}) {
  const allow10 = decisionLink(ctx.dashboardUrl, { id: pending.id, decision: 'allow_10m' });
  const allowForever = decisionLink(ctx.dashboardUrl, { id: pending.id, decision: 'allow_forever' });
  const deny = decisionLink(ctx.dashboardUrl, { id: pending.id, decision: 'deny' });
  if (!allow10 || !allowForever || !deny) {
    return 'Approval links unavailable. Set `KEYRING_DASHBOARD_URL` to the current public KEYRING URL.';
  }
  return `<${allow10}|Allow for 10 mins>   ·   <${allowForever}|Allow forever>   ·   <${deny}|Deny>`;
}

// --- Block Kit composition ---

// ctx is { cli, invoker, allowHosts, recentApproved, recentDenied, taskAgeMs, dashboardUrl }
// All fields optional — message degrades gracefully if absent.
function approvalBlocks(pending, ctx = {}) {
  const cli = ctx.cli ? `\`${ctx.cli}\`` : 'an agent';
  const allow = (ctx.allowHosts && ctx.allowHosts.length)
    ? ctx.allowHosts.map(h => `\`${h}\``).join(', ')
    : '(no scope set)';
  const recentLine = (ctx.recentApproved || ctx.recentDenied)
    ? `Recent in this task: ${ctx.recentApproved || 0} allowed · ${ctx.recentDenied || 0} denied`
    : 'No prior activity for this task';
  const invoker = ctx.invoker ? `\`${ctx.invoker}\`` : 'unknown user';

  const elements = [
    { type: 'mrkdwn', text: `*Task* \`${pending.taskId}\` · *Host* \`${pending.host}\`` },
    { type: 'mrkdwn', text: `*Scope* ${allow}` },
    { type: 'mrkdwn', text: `*Invoked by* ${invoker} · *via* ${cli}` },
    { type: 'mrkdwn', text: recentLine }
  ];
  if (ctx.accessRule) {
    elements.push({ type: 'mrkdwn', text: `*Direct ${ctx.accessRule.cli} access* \`${ctx.accessRule.direct}\` · *Proxy* \`${ctx.accessRule.proxy}\`` });
  }
  if (ctx.dashboardUrl) {
    elements.push({ type: 'mrkdwn', text: `<${ctx.dashboardUrl}|Open dashboard>` });
  }

  return [
    { type: 'header', text: { type: 'plain_text', text: '🔑 KEYRING approval requested' } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `KEYRING is holding a connection from ${cli} to *${pending.host}* (task *${pending.taskId}*). Choose how long Railway may use the KEYRING proxy.` } },
    { type: 'context', elements },
    { type: 'section', text: { type: 'mrkdwn', text: approvalLinksText(pending, ctx) } }
  ];
}

// Replaces the actions block with a static resolved-by line. Called after resolve.
function resolvedBlocks(pending, status, approver, ctx = {}) {
  const icon = status === 'approved' ? '✅' : '⛔';
  const word = status === 'approved' ? 'Allowed' : 'Denied';
  const cli = ctx.cli ? `\`${ctx.cli}\`` : 'agent';
  return [
    { type: 'header', text: { type: 'plain_text', text: `${icon} KEYRING — ${word}` } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `${word} ${cli} → *${pending.host}* (task *${pending.taskId}*).` } },
    { type: 'context', elements: [
      { type: 'mrkdwn', text: `${icon} ${word} by *${approver || 'unknown'}* · ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC` }
    ]}
  ];
}

function accessRuleBlocks(rule, ctx = {}) {
  const direct = rule.direct === 'blocked' ? 'blocked' : 'unblocked';
  const icon = direct === 'blocked' ? '⛔' : '✅';
  const mode = rule.enforcement || 'real';
  const changedBy = rule.lastChangedBy ? `Last changed by \`${rule.lastChangedBy}\`` : 'No changes recorded yet';
  const cli = rule.cli || 'railway';
  const elements = [
    { type: 'mrkdwn', text: `*CLI* \`${cli}\` · *Direct access* \`${direct}\`` },
    { type: 'mrkdwn', text: `*Enforcement* \`${mode}\` · *Proxy* \`${rule.proxy || 'requires_approval'}\`` },
    { type: 'mrkdwn', text: changedBy }
  ];
  if (ctx.dashboardUrl) {
    elements.push({ type: 'mrkdwn', text: `<${ctx.dashboardUrl}|Open dashboard>` });
  }
  const proxy = rule.proxy || 'requires_approval';
  const version = rule.updatedAt !== undefined && rule.updatedAt !== null ? String(rule.updatedAt) : undefined;
  const requireApproval = decisionLink(ctx.dashboardUrl, { cli, decision: 'require_approval', version });
  const allowForever = decisionLink(ctx.dashboardUrl, { cli, decision: 'allow_forever', version });
  const blockProxy = decisionLink(ctx.dashboardUrl, { cli, decision: 'deny_future', version });
  const proxyControls = requireApproval && allowForever && blockProxy
    ? `<${requireApproval}|Require approval>   ·   <${allowForever}|Allow forever>   ·   <${blockProxy}|Block KEYRING Railway>`
    : 'Proxy control links unavailable. Set `KEYRING_DASHBOARD_URL`.';
  const nextPrompt = proxy === 'requires_approval'
    ? 'Next Railway proxy use will ask in Slack: *Allow for 10 mins* · *Allow forever* · *Deny*.'
    : proxy === 'allowed'
      ? 'Railway proxy is currently allowed. Each monitored use will notify Slack with a deny-future link.'
      : 'Railway proxy is blocked. Use Require approval before running the protected demo path.';
  return [
    { type: 'header', text: { type: 'plain_text', text: `${icon} KEYRING Railway access` } },
    { type: 'section', text: { type: 'mrkdwn',
      text: direct === 'blocked'
        ? `Direct \`${rule.cli}\` network access is *blocked*. The agent must use KEYRING as the proxy.`
        : `Direct \`${rule.cli}\` network access is *unblocked*. Block it before running the protected demo path.` } },
    { type: 'context', elements },
    { type: 'section', text: { type: 'mrkdwn', text: nextPrompt } },
    { type: 'section', text: { type: 'mrkdwn', text: proxyControls } },
    { type: 'actions', elements: [
      { type: 'button', style: 'danger', text: { type: 'plain_text', text: 'Block Direct Railway' }, action_id: 'access_block', value: rule.cli },
      { type: 'button', style: 'primary', text: { type: 'plain_text', text: 'Unblock Direct Railway' }, action_id: 'access_unblock', value: rule.cli }
    ]}
  ];
}

function formatGrant(rule) {
  if (!rule || !rule.proxyGrant) return 'forever';
  if (!rule.proxyGrant.exp) return 'forever';
  const ms = rule.proxyGrant.exp - Date.now();
  if (ms <= 0) return 'expired';
  const mins = Math.max(1, Math.ceil(ms / 60000));
  return `${mins} min${mins === 1 ? '' : 's'}`;
}

function proxyUseBlocks(rule, ctx = {}) {
  const cli = rule && rule.cli ? rule.cli : (ctx.cli || 'cli');
  const host = ctx.host || 'unknown host';
  const task = ctx.taskId || 'unknown';
  const grant = formatGrant(rule);
  const elements = [
    { type: 'mrkdwn', text: `*CLI* \`${cli}\` · *Host* \`${host}\`` },
    { type: 'mrkdwn', text: `*Task* \`${task}\` · *Grant* \`${grant}\`` }
  ];
  if (ctx.invoker) elements.push({ type: 'mrkdwn', text: `*Invoked by* \`${ctx.invoker}\`` });
  if (ctx.dashboardUrl) elements.push({ type: 'mrkdwn', text: `<${ctx.dashboardUrl}|Open dashboard>` });
  const version = rule && rule.updatedAt !== undefined && rule.updatedAt !== null ? String(rule.updatedAt) : undefined;
  const denyFuture = decisionLink(ctx.dashboardUrl, { cli, decision: 'deny_future', version });
  return [
    { type: 'header', text: { type: 'plain_text', text: '🔔 KEYRING Railway proxy used' } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `A monitored \`${cli}\` connection is going through KEYRING.` } },
    { type: 'context', elements },
    { type: 'section', text: { type: 'mrkdwn',
      text: denyFuture ? `<${denyFuture}|Deny future approvals>` : 'Deny link unavailable. Set `KEYRING_DASHBOARD_URL`.' } }
  ];
}

function proxyControlUrls(rule, ctx = {}) {
  const cli = rule && rule.cli ? rule.cli : (ctx.cli || 'railway');
  const version = rule && rule.updatedAt !== undefined && rule.updatedAt !== null ? String(rule.updatedAt) : undefined;
  return {
    allow10: decisionLink(ctx.dashboardUrl, { cli, decision: 'allow_10m', version }),
    allowForever: decisionLink(ctx.dashboardUrl, { cli, decision: 'allow_forever', version }),
    requireApproval: decisionLink(ctx.dashboardUrl, { cli, decision: 'require_approval', version })
  };
}

function proxyControlButton(text, url, actionId, style) {
  if (!url) return null;
  const button = {
    type: 'button',
    text: { type: 'plain_text', text },
    url,
    action_id: actionId
  };
  if (style) button.style = style;
  return button;
}

function proxyUseDeniedBlocks(rule, actor, ctx = {}) {
  const cli = rule && rule.cli ? rule.cli : (ctx.cli || 'cli');
  const host = ctx.host || 'future Railway connections';
  const urls = proxyControlUrls(rule, ctx);
  const buttons = [
    proxyControlButton('Allow for 10 mins', urls.allow10, 'proxy_link_allow_10m', 'primary'),
    proxyControlButton('Allow forever', urls.allowForever, 'proxy_link_allow_forever'),
    proxyControlButton('Require approval', urls.requireApproval, 'proxy_link_require_approval')
  ].filter(Boolean);
  return [
    { type: 'header', text: { type: 'plain_text', text: '⛔ KEYRING Railway access disabled' } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `Future \`${cli}\` proxy connections are now denied.` } },
    { type: 'context', elements: [
      { type: 'mrkdwn', text: `Changed by *${actor || 'unknown'}* · last host \`${host}\`` }
    ]},
    buttons.length
      ? { type: 'actions', elements: buttons }
      : { type: 'section', text: { type: 'mrkdwn', text: 'Allow links unavailable. Set `KEYRING_DASHBOARD_URL`.' } }
  ];
}

function proxyDeniedBlocks(rule, ctx = {}) {
  const cli = rule && rule.cli ? rule.cli : (ctx.cli || 'cli');
  const argv = Array.isArray(ctx.argv) && ctx.argv.length ? ` \`${ctx.argv.join(' ')}\`` : '';
  const elements = [
    { type: 'mrkdwn', text: `*CLI* \`${cli}\` · *Proxy* \`${(rule && rule.proxy) || 'denied'}\`` }
  ];
  if (ctx.invoker) elements.push({ type: 'mrkdwn', text: `*Invoked by* \`${ctx.invoker}\`` });
  if (ctx.dashboardUrl) elements.push({ type: 'mrkdwn', text: `<${ctx.dashboardUrl}|Open dashboard>` });
  const urls = proxyControlUrls(rule, ctx);
  const buttons = [
    proxyControlButton('Allow for 10 mins', urls.allow10, 'proxy_link_allow_10m', 'primary'),
    proxyControlButton('Allow forever', urls.allowForever, 'proxy_link_allow_forever'),
    proxyControlButton('Require approval', urls.requireApproval, 'proxy_link_require_approval')
  ].filter(Boolean);
  return [
    { type: 'header', text: { type: 'plain_text', text: '⛔ KEYRING Railway command blocked' } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `A \`${cli}\` command was blocked because KEYRING proxy access is denied.${argv}` } },
    { type: 'context', elements },
    buttons.length
      ? { type: 'actions', elements: buttons }
      : { type: 'section', text: { type: 'mrkdwn', text: 'Allow links unavailable. Set `KEYRING_DASHBOARD_URL`.' } }
  ];
}

// Plain-text fallback for notification previews. Slack uses `text:` when blocks
// can't render (mobile, accessibility, push, etc.).
function fallbackText(pending, ctx = {}) {
  const cli = ctx.cli ? ` (${ctx.cli})` : '';
  return `KEYRING approval needed${cli}: allow agent to reach ${pending.host} for task ${pending.taskId}?`;
}

// --- HTTP plumbing ---

function postJson(pathStr, payload) {
  const token = process.env.SLACK_BOT_TOKEN;
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: SLACK_API, path: pathStr, method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': 'Bearer ' + token,
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d || '{}') }); }
        catch (e) { resolve({ status: res.statusCode, body: { raw: d, parseError: e.message } }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Same as postJson but to an arbitrary URL (used for Slack's response_url callbacks).
function postUrl(urlStr, payload) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'POST', port: u.port || 443,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Transient errors: network failures, 5xx, Slack 'fatal_error'/'service_unavailable'.
// One retry after 500ms is enough for typical Slack hiccups.
async function withRetry(fn) {
  try {
    const r = await fn();
    if (r.status >= 500 || (r.body && (r.body.error === 'fatal_error' || r.body.error === 'service_unavailable'))) {
      await new Promise(rs => setTimeout(rs, 500));
      return await fn();
    }
    return r;
  } catch (e) {
    await new Promise(rs => setTimeout(rs, 500));
    return await fn();
  }
}

// --- Public API ---

function isEnabled() { return !!process.env.SLACK_BOT_TOKEN; }

// Returns { ok, channel, ts, error }. ts/channel needed for later update().
async function notify(pending, ctx = {}) {
  if (!isEnabled()) return { ok: false, error: 'slack_disabled' };
  const channel = process.env.SLACK_APPROVAL_CHANNEL;
  if (!channel) return { ok: false, error: 'channel_unset' };
  const r = await withRetry(() => postJson('/api/chat.postMessage', {
    channel,
    text: fallbackText(pending, ctx),
    blocks: approvalBlocks(pending, ctx)
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true, channel: r.body.channel, ts: r.body.ts };
}

async function notifyAccessRule(rule, ctx = {}) {
  if (!isEnabled()) return { ok: false, error: 'slack_disabled' };
  const channel = process.env.SLACK_APPROVAL_CHANNEL;
  if (!channel) return { ok: false, error: 'channel_unset' };
  const r = await withRetry(() => postJson('/api/chat.postMessage', {
    channel,
    text: `KEYRING ${rule.cli} direct access is ${rule.direct}`,
    blocks: accessRuleBlocks(rule, ctx)
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true, channel: r.body.channel, ts: r.body.ts };
}

async function notifyProxyUse(rule, ctx = {}) {
  if (!isEnabled()) return { ok: false, error: 'slack_disabled' };
  const channel = process.env.SLACK_APPROVAL_CHANNEL;
  if (!channel) return { ok: false, error: 'channel_unset' };
  const r = await withRetry(() => postJson('/api/chat.postMessage', {
    channel,
    text: `KEYRING ${rule.cli} proxy used for ${ctx.host || 'unknown host'}`,
    blocks: proxyUseBlocks(rule, ctx)
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true, channel: r.body.channel, ts: r.body.ts };
}

async function notifyProxyDenied(rule, ctx = {}) {
  if (!isEnabled()) return { ok: false, error: 'slack_disabled' };
  const channel = process.env.SLACK_APPROVAL_CHANNEL;
  if (!channel) return { ok: false, error: 'channel_unset' };
  const r = await withRetry(() => postJson('/api/chat.postMessage', {
    channel,
    text: `KEYRING blocked ${rule.cli} because proxy access is denied`,
    blocks: proxyDeniedBlocks(rule, ctx)
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true, channel: r.body.channel, ts: r.body.ts };
}

// Edits the approval message to remove buttons and show the outcome.
// Pass either { channel, ts } (chat.update path) or { responseUrl } (faster, no auth needed —
// Slack gives us this on interactivity callbacks).
async function update(target, pending, status, approver, ctx = {}) {
  if (!isEnabled() && !target.responseUrl) return { ok: false, error: 'slack_disabled' };
  const payload = {
    text: `${status === 'approved' ? '✅ Allowed' : '⛔ Denied'} ${pending.host} for ${pending.taskId} by ${approver || 'unknown'}`,
    blocks: resolvedBlocks(pending, status, approver, ctx),
    replace_original: true
  };
  if (target.responseUrl) {
    const r = await postUrl(target.responseUrl, payload).catch(e => ({ status: 0, body: e.message }));
    return { ok: r.status === 200, error: r.status !== 200 ? ('response_url_' + r.status) : undefined };
  }
  const r = await withRetry(() => postJson('/api/chat.update', {
    channel: target.channel, ts: target.ts,
    text: payload.text, blocks: payload.blocks
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true };
}

async function updateAccessRule(target, rule, actor, ctx = {}) {
  if (!isEnabled() && !target.responseUrl) return { ok: false, error: 'slack_disabled' };
  const payload = {
    text: `KEYRING ${rule.cli} direct access is ${rule.direct} by ${actor || 'unknown'}`,
    blocks: accessRuleBlocks(rule, { ...ctx, actor }),
    replace_original: true
  };
  if (target.responseUrl) {
    const r = await postUrl(target.responseUrl, payload).catch(e => ({ status: 0, body: e.message }));
    return { ok: r.status === 200, error: r.status !== 200 ? ('response_url_' + r.status) : undefined };
  }
  const r = await withRetry(() => postJson('/api/chat.update', {
    channel: target.channel, ts: target.ts,
    text: payload.text, blocks: payload.blocks
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true };
}

async function updateProxyUseDenied(target, rule, actor, ctx = {}) {
  if (!isEnabled() && !target.responseUrl) return { ok: false, error: 'slack_disabled' };
  const payload = {
    text: `KEYRING ${rule.cli} proxy access denied for future approvals by ${actor || 'unknown'}`,
    blocks: proxyUseDeniedBlocks(rule, actor, ctx),
    replace_original: true
  };
  if (target.responseUrl) {
    const r = await postUrl(target.responseUrl, payload).catch(e => ({ status: 0, body: e.message }));
    return { ok: r.status === 200, error: r.status !== 200 ? ('response_url_' + r.status) : undefined };
  }
  const r = await withRetry(() => postJson('/api/chat.update', {
    channel: target.channel, ts: target.ts,
    text: payload.text, blocks: payload.blocks
  }));
  if (!r.body || !r.body.ok) return { ok: false, error: (r.body && r.body.error) || 'http_' + r.status };
  return { ok: true };
}

// Send a sample approval message to confirm wiring. Returns the same shape as notify().
async function test() {
  if (!isEnabled()) return { ok: false, error: 'SLACK_BOT_TOKEN not set' };
  if (!process.env.SLACK_APPROVAL_CHANNEL) return { ok: false, error: 'SLACK_APPROVAL_CHANNEL not set' };
  return notify(
    { id: 'ap_test_' + Math.floor(Date.now() / 1000), taskId: 'keyring-slack-test', host: 'example.com' },
    {
      cli: 'keyring',
      invoker: process.env.USER || 'unknown',
      allowHosts: ['example.com'],
      recentApproved: 0,
      recentDenied: 0
    }
  );
}

function verifySignature(rawBody, timestamp, signature) {
  const secret = process.env.SLACK_SIGNING_SECRET;
  if (!secret) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay window
  const base = `v0:${timestamp}:${rawBody}`;
  const mine = 'v0=' + crypto.createHmac('sha256', secret).update(base).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(mine), Buffer.from(signature)); }
  catch (e) { return false; }
}

module.exports = {
  notify, notifyAccessRule, notifyProxyUse, notifyProxyDenied,
  update, updateAccessRule, updateProxyUseDenied,
  test, verifySignature, isEnabled,
  signDecision, verifyDecisionToken,
  approvalBlocks, resolvedBlocks, accessRuleBlocks, proxyUseBlocks, proxyDeniedBlocks // exported for tests
};
