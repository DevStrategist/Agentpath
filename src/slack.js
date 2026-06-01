// Slack adapter — Block Kit approval messages with full context, lifecycle updates,
// transient-error retry, and a built-in test command. No SDK; uses built-in https.
//
// If SLACK_BOT_TOKEN is unset, notify() / update() are no-ops and KEYRING falls back
// to the local CLI/dashboard approver.
const https = require('https');
const crypto = require('crypto');

const SLACK_API = 'slack.com';

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
  if (ctx.dashboardUrl) {
    elements.push({ type: 'mrkdwn', text: `<${ctx.dashboardUrl}|Open dashboard>` });
  }

  return [
    { type: 'header', text: { type: 'plain_text', text: '🔑 KEYRING approval requested' } },
    { type: 'section', text: { type: 'mrkdwn',
      text: `KEYRING is holding a connection from ${cli} to *${pending.host}* (task *${pending.taskId}*). Approve to tunnel; deny to refuse.` } },
    { type: 'context', elements },
    { type: 'actions', elements: [
      { type: 'button', style: 'primary', text: { type: 'plain_text', text: 'Allow' }, action_id: 'allow', value: pending.id },
      { type: 'button', style: 'danger',  text: { type: 'plain_text', text: 'Deny'  }, action_id: 'deny',  value: pending.id }
    ]}
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
  notify, update, test, verifySignature, isEnabled,
  approvalBlocks, resolvedBlocks // exported for tests
};
