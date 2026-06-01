// Approval store + waiting. Channel-agnostic: local CLI or Slack both resolve the same records.
const crypto = require('crypto');
const { load, update } = require('./store');

function findApproval(taskId, host) {
  return Object.values(load().approvals).find(a => a.taskId === taskId && a.host === host);
}
function createPending(taskId, host) {
  return update(s => {
    const id = 'ap_' + crypto.randomBytes(4).toString('hex');
    s.approvals[id] = { id, taskId, host, status: 'pending', ts: Date.now() };
    return s.approvals[id];
  });
}
// Attach Slack delivery metadata so the resolver can update the original message later.
function attachSlackTarget(id, channel, ts) {
  return update(s => {
    if (s.approvals[id]) s.approvals[id].slack = { channel, ts };
    return s.approvals[id];
  });
}
function resolve(id, status, approver) {
  return update(s => {
    if (s.approvals[id]) { s.approvals[id].status = status; s.approvals[id].approver = approver || 'unknown'; s.approvals[id].resolvedAt = Date.now(); }
    return s.approvals[id];
  });
}
function listPending(taskId) {
  return Object.values(load().approvals).filter(a => a.status === 'pending' && (!taskId || a.taskId === taskId));
}
async function waitFor(id, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const a = load().approvals[id];
    if (a && a.status !== 'pending') return a;
    await new Promise(r => setTimeout(r, 400));
  }
  return { status: 'timeout' };
}
function getApproval(id) { return load().approvals[id]; }
module.exports = { findApproval, createPending, attachSlackTarget, resolve, getApproval, listPending, waitFor };
