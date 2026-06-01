// keyring CLI — manage tasks, grants, approvals, gated CLIs; run the proxy and the server.
const core = require('./core');
const ap = require('./approver');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const { resolveInvokingUser, bootstrapInvocation } = require('./invoker');
require('./env').loadDotEnv();

const DEFAULT_TASK = 'default';
const DEFAULT_APPROVAL_TIMEOUT = parseInt(process.env.KEYRING_APPROVAL_TIMEOUT || '300000', 10);
const argv = process.argv.slice(2);
const cmd = argv[0];
const sub = argv[1] && !argv[1].startsWith('--') ? argv[1] : null;

// Find the `--` boundary (everything after is positional, untouched). Used by `keyring run`.
const ddIdx = argv.indexOf('--');
const headArgs = ddIdx === -1 ? argv : argv.slice(0, ddIdx);
const tailArgs = ddIdx === -1 ? [] : argv.slice(ddIdx + 1);

const flags = {};
const startIdx = sub ? 2 : 1;
const stopIdx = ddIdx === -1 ? headArgs.length : ddIdx;
for (let i = startIdx; i < stopIdx; i++) {
  if (headArgs[i].startsWith('--')) {
    const key = headArgs[i].slice(2);
    const val = (headArgs[i + 1] && !headArgs[i + 1].startsWith('--')) ? headArgs[++i] : true;
    flags[key] = val;
  }
}
const die = m => { console.error('error: ' + m); process.exit(1); };
const ok = o => { console.log(typeof o === 'string' ? o : JSON.stringify(o, null, 2)); };
const which = (bin) => {
  const r = spawnSync('which', [bin], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
};
const jailDir = path.join(__dirname, '..', 'jail');
const HELPER = '/usr/local/libexec/keyring-helper';

function dashboardUrl() {
  return core.getRuntimeConfig().dashboardUrl || process.env.KEYRING_DASHBOARD_URL || undefined;
}
if (process.env.KEYRING_DASHBOARD_URL) {
  core.setRuntimeConfig({ dashboardUrl: process.env.KEYRING_DASHBOARD_URL });
}

// Call the privileged helper non-interactively via sudo. Returns { ok, data, error, raw }.
// If sudoers isn't set up yet, returns { ok:false, error:'not_installed' } so callers can
// tell the user to run `sudo keyring install` first.
function helper(...args) {
  const r = spawnSync('sudo', ['-n', HELPER, ...args], { encoding: 'utf8' });
  if (r.error) return { ok: false, error: 'helper_exec_failed', raw: r.error.message };
  if (r.status !== 0 && /a password is required/i.test(r.stderr || '')) {
    return { ok: false, error: 'not_installed', raw: 'run: sudo keyring install' };
  }
  const out = (r.stdout || '').trim();
  try {
    const parsed = JSON.parse(out);
    return { ok: !!parsed.ok, data: parsed, error: parsed.error, raw: out };
  } catch (e) {
    return { ok: false, error: 'helper_bad_output', raw: out + '\n' + (r.stderr || '') };
  }
}
function helperOrDie(...args) {
  const r = helper(...args);
  if (!r.ok) {
    if (r.error === 'not_installed') {
      die('KEYRING privileged helper not installed. run once:  sudo keyring install');
    }
    die(`helper error: ${r.error || 'unknown'}${r.raw ? '\n' + r.raw : ''}`);
  }
  return r.data;
}

async function ensureRailwayProxyApproval(cliName, accessRule, opts = {}) {
  if (cliName !== 'railway') return;
  if (!accessRule || accessRule.proxy !== 'requires_approval') return;
  if (core.proxyGrantActive(accessRule)) return;

  const slack = require('./slack');
  const taskId = opts.taskId || process.env.KEYRING_TASK || DEFAULT_TASK;
  const host = 'backboard.railway.com';
  let task = core.getTask(taskId);
  if (!task || task.status !== 'active') task = core.createTask(taskId);

  const hosts = core.defaultAllowHostsForGatedClis([cliName]);
  const grant = core.getGrant(taskId);
  if (!core.verifyGrant(grant)) core.setGrant(taskId, hosts);

  for (const old of ap.listPending(taskId).filter(p => p.host === host && p.cli === cliName)) {
    ap.resolve(old.id, 'denied', 'superseded-by-preflight');
  }

  const pending = ap.createPending(taskId, host, { cli: cliName, preflight: true });
  const ctx = {
    cli: cliName,
    invoker: opts.invoker,
    allowHosts: hosts,
    accessRule,
    dashboardUrl: dashboardUrl()
  };
  const r = await slack.notify(pending, ctx);
  if (r && r.ok) ap.attachSlackTarget(pending.id, r.channel, r.ts);
  else if (r && r.error && r.error !== 'slack_disabled') {
    process.stderr.write(`[KEYRING] slack notify failed: ${r.error}\n`);
  }

  process.stderr.write(`KEYRING waiting for Slack approval before launching railway (${pending.id}).\n`);
  if (!slack.isEnabled()) process.stderr.write(`Approve locally with: keyring approve --id ${pending.id}\n`);
  const result = await ap.waitFor(pending.id, DEFAULT_APPROVAL_TIMEOUT);

  if (slack.isEnabled()) {
    const full = ap.getApproval(pending.id);
    const target = full && full.slack;
    if (target && target.channel && target.ts) {
      const status = result.status === 'approved' ? 'approved' : 'denied';
      const approver = result.approver || (result.status === 'timeout' ? 'timeout' : 'unknown');
      slack.update(target, pending, status, approver, ctx).catch(() => {});
    }
  }

  if (result.status !== 'approved') {
    die(result.status === 'timeout'
      ? `KEYRING timed out waiting for Slack approval before launching ${cliName}.`
      : `KEYRING denied ${cliName} before launch.`);
  }

  const latestRule = core.getAccessRule(cliName);
  if (!core.proxyGrantActive(latestRule)) {
    core.grantProxyAccess(cliName, {
      durationMs: 10 * 60 * 1000,
      by: result.approver || 'preflight',
      source: 'cli-preflight'
    });
  }
}

async function notifyRailwayProxyDenied(cliName, accessRule, opts = {}) {
  if (cliName !== 'railway' || !accessRule) return;
  const slack = require('./slack');
  const r = await slack.notifyProxyDenied(accessRule, {
    cli: cliName,
    invoker: opts.invoker,
    argv: opts.argv || [],
    dashboardUrl: dashboardUrl()
  }).catch(e => ({ ok: false, error: e.message }));
  if (r && r.error && r.error !== 'slack_disabled') {
    process.stderr.write(`[KEYRING] slack denied notify failed: ${r.error}\n`);
  }
}

switch (cmd) {
  case 'task': {
    if (sub === 'create') { if (!flags.id) die('--id required'); ok(core.createTask(flags.id, flags.ttl ? Number(flags.ttl) : null)); }
    else if (sub === 'cancel') { if (!flags.id) die('--id required'); ok(core.cancelTask(flags.id)); }
    else if (sub === 'show') { ok(core.getTask(flags.id)); }
    else die('usage: keyring task create|cancel|show --id <id> [--ttl <sec>]');
    break;
  }
  case 'grant': {
    if (!flags.task || !flags.allow) die('usage: keyring grant --task <id> --allow host1,host2');
    ok(core.setGrant(flags.task, String(flags.allow).split(',').map(s => s.trim())));
    break;
  }
  case 'derive': { // attenuation demo: child allowlist must be a subset of the parent's
    if (!flags.task || !flags.allow) die('usage: keyring derive --task <id> --allow host1,host2');
    try { ok(core.deriveGrant(flags.task, String(flags.allow).split(',').map(s => s.trim()))); }
    catch (e) { die(e.message); } // e.g. scope_widen_blocked
    break;
  }
  case 'approve': { if (!flags.id) die('--id required'); ok(ap.resolve(flags.id, 'approved', flags.by || 'cli')); break; }
  case 'deny':    { if (!flags.id) die('--id required'); ok(ap.resolve(flags.id, 'denied', flags.by || 'cli')); break; }
  case 'pending': {
    const list = ap.listPending(flags.task || undefined);
    if (flags.idonly) { ok(list.length ? list[list.length - 1].id : ''); }
    else ok(list);
    break;
  }
  case 'log': { ok(core.getAudit(flags.task || undefined)); break; }
  case 'proxy': {
    if (!flags.task) die('usage: keyring proxy --task <id> [--port <p>]');
    process.env.KEYRING_TASK = flags.task;
    if (flags.port) process.env.KEYRING_PROXY_PORT = String(flags.port);
    require('./proxy'); // long-running
    break;
  }
  case 'serve': {
    if (flags.port) process.env.KEYRING_SERVER_PORT = String(flags.port);
    require('./server'); // long-running
    break;
  }
  case 'slack': {
    const slack = require('./slack');
    if (sub === 'test') {
      if (!slack.isEnabled()) die('SLACK_BOT_TOKEN not set. set it in your shell or .env and re-run.');
      if (!process.env.SLACK_APPROVAL_CHANNEL) die('SLACK_APPROVAL_CHANNEL not set.');
      slack.test().then(r => {
        if (r.ok) {
          console.log(JSON.stringify({ ok: true, posted_to: process.env.SLACK_APPROVAL_CHANNEL, channel: r.channel, ts: r.ts }, null, 2));
          console.log('\nopen Slack — you should see a 10-minute / forever / deny prompt for "keyring-slack-test".');
          console.log('clicking either button confirms your interactivity URL is wired correctly.');
        } else {
          die('slack post failed: ' + r.error);
        }
      }).catch(e => die('slack threw: ' + e.message));
    } else if (sub === 'status') {
      ok({
        enabled: slack.isEnabled(),
        token_set: !!process.env.SLACK_BOT_TOKEN,
        channel_set: !!process.env.SLACK_APPROVAL_CHANNEL,
        signing_secret_set: !!process.env.SLACK_SIGNING_SECRET,
        channel: process.env.SLACK_APPROVAL_CHANNEL || null
      });
    } else {
      die('usage: keyring slack test|status');
    }
    break;
  }
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
    } else if (sub === 'proxy') {
      const proxy = flags.proxy || flags.state;
      if (!proxy || !['requires_approval', 'allowed', 'denied'].includes(proxy)) die('usage: keyring access proxy --cli railway --proxy requires_approval|allowed|denied');
      ok(core.setAccessRule(cli, { proxy, by: flags.by || process.env.USER || 'cli', source: 'cli' }));
    } else {
      die('usage: keyring access show|list|block|unblock|mode|proxy --cli <name>');
    }
    break;
  }
  case 'gate': {
    if (sub === 'add') {
      if (!flags.name) die('usage: keyring gate add --name <cli> [--bin <path>] [--config-paths a,b]');
      const binPath = flags.bin && flags.bin !== true ? String(flags.bin) : which(flags.name);
      if (!binPath) die(`could not find binary "${flags.name}" on PATH. Pass --bin <path> explicitly.`);
      if (!fs.existsSync(binPath)) die(`binary not found: ${binPath}`);
      const configPaths = flags['config-paths'] && flags['config-paths'] !== true
        ? String(flags['config-paths']).split(',').map(s => s.trim()).filter(Boolean)
        : undefined; // let core.addGate apply per-CLI defaults
      try { ok(core.addGate(flags.name, { binPath, configPaths })); }
      catch (e) { die(e.message); }
    } else if (sub === 'list') {
      ok(core.listGates());
    } else if (sub === 'remove') {
      if (!flags.name) die('--name required');
      const g = core.getGate(flags.name);
      if (g && g.enforcement === 'shimmed') {
        die(`gate "${flags.name}" is shimmed. Run: keyring gate uninstall --name ${flags.name}  first.`);
      }
      try { ok(core.removeGate(flags.name)); }
      catch (e) { die(e.message); }
    } else if (sub === 'show') {
      if (!flags.name) die('--name required');
      ok(core.getGate(flags.name) || null);
    } else if (sub === 'install') {
      if (!flags.name) die('usage: keyring gate install --name <cli>');
      const g = core.getGate(flags.name);
      if (!g) die(`gate "${flags.name}" not registered. Run: keyring gate add --name ${flags.name}`);
      if (!g.binPath) die(`gate "${flags.name}" has no binPath`);
      const proxyPort = process.env.KEYRING_PROXY_PORT || '8080';
      const invoker = process.env.SUDO_USER || process.env.USER;
      const r = helperOrDie('shim-install', flags.name, g.binPath, String(proxyPort), invoker);
      core.updateGate(flags.name, { enforcement: 'shimmed', realPath: r.real, shimmedAt: Date.now() });
      ok(core.getGate(flags.name));
    } else if (sub === 'uninstall') {
      if (!flags.name) die('--name required');
      const g = core.getGate(flags.name);
      if (!g) die(`gate "${flags.name}" not registered.`);
      helperOrDie('shim-uninstall', flags.name, g.binPath);
      core.updateGate(flags.name, { enforcement: 'registered', realPath: null });
      ok(core.getGate(flags.name));
    } else {
      die('usage: keyring gate add|list|show|remove|install|uninstall --name <cli>');
    }
    break;
  }
  case 'run': {
    (async () => {
      if (!tailArgs.length) die('usage: keyring run [--proxy-port <p>] [--task <id>] -- <command> [args...]');
      const proxyPort = flags['proxy-port'] || process.env.KEYRING_PROXY_PORT || '8080';
      const [binArg, ...rest] = tailArgs;
      // Resolve to absolute path so the helper (running as root) can locate it.
      const absBin = binArg.startsWith('/') ? binArg : which(binArg);
      if (!absBin || !fs.existsSync(absBin)) die(`binary not found: ${binArg}`);
      // When a shim execs `keyring run -- /opt/.../railway.keyring-real ...`, strip the
      // .keyring-real suffix so we look up the gate by its real name (railway) and apply
      // the right configPaths / audit cli field.
      const cliName = path.basename(absBin).replace(/\.keyring-real$/, '');
      const gate = core.getGate(cliName);
      const invoker = process.env.SUDO_USER || process.env.USER;
      const configPaths = (gate && gate.configPaths) ? gate.configPaths.join(',') : '';
      const accessRule = core.getAccessRule(cliName);

      if (accessRule && accessRule.proxy === 'denied') {
        core.addAudit({
          taskId: flags.task || null,
          host: null,
          decision: 'denied',
          reason: 'railway_access_disabled_preflight',
          cli: cliName,
          argv: rest
        });
        await notifyRailwayProxyDenied(cliName, accessRule, { invoker, argv: rest });
        die(`KEYRING blocked ${cliName}: proxy access is denied. Use the dashboard or Slack to require approval again.`);
      }

      await ensureRailwayProxyApproval(cliName, accessRule, {
        taskId: flags.task || null,
        invoker
      });

      // Audit the invocation up front (independent of whether KEYRING is running).
      core.addAudit({
        taskId: flags.task || null,
        host: null,
        decision: 'invoked',
        reason: gate ? 'gated_cli_invoked' : 'ungated_cli_invoked',
        cli: cliName,
        argv: rest
      });

      // Hand off to the helper, which drops to keyring-jail with a temp HOME holding
      // copies of the invoker's config paths. Stdio flows through inherit.
      const r = spawnSync('sudo', [
        '-n', HELPER, 'run',
        invoker, configPaths, String(proxyPort), absBin, ...rest
      ], { stdio: 'inherit' });
      if (r.error) die(`could not invoke helper: ${r.error.message}`);
      if (r.status === 1 && !rest.length && !fs.existsSync(HELPER)) {
        die('KEYRING privileged helper not installed. run once:  sudo keyring install');
      }
      process.exit(r.status === null ? 1 : r.status);
    })().catch(e => die(e.message));
    break;
  }
  case 'jail': {
    const action = sub || 'status';
    if (action === 'verify') {
      console.error(`run once:  sudo bash ${path.join(jailDir, 'verify-pf-user.sh')}\n`);
      console.error('non-destructive spike: confirms macOS pf uid-filtering works on this Mac.');
      break;
    }
    if (action === 'up') {
      const port = flags.port || process.env.KEYRING_PROXY_PORT || '8080';
      ok(helperOrDie('jail-up', String(port)));
    } else if (action === 'down') {
      ok(helperOrDie('jail-down'));
    } else if (action === 'status') {
      ok(helperOrDie('jail-status'));
    } else {
      die('usage: keyring jail up [--port 8080] | down | status | verify');
    }
    break;
  }
  case 'install': {
    // One-time bootstrap. The user must type their password ONCE; after that
    // keyring uses the installed helper non-interactively for all privileged ops.
    const script = path.join(jailDir, 'bootstrap.sh');
    const invoker = resolveInvokingUser();
    if (!invoker) die('could not determine invoking user. Try: sudo SUDO_USER=$USER keyring install');
    console.error(`installing KEYRING privileged helper. you will be prompted for your password once.`);
    const invocation = bootstrapInvocation(script, invoker, typeof process.getuid === 'function' && process.getuid() === 0);
    const r = spawnSync(invocation.cmd, invocation.args, { stdio: 'inherit', env: invocation.env || process.env });
    process.exit(r.status === null ? 1 : r.status);
  }
  case 'uninstall': {
    // Use the helper to tear everything down (works because we still have the
    // NOPASSWD entry until self-uninstall removes it).
    const r = helper('self-uninstall');
    if (!r.ok && r.error === 'not_installed') die('KEYRING helper not installed; nothing to do.');
    if (!r.ok) die(`uninstall failed: ${r.error || 'unknown'}\n${r.raw || ''}`);
    // Also drop our top-level sudoers entry (helper drops itself + jail user + per-shim ones)
    console.error('removing /etc/sudoers.d/keyring (last sudo prompt)...');
    spawnSync('sudo', ['rm', '-f', '/etc/sudoers.d/keyring'], { stdio: 'inherit' });
    ok({ uninstalled: true });
  }
  default:
    ok([
      'keyring — policy egress proxy for AI agents',
      '',
      'setup (run once):',
      '  install                               install privileged helper (one sudo prompt)',
      '  uninstall                             remove the helper + everything it installed',
      '  jail verify                           non-destructive pre-flight: confirms pf uid filtering works',
      '',
      'tasks + grants:',
      '  task create --id <id> [--ttl <sec>]   create a task (active)',
      '  task cancel --id <id>                 cancel a task (voids its grant + approvals)',
      '  grant --task <id> --allow a,b         set the host allowlist (root grant)',
      '  derive --task <id> --allow a          narrow the grant (rejects widening)',
      '',
      'access controls:',
      '  access show --cli railway              show one access rule',
      '  access list                            list access rules',
      '  access block --cli railway             block direct CLI egress',
      '  access unblock --cli railway           unblock direct CLI egress',
      '  access mode --cli railway --enforcement real|simulated',
      '  access proxy --cli railway --proxy requires_approval|allowed|denied',
      '',
      'gated CLIs (per-binary universal mode — silent after install):',
      '  gate add --name <cli> [--bin <path>]  register a CLI to gate (no system change)',
      '  gate list                             list registered gates',
      '  gate show --name <cli>                show one gate',
      '  gate install --name <cli>             install the binary shim (no password prompt)',
      '  gate uninstall --name <cli>           remove the binary shim (no password prompt)',
      '  gate remove --name <cli>              unregister (must be uninstalled first if shimmed)',
      '',
      'kernel jail:',
      '  jail up [--port 8080]                 load the deny-by-default pf rules (no prompt)',
      '  jail down                             unload the pf rules (no prompt)',
      '  jail status                           show jail user, anchor, rule count',
      '',
      'runtime:',
      '  proxy --task <id> [--port 8080]       run the gating CONNECT proxy',
      '  run [--proxy-port p] -- <cmd>         run a command with HTTPS_PROXY pointed at KEYRING',
      '  serve [--port 3000]                   run dashboard + approval + Slack endpoint',
      '',
      'approvals + audit:',
      '  pending [--task <id>] [--idonly]      list pending approvals',
      '  approve --id <ap_..>                  approve a pending request',
      '  deny --id <ap_..>                     deny a pending request',
      '  log [--task <id>]                     print the audit trail',
      '',
      'slack integration:',
      '  slack status                          show current Slack env config',
      '  slack test                            post a sample approval to confirm wiring'
    ].join('\n'));
}
