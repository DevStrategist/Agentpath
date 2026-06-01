const { execFileSync } = require('child_process');

function fromEnv(env) {
  for (const key of ['SUDO_USER', 'USER', 'LOGNAME']) {
    const v = env[key];
    if (v && v !== 'root') return v;
  }
  return null;
}

function defaultConsoleUser() {
  try {
    const u = execFileSync('stat', ['-f', '%Su', '/dev/console'], { encoding: 'utf8' }).trim();
    return u && u !== 'root' ? u : null;
  } catch (e) {
    return null;
  }
}

function resolveInvokingUser(env = process.env, consoleUser = defaultConsoleUser) {
  return fromEnv(env) || consoleUser() || null;
}

function bootstrapInvocation(script, invoker, isRoot, env = process.env) {
  const nextEnv = { ...env, SUDO_USER: invoker };
  if (isRoot) return { cmd: 'bash', args: [script], env: nextEnv };
  return { cmd: 'sudo', args: [`SUDO_USER=${invoker}`, 'bash', script], env };
}

module.exports = { resolveInvokingUser, bootstrapInvocation };
