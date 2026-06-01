const fs = require('fs');
const path = require('path');

function parseDotEnv(text) {
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    let value = line.slice(idx + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function defaultDotEnvPath(cwd = process.cwd) {
  try {
    return path.join(cwd(), '.env');
  } catch (e) {
    return null;
  }
}

function loadDotEnv(file, target = process.env) {
  const resolved = file || defaultDotEnvPath();
  if (!resolved) return {};
  file = resolved;
  if (!fs.existsSync(file)) return {};
  const parsed = parseDotEnv(fs.readFileSync(file, 'utf8'));
  for (const [key, value] of Object.entries(parsed)) {
    if (target[key] == null) target[key] = value;
  }
  return parsed;
}

module.exports = { parseDotEnv, loadDotEnv, defaultDotEnvPath };
