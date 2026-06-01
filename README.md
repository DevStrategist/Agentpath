# KEYRING

**Agentic Firewall to keep your local autonomous agents in check.**

KEYRING is a firewall that sits between your autonomous agent and the powerful tools on your computer: local CLIs, MCP servers, APIs, and infrastructure commands. Instead of trusting an agent to always call the right thing, KEYRING watches the connection, blocks risky access by default, and asks a human before letting the agent through.

In plain English: if an agent hallucinates, gets prompt-injected, or starts running wild, KEYRING is the checkpoint it has to pass first. Today that checkpoint is human-in-the-loop approval with real-time Slack/dashboard controls; next, KEYRING is adding real-time agentic assessment so requests can be judged before they touch your tools.

KEYRING never needs to store your credentials. You stay logged in to tools like Railway, GitHub, or AWS yourself. The agent only gets a controlled route through KEYRING, and KEYRING decides whether that route is allowed.

## Technical Summary

**A policy egress proxy for AI agents. The agent can't reach your infrastructure without a human's say-so — and KEYRING never touches your credentials.**

The human has already authenticated their tools (e.g. `railway login`). The agent runs network-jailed: its only route out is KEYRING. To reach an approved destination, the agent's traffic passes through KEYRING, which checks a task-scoped host allowlist, requires human approval (Slack or local), and only then opens the tunnel. The credential rides *inside* the TLS stream KEYRING never decrypts — so KEYRING gates **access**, it never stores or sees secrets.

## What it enforces

- **Host-scoped access** — each task carries an allowlist of destination hosts. Anything else is refused (`host_not_in_scope`). Gating is by host (from the CONNECT line / SNI); no TLS interception.
- **Human-in-the-loop** — first access to a host requires approval, cached per `(task, host)`, surfaced in Slack (Block Kit Allow/Deny) or via the local CLI/dashboard.
- **Attenuation** — a derived grant can only narrow the allowlist, never widen it (`scope_widen_blocked`).
- **Task-binding** — cancel or expire the task and every grant + approval under it is void, even ones approved seconds earlier (`task_not_active`).
- **Per-binary gating (macOS)** — flag a CLI (e.g. `railway`) in the dashboard and that binary cannot make ANY outbound network call except through KEYRING. Enforced at the kernel by pf rules + a binary shim; not honor-system.

## Run the demo (no Slack, no Railway needed)

```bash
npm run demo
```

Runs four beats against stand-in hosts (allowed = `example.com`, out-of-scope = `api.github.com`):
1. agent reaches the allowed host → **held for approval** → approved → tunneled (HTTP 200);
2. agent tries an out-of-scope host → **refused** (`host_not_in_scope`);
3. task cancelled → retry the just-approved host → **refused** (`task_not_active`).

Run `npm test` for the attenuation / task-binding / tamper assertions.

## Use it for real

```bash
# 1. human authenticates the tool once, out of band
railway login

# 2. define the task + allowlist (Railway's API host)
keyring task create --id deploy-staging
keyring grant --task deploy-staging --allow '*.railway.com'

# 3. run the proxy and the dashboard
keyring proxy --task deploy-staging --port 8080 &
keyring serve --port 3000 &     # dashboard at http://localhost:3000

# 4. jail the agent so the proxy is its ONLY way out, then run it
sudo ./jail/jail.sh up                       # Linux iptables --uid-owner (or use jail/Dockerfile)
sudo -u agentjail HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 <agent command>
```

Approve from the dashboard, the Slack message, or `keyring approve --id <ap_..>`.

## Per-binary gating (macOS): "block railway everywhere except through KEYRING"

The host-allowlist model gates traffic *destined to* an approved host. The per-binary mode is the dual: gate traffic *originating from* a specific CLI binary. Once enabled, the chosen CLI cannot egress through any path other than KEYRING — for any user on the machine, agent or human. The kernel drops the packet before SYN.

How it works:
- pf rules deny all outbound for a dedicated `keyring-jail` uid, except loopback to the proxy and DNS.
- The CLI's binary is replaced with a small shim. The shim re-execs the real binary as `keyring-jail` with `HTTPS_PROXY=http://127.0.0.1:<proxy>`.
- A narrow `sudoers.d` entry lets the invoking user run the wrapped binary without typing a password.
- Bypass attempts (running the moved real binary directly, unsetting `HTTPS_PROXY`, etc.) are caught at the kernel pf layer — the real binary is `chmod 750 root:keyring-jail`, so only members of the jail group can exec it, and those members can't egress.

### Setup, one time (one password prompt)

```bash
# 0. (optional) verify your macOS actually supports pf uid-filtering
sudo bash jail/verify-pf-user.sh             # non-destructive 10s spike; expect: ✅ PASS

# 1. install the privileged helper — this is the ONLY time KEYRING asks for sudo
sudo keyring install
```

That command installs `/usr/local/libexec/keyring-helper` (root:wheel, 755), writes `/etc/sudoers.d/keyring` permitting your user to invoke *that exact helper* with no password, creates the `keyring-jail` user/group, and symlinks `/usr/local/bin/keyring` so the CLI is on `PATH`. After this, all KEYRING operations work silently from the CLI or the dashboard.

### Use it (the agent jail flow)

The model: **you keep using your CLIs normally as yourself; the agent runs jailed.** No human-side disruption.

```bash
# 1. you log in to railway normally — KEYRING is not in this loop
railway login

# 2. tell KEYRING which CLIs to gate (just metadata; no system change)
keyring gate add --name railway
# — or open the dashboard at http://localhost:3000 and use the
#   "Discovered CLIs" panel to scan your $PATH and toggle Enable per tool

# 3. bring the kernel jail up (silent, no password)
keyring jail up

# 4. start the proxy + dashboard
keyring task create --id deploy-staging
keyring grant --task deploy-staging --allow '*.railway.com'
keyring proxy --task deploy-staging --port 8080 &
keyring serve --port 3000 &

# 5. you keep using railway normally — runs as YOU, your Keychain works
railway whoami                                # → Logged in as ...

# 6. but agents reach railway ONLY through KEYRING:
keyring run -- railway whoami                 # drops to keyring-jail, snapshots your
                                              # ~/.railway auth into a temp HOME, sets
                                              # HTTPS_PROXY, exec's railway. Traffic to
                                              # backboard.railway.com hits KEYRING, you
                                              # approve in Slack/dashboard, then it tunnels.

# anything the jailed agent tries to do OUTSIDE the proxy is dropped at pf:
keyring run -- curl https://api.github.com    # → connection refused (host_not_in_scope at pf)
keyring run -- /opt/homebrew/bin/railway whoami    # same — direct binary call, pf still bites
```

### What the agent jail actually guarantees

When the agent is launched via `keyring run`, it runs as the `keyring-jail` uid for its entire process tree. pf rules give that uid exactly one route out: loopback to KEYRING. Every bypass an agent might try (env stripping, direct binary calls, raw sockets via `curl`/`node`/`python`, etc.) ends at the same kernel deny because pf is uid-keyed, not binary-keyed.

The human's egress is untouched — you keep your normal Keychain, normal config files, normal `railway login`. KEYRING gates the agent, not you.

### Auth pass-through

Each gate has a `configPaths` list — directories under your home that get snapshotted into the agent's temp `HOME` on every `keyring run`. Defaults are baked in for common CLIs (`railway → .railway`, `gh → .config/gh`, `aws → .aws`, ...). Override with `--config-paths`:

```bash
keyring gate add --name mytool --config-paths '.mytool,.config/mytool'
```

The snapshot is read-only from your side — the agent gets a fresh copy per invocation, can modify it freely, and the temp HOME is wiped on exit.

### Tear down

```bash
keyring gate remove --name railway     # unregister
keyring jail down                      # unload pf rules
keyring uninstall                      # remove helper, sudoers, jail user, symlink
```

### Why the helper

The alternative — KEYRING running its own commands with `sudo` each time — would either spam you with password prompts or require an overbroad `sudoers` rule. The helper pattern (same one Docker Desktop, Homebrew, Little Snitch use) keeps the elevated surface area to a single audited binary with input validation, and the `sudoers` rule is scoped to *exactly that path*.

### Bonus: per-binary universal mode (power-user)

If you want railway gated *everywhere on the machine* — including your own shell — there's a stricter `gate install` mode that shims the binary and forces every invocation through KEYRING. It's available via `sudo bash jail/install-shim.sh railway /opt/homebrew/bin/railway 8080`, but the auth-passthrough story doesn't work cleanly with it (your normal `railway whoami` would require KEYRING approval). The default per-agent-uid mode above is the recommended path for almost everyone.

## Slack approval

KEYRING posts a Block Kit approval message per pending host, with full context (CLI, scope, invoker, recent task activity), and updates the message in place when someone clicks Allow/Deny — no dead buttons, no double-resolves.

### Setup

1. Create a Slack app at https://api.slack.com/apps. Add the `chat:write` bot token scope. Install to your workspace.
2. Invite the bot to the channel you want approvals to land in: `/invite @your-bot` in that channel.
3. In **Interactivity & Shortcuts**, enable interactivity and set the Request URL to `https://<your-keyring-serve-host>/api/slack/interactivity`. Slack signs every callback; KEYRING verifies the signature and rejects 401 on mismatch.
4. Set env (in `.env` or your shell):
   ```bash
   SLACK_BOT_TOKEN=xoxb-...                  # bot token from "OAuth & Permissions"
   SLACK_SIGNING_SECRET=...                  # from "Basic Information"
   SLACK_APPROVAL_CHANNEL=C0123456789        # channel id (or "#name")
   KEYRING_DASHBOARD_URL=https://...         # optional "Open dashboard" deep-link
   ```
5. Verify the wiring before relying on it:
   ```bash
   keyring slack status     # shows what's set / missing
   keyring slack test       # posts a sample approval to SLACK_APPROVAL_CHANNEL
   ```
   Click Allow or Deny on the test message — the buttons should disappear and the message should update to show your username. If clicking does nothing visible, your interactivity URL isn't reachable from Slack.

### What approvers see

```
🔑 KEYRING approval requested
KEYRING is holding a connection from `railway` to *backboard.railway.com* (task *deploy-staging*).
Approve to tunnel; deny to refuse.

Task `deploy-staging` · Host `backboard.railway.com`
Scope `*.railway.com`
Invoked by `axiom` · via `railway`
Recent in this task: 0 allowed · 0 denied
<Open dashboard>

[ Allow ]  [ Deny ]
```

After click, the message replaces itself with `✅ KEYRING — Allowed by @alice · 2026-05-31 22:51:14 UTC` and the buttons are gone. Dashboard approvals do the same in reverse: clicking Allow in the dashboard updates the Slack message too, so two approvers can't race.

### Reliability

- One automatic retry on transient Slack errors (5xx, `service_unavailable`).
- Interactivity callbacks use `response_url` for instant message replace (no auth, no rate-limit concerns).
- If a pending approval times out, the message is updated to show `⛔ Denied by timeout`.
- If Slack is unreachable when KEYRING tries to post, the proxy still works via the local approver — `keyring approve --id <ap_..>` always works as a fallback, and the dashboard is always up.

## Honest scope

The deny is **enforced at the network layer** (iptables on Linux, pf on macOS, or a container network), not by an honor-system proxy env var. KEYRING gates *which hosts* the agent may reach; because it does not decrypt TLS, it cannot distinguish operations on the same host (e.g. deploy vs. teardown) — that distinction belongs to a command-broker variant. Task-binding reduces blast radius; it does not prove an in-scope action reflects user intent rather than a prompt injection.

Per-binary gating on macOS depends on pf supporting `user`-keyed outbound rules on your version. Run `sudo bash jail/verify-pf-user.sh` once to confirm; if it fails the kernel deny doesn't bite and we fall back to a Docker backend (TODO).

## Layout

```
bin/keyring         user-facing CLI (delegates privileged ops to the helper)
bin/keyring-helper  privileged single-entry-point (installed to /usr/local/libexec/...)

src/core.js         grants, host-scope, attenuation, task-binding, audit, gated CLIs
src/proxy.js        the CONNECT proxy (host gating + approval + tunnel)
src/approver.js     approval store + waiting
src/slack.js        Block Kit message + signature verification
src/server.js       dashboard + approval API + gates API + jail API + Slack interactivity
src/scanner.js      walks ~/.cargo/bin, /opt/homebrew/bin, etc. for the Discovered CLIs UI
src/cli.js          CLI dispatcher (task, grant, gate, run, proxy, serve, jail, install)

jail/bootstrap.sh         one-time installer (sudo'd by `keyring install`)
jail/jail.sh              Linux iptables --uid-owner jail
jail/jail-macos.sh        standalone macOS pf jail (power-user; helper supersedes this)
jail/verify-pf-user.sh    one-shot spike to confirm pf uid-filtering works on this Mac
jail/install-shim.sh      standalone per-binary shim installer (power-user)
jail/uninstall-shim.sh    standalone shim remover (power-user)
jail/Dockerfile           cross-platform container jail (TODO: --internal network)

demo/run-demo.sh          the four beats
```
