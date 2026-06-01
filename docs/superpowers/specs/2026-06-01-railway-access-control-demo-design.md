# Railway Access Control Demo Design

## Purpose

KEYRING should demo domain access controls without storing infrastructure credentials. The human authenticates `railway` normally, outside KEYRING. KEYRING then blocks the real Railway CLI from direct network access and exposes a controlled proxy path that the agent must use. Slack notifies the human about access attempts and lets the human toggle Railway access on or off during the demo.

The headline claim for the demo is:

> The agent cannot directly reach Railway. It must ask KEYRING, and KEYRING only grants network access when the human allows it.

## Demo Modes

### Primary Mode: Real Railway CLI Blocking

The main demo uses the actual `railway` binary on macOS.

- `sudo keyring install` performs the one-time helper setup.
- KEYRING registers the discovered `railway` binary.
- KEYRING installs a shim for `railway`.
- KEYRING loads `pf` rules that block direct egress to Railway destination IPs except from the KEYRING proxy user.
- The agent is told that KEYRING is the Railway proxy and that direct Railway access is unavailable.
- When direct Railway access is blocked, direct `railway` usage fails closed.
- When a KEYRING proxy request is approved, the operation can proceed through the proxy.

This path is the one used for the live demo whenever the host machine supports the helper and macOS `pf` UID rules.

### Fallback Mode: Simulated Enforcement

The fallback mode is for rehearsals, CI, and machines where real firewall enforcement is unavailable.

- The demo uses a deterministic mock Railway command or mock Railway endpoint.
- The same access rule state, Slack controls, dashboard controls, and audit trail are exercised.
- The UI clearly labels this as simulated enforcement.

Fallback mode exists to keep the story rehearsable. It should not replace the real Railway CLI blocking path in the demo narrative.

## User-Facing Flow

1. The human runs `railway login` normally. KEYRING does not capture, store, or inspect Railway credentials.
2. The human runs one-time setup with `sudo keyring install`.
3. The human starts the KEYRING dashboard and proxy.
4. The human enables the Railway gate from the dashboard or CLI.
5. Slack receives a message showing that Railway direct access is controlled by KEYRING.
6. The demo starts with Railway direct access blocked.
7. The agent attempts to use Railway directly and fails.
8. The agent is instructed to ask KEYRING, the proxy, for Railway access.
9. KEYRING sends a Slack notification for the request.
10. The human toggles or approves access from Slack.
11. KEYRING allows the proxied Railway request.
12. The dashboard and Slack show the audit trail and final state.

## Access Rule Model

The demo should expose one understandable rule:

```text
railway direct access: blocked | unblocked
```

The rule controls whether the real Railway CLI is prevented from direct network egress. When direct access is blocked, the agent's only successful route is KEYRING's proxy path. In the normal demo, the rule stays blocked while individual proxy requests are approved or denied. Temporarily unblocking direct access is available as an operator control to demonstrate the before and after state.

The rule should record:

- CLI name: `railway`
- enforcement mode: `real` or `simulated`
- direct access state: `blocked` or `unblocked`
- proxy access state: `allowed`, `requires_approval`, or `denied`
- hosts in scope: Railway host patterns and concrete expanded hosts
- last changed by: Slack user, dashboard, CLI, or system
- timestamps for blocked, unblocked, approved, denied, and expired events

## Architecture

### Core State

`src/core.js` owns the access rule state alongside existing tasks, grants, gated CLIs, and audit events.

Required behavior:

- Register `railway` as a gate.
- Store whether the gate is real or simulated.
- Store whether direct Railway access is blocked or unblocked.
- Refuse scope widening.
- Keep task binding intact.
- Add audit events for direct attempts, proxy attempts, Slack toggles, dashboard toggles, approvals, denials, and failures.

### Firewall and Shim Layer

The existing helper and `pf` machinery are the primary real enforcement backend.

Required behavior:

- The real `railway` binary can be shimmed.
- The shim routes invocation through `keyring run`.
- The jailed execution receives Railway auth config through the existing config snapshot mechanism.
- Direct network access to Railway destination IPs is blocked except from the KEYRING proxy user.
- Stopping the proxy should fail closed for gated Railway operations.
- Disabling the gate restores the binary and removes Railway host blocks that are not needed by another gate.

### Proxy Layer

`src/proxy.js` remains the domain-level CONNECT proxy.

Required behavior:

- KEYRING presents itself as the Railway proxy to the agent.
- It checks the active task, grant, host scope, access rule, and approval state before opening a tunnel.
- It never decrypts TLS and never sees Railway credentials.
- It logs denied requests with explicit reasons such as `railway_access_disabled`, `host_not_in_scope`, `task_not_active`, or `approval_denied`.

### Slack Controls

Slack is both a notification surface and a control surface.

Required behavior:

- Notify when a Railway access request is held.
- Provide Allow and Deny buttons for individual requests.
- Provide Block Direct Railway and Unblock Direct Railway buttons for the rule state.
- Update messages in place after a click.
- Show who changed the state.
- Keep dashboard and Slack state synchronized.
- Fail gracefully if Slack is unavailable, with dashboard and CLI as fallback controls.

### Dashboard Controls

The dashboard remains the local operator panel.

Required behavior:

- Show whether Railway is gated.
- Show whether enforcement is real or simulated.
- Show whether the proxy is running.
- Show whether direct Railway access is blocked.
- Provide enable, disable, install, uninstall, proxy start, and proxy stop controls.
- Surface clear warnings when helper setup is missing or when the proxy is down while the gate is active.

### Demo Runner

The demo script should support both paths.

Required behavior:

- `npm run demo` remains safe and deterministic.
- A new real demo command, such as `npm run demo:railway`, can drive the actual Railway path after setup.
- The real demo preflights the helper, `railway` binary, proxy health, Slack status, and `pf` support before mutating anything.
- The real demo stops early with actionable messages if a preflight fails.

## Command Shape

The demo should support commands close to:

```bash
sudo keyring install
keyring serve --port 3000
keyring gate add --name railway
keyring proxy --task railway-demo --port 8080
keyring access block --cli railway
keyring access unblock --cli railway
keyring run -- railway whoami
```

Slack and dashboard should call the same underlying access-rule operations as the CLI. The exact command names can follow the existing CLI style during implementation.

## Error Handling

The system should prefer explicit failure over silent bypass.

- If helper setup is missing, show `helper_not_installed`.
- If `pf` rules are unavailable, show `real_enforcement_unavailable` and offer simulated mode.
- If the proxy is down while Railway is gated, direct access remains blocked and proxied access fails closed.
- If Slack is unavailable, keep local dashboard and CLI approval available.
- If Railway host IPs rotate, refresh host blocks and show refresh state in the dashboard.
- If a Slack action races with dashboard action, the first resolved action wins and both UIs update.

## Security Boundaries

KEYRING must not store Railway credentials. It may snapshot local Railway config into a temporary jailed HOME when running the gated command, then delete that HOME after the command exits.

KEYRING gates domains and network paths, not Railway subcommands. Because TLS is not decrypted, KEYRING cannot distinguish `railway status` from `railway up` once both target the same approved Railway host. The demo should present this honestly as domain access control, not semantic command authorization.

## Testing

Unit tests should cover:

- Access rule creation and state transitions.
- Audit events for enable, disable, approve, deny, direct attempt, and proxy attempt.
- Host allowlist behavior for Railway hosts.
- Slack block generation for rule toggles and approvals.
- Fallback simulated mode behavior.

Integration or scripted tests should cover:

- Existing deterministic `npm run demo`.
- Simulated Railway access disabled versus enabled.
- Real-mode preflight checks without requiring mutation.

Manual verification should cover:

- Real `railway` binary is restored after disabling or uninstalling the gate.
- Direct Railway access fails while gated.
- Proxied Railway access waits for Slack approval.
- Slack block and unblock controls change dashboard state.
- KEYRING proxy logs and audit trail match the demo story.

## Acceptance Criteria

- The real `railway` CLI can be blocked for the demo.
- The agent is clearly informed that KEYRING is the Railway proxy.
- The agent cannot bypass KEYRING with direct Railway network access in primary mode.
- Slack notifies the user about Railway access attempts.
- Slack can block or unblock direct Railway access controls.
- Dashboard, Slack, and CLI all reflect the same rule state.
- KEYRING never stores Railway credentials.
- A safe simulated fallback exists for rehearsals and unsupported machines.
