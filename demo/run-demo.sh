#!/usr/bin/env bash
# Runnable demo of the 4 beats. Uses stand-in hosts so it runs anywhere:
#   ALLOWED  (Railway stand-in) = example.com
#   OUT-OF-SCOPE (exfil stand-in) = api.github.com
# Point ALLOW at backboard.railway.com for the real demo.
set -u
cd "$(dirname "$0")/.."
export KEYRING_STATE="$(pwd)/.keyring-demo-state.json"
rm -f "$KEYRING_STATE"
KR="node bin/keyring"
PORT=8899
ALLOW=example.com
FORBID=api.github.com
line(){ echo; echo "──────────────────────────────────────────────"; echo "$1"; echo "──────────────────────────────────────────────"; }

line "Beat 0 — create task + grant (allowlist = $ALLOW)"
$KR task create --id deploy-staging >/dev/null
$KR grant --task deploy-staging --allow $ALLOW >/dev/null
echo "task deploy-staging active; allowlist: [$ALLOW]"

KEYRING_PROXY_PORT=$PORT KEYRING_APPROVAL_TIMEOUT=30000 $KR proxy --task deploy-staging 2>/tmp/keyring-proxy.log &
PROXY_PID=$!
sleep 1

line "Beat 1+2 — agent reaches ALLOWED host: blocked pending HUMAN APPROVAL, then tunneled"
echo "agent: curl -x http://127.0.0.1:$PORT https://$ALLOW   (will hang awaiting approval)"
curl -s -o /dev/null -w "   -> agent got HTTP %{http_code} from $ALLOW\n" --max-time 25 -x http://127.0.0.1:$PORT https://$ALLOW/ &
CURL_PID=$!
sleep 2
AP=$($KR pending --task deploy-staging --idonly)
echo "   [human] Slack/CLI approval prompt fired -> approving $AP"
$KR approve --id "$AP" --by '@alex' >/dev/null
wait $CURL_PID

line "Beat 3 — agent tries an OUT-OF-SCOPE host ($FORBID): denied, no approval even offered"
curl -s -o /dev/null -w "   -> agent got HTTP %{http_code} (000 = refused at proxy)\n" --max-time 10 -x http://127.0.0.1:$PORT https://$FORBID/ 2>/dev/null
echo "   (see reason in audit log below)"

line "Beat 4 — cancel the task, then retry the ALREADY-APPROVED host"
$KR task cancel --id deploy-staging >/dev/null
echo "   task cancelled."
curl -s -o /dev/null -w "   -> agent got HTTP %{http_code} (000 = refused) even though it was approved 5s ago\n" --max-time 10 -x http://127.0.0.1:$PORT https://$ALLOW/ 2>/dev/null

line "Audit trail (task deploy-staging)"
$KR log --task deploy-staging

kill $PROXY_PID 2>/dev/null
echo; echo "proxy log:"; sed 's/^/   /' /tmp/keyring-proxy.log
