#!/usr/bin/env bash
# Make the network jail REAL (Linux). The agent runs as a dedicated UID whose only
# permitted egress is the KEYRING proxy. Everything else is dropped — so the agent
# cannot reach Railway (or anywhere) except by routing through KEYRING.
#
#   sudo ./jail/jail.sh up      # install rules
#   sudo ./jail/jail.sh down    # remove rules
# Then run the agent as that user:
#   sudo -u agentjail HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 <agent cmd>
set -euo pipefail
AGENT_USER="${AGENT_USER:-agentjail}"
PROXY_PORT="${PROXY_PORT:-8080}"
UID_N="$(id -u "$AGENT_USER")"

case "${1:-}" in
  up)
    # allow loopback to the proxy + DNS; drop all other egress for the jailed uid
    iptables -A OUTPUT -m owner --uid-owner "$UID_N" -o lo -p tcp --dport "$PROXY_PORT" -j ACCEPT
    iptables -A OUTPUT -m owner --uid-owner "$UID_N" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -m owner --uid-owner "$UID_N" -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -m owner --uid-owner "$UID_N" -j REJECT
    echo "jail up: uid $UID_N ($AGENT_USER) may only egress via 127.0.0.1:$PROXY_PORT"
    ;;
  down)
    iptables -D OUTPUT -m owner --uid-owner "$UID_N" -o lo -p tcp --dport "$PROXY_PORT" -j ACCEPT || true
    iptables -D OUTPUT -m owner --uid-owner "$UID_N" -p udp --dport 53 -j ACCEPT || true
    iptables -D OUTPUT -m owner --uid-owner "$UID_N" -p tcp --dport 53 -j ACCEPT || true
    iptables -D OUTPUT -m owner --uid-owner "$UID_N" -j REJECT || true
    echo "jail down"
    ;;
  *) echo "usage: sudo $0 up|down   (AGENT_USER=$AGENT_USER PROXY_PORT=$PROXY_PORT)"; exit 1;;
esac
