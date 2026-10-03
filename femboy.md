#!/bin/bash
PORT=${1:-8080}
echo "== 1. container running? =="
nerdctl ps | grep -i keycloak
echo "== 2. answers locally? (want 200/302) =="
curl -s -o /dev/null -m 5 -w "%{http_code}\n" http://localhost:$PORT/
echo "== 3. ip forwarding (MUST be 1) =="
sysctl net.ipv4.ip_forward
grep -rs "ip_forward" /etc/sysctl.conf /etc/sysctl.d/
echo "== 4. ufw =="
ufw status verbose | head -5
echo "== 5. FORWARD chain (policy + drop counters) =="
iptables -L FORWARD -n -v --line-numbers | head -15
echo "== 6. port redirect rule for $PORT (must exist) =="
iptables -t nat -S | grep -- "--dport $PORT"
echo "== 7. nftables tables =="
nft list tables
