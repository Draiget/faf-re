#!/bin/bash
# Makes the runner's apt mirrors reachable before `apt-get update`.
# On 2026-11-11 GitHub's ubuntu-24.04 runners couldn't resolve any Ubuntu archive host for hours
# (azure.archive.ubuntu.com, archive.ubuntu.com, security.ubuntu.com: "Temporary failure resolving"), while
# packages.microsoft.com resolved and the same names resolved everywhere else. The runner's own resolver was
# failing, not the names. A host that doesn't resolve is looked up through public DNS (1.1.1.1, then 8.8.8.8) and
# pinned in /etc/hosts; only a host public DNS can't resolve either is dropped from the mirror list.
# Nothing changes while every mirror resolves.
list=/etc/apt/apt-mirrors.txt
hosts=$( { [ -f "$list" ] && grep -o -E 'https?://[^/[:space:]]+' "$list"
           grep -h -o -E '^(deb|URIs:)[^#]*https?://[^/[:space:]]+' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null \
             | grep -o -E 'https?://[^/[:space:]]+'; } | sed -E 's#^https?://##' | sort -u)

# The IPv4 addresses public DNS gives for $1, one per line; empty when none answers.
public_lookup() {
  local server ips
  for server in 1.1.1.1 8.8.8.8; do
    if command -v dig > /dev/null; then
      ips=$(dig +short +time=3 +tries=2 A "$1" "@$server" 2>/dev/null | grep -E '^[0-9.]+$')
    else
      ips=$(python3 - "$1" "$server" << 'EOF'
import random, socket, struct, sys
name, server = sys.argv[1], sys.argv[2]
qid = random.randrange(65536)
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(
    bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, (server, 53)); r = s.recv(4096)
except OSError:
    sys.exit(0)
an = struct.unpack(">H", r[6:8])[0]; i = 12
while r[i]: i += r[i] + 1
i += 5
for _ in range(an):
    i = i + 2 if r[i] & 0xC0 == 0xC0 else r.index(0, i) + 1
    t, _, _, n = struct.unpack(">HHIH", r[i:i + 10]); i += 10
    if t == 1 and n == 4: print(".".join(map(str, r[i:i + 4])))
    i += n
EOF
)
    fi
    [ -n "$ips" ] && { echo "$ips"; return; }
  done
}

for host in $hosts; do
  getent hosts "$host" > /dev/null && continue
  ips=$(public_lookup "$host")
  if [ -n "$ips" ]; then
    echo "apt-mirrors: $host doesn't resolve on the runner; pinned to $(echo $ips) from public DNS"
    for ip in $ips; do echo "$ip $host"; done | sudo tee -a /etc/hosts > /dev/null
    timeout 10 bash -c "exec 3<>/dev/tcp/$host/80" 2> /dev/null \
      && echo "apt-mirrors: $host:80 accepts connections" \
      || echo "apt-mirrors: $host:80 doesn't accept connections either; the network, not DNS, is failing"
  elif [ -f "$list" ] && grep -q "://$host/" "$list"; then
    echo "apt-mirrors: $host doesn't resolve, not even through public DNS; dropped from $list"
    sudo sed -i "\#://$host/#d" "$list"
  else
    echo "apt-mirrors: $host doesn't resolve, not even through public DNS"
  fi
done
if [ -f "$list" ] && ! grep -q -E 'https?://' "$list"; then
  echo "apt-mirrors: no mirror in $list resolves; apt-get will fail"
fi
exit 0
