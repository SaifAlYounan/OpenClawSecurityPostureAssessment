# HITL Defenses Reference

Based on "Don't Let the Claw Grip Your Hand" (Shan et al., 2026).

## HITL Environment Variables

| Variable | What It Does | Value |
|----------|-------------|-------|
| `OPENCLAW_HITL_POLICY` | Defense strictness | `strict` / `standard` / `permissive` |
| `OPENCLAW_HITL_ENFORCE_ALLOWLIST` | Only pre-approved commands run | `1` |
| `OPENCLAW_HITL_SEMANTIC_JUDGE` | AI intent analysis | `1` |
| `OPENCLAW_HITL_SANDBOX_REQUIRED` | Force sandbox boundaries | `1` |
| `OPENCLAW_HITL_APPROVAL_MODE` | Handle flagged commands | `deny` / `allow` / `prompt` |

## Setting via systemd (Agent Cannot Undo)

```bash
sudo systemctl edit --force openclaw-gateway.service
```
```ini
[Service]
Environment="OPENCLAW_HITL_POLICY=strict"
Environment="OPENCLAW_HITL_ENFORCE_ALLOWLIST=1"
Environment="OPENCLAW_HITL_SEMANTIC_JUDGE=1"
Environment="OPENCLAW_HITL_SANDBOX_REQUIRED=1"
Environment="OPENCLAW_HITL_APPROVAL_MODE=deny"
```
```bash
sudo systemctl daemon-reload
sudo systemctl --user -M USERNAME@ restart openclaw-gateway.service
```

## OS-Level Defenses

### Outbound Network Restriction (Operator as root)
```bash
AGENT_UID=$(id -u AGENT_USER)
sudo iptables -A OUTPUT -o lo -m owner --uid-owner $AGENT_UID -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner $AGENT_UID -j ACCEPT
sudo iptables -A OUTPUT -d ANTHROPIC_IP/32 -m owner --uid-owner $AGENT_UID -j ACCEPT
sudo iptables -A OUTPUT -d TELEGRAM_IP/32 -m owner --uid-owner $AGENT_UID -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -m owner --uid-owner $AGENT_UID -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner $AGENT_UID -j DROP
sudo apt-get install iptables-persistent -y && sudo netfilter-persistent save
```

### File Permissions
```bash
sudo chmod 700 /root
sudo chmod 600 /path/to/config/with/api/key
```

### Container Isolation (Architectural)
```bash
docker run -d --name openclaw --user 1000:1000 --read-only --tmpfs /tmp \
  -v /home/AGENT_USER/workspace:/workspace:rw \
  --network=restricted openclaw-image
```

## Priority

| # | Defense | Who |
|---|---------|-----|
| 1 | Non-root user | Operator |
| 2 | No sudo | Operator |
| 3 | Outbound network lock | Operator |
| 4 | HITL strict via systemd | Operator |
| 5 | Container isolation | Operator |
| 6 | File permission hardening | Operator |
