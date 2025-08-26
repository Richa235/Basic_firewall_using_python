# PyFirewall (Basic Firewall Using Python)

A small, educational packet filter built with **Scapy** + **YAML** rules.
Runs in **monitor** mode by default, and can optionally **enforce** blocks
by adding OS firewall rules (Windows `netsh`, Linux `iptables`).

## Project Structure
```
basic_firewall_python/
├─ firewall.py
├─ rules.yaml
├─ requirements.txt
└─ logs/
```

## Prerequisites
- Python 3.9+
- Admin/root privileges to sniff packets
- Packet capture driver:
  - **Windows:** Install [Npcap](https://npcap.com/)
  - **Linux/macOS:** libpcap is usually preinstalled
- VS Code with Python extension (optional but recommended)

## Setup
```bash
pip install -r requirements.txt
```

## Run (Monitor Mode)
```bash
python firewall.py -v
```
- Press `Ctrl+C` to stop. Logs are written to `logs/firewall.log`.

## Run (Enforce Blocks)
```bash
python firewall.py --enforce -v
```
- On **Windows**, adds inbound/outbound block rules for offending IPs.
- On **Linux**, adds `iptables` DROP rules for offending IPs.
- On **macOS**, the script will print guidance (pf requires manual setup).

## Customize Rules
Edit `rules.yaml`. Precedence: any **block** match wins. If any allow lists
are non-empty, the default policy is **deny** (block) unless an allow list matches.

## Notes
- This is for learning/demo purposes, not a production firewall.
- Removing OS-level rules:
  - Windows: remove in *Windows Defender Firewall with Advanced Security* or via `netsh advfirewall firewall delete rule name=PyFirewallBlock_*`
  - Linux: `iptables -L --line-numbers` then `iptables -D ...` to delete.
