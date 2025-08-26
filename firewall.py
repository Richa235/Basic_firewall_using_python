#!/usr/bin/env python3
"""
PyFirewall — a simple learning firewall in Python.
- Sniffs packets with Scapy and evaluates them against YAML rules.
- Default policy is "deny": if allow lists are present and none match, block.
- If a block rule matches, the packet is blocked (decision = BLOCK).
- In monitor mode we only log the decision.
- In enforce mode we *attempt* to add OS firewall rules to block the peer IP.
  - Windows: uses `netsh advfirewall` (requires Administrator).
  - Linux: uses `iptables` (requires root).
  - macOS: prints guidance (pf requires manual setup).

Run:
  python firewall.py --help
"""
import argparse
import ipaddress
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime

try:
    import yaml
except ModuleNotFoundError:
    print("Missing dependency: PyYAML. Install with `pip install -r requirements.txt`")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, conf
except ModuleNotFoundError:
    print("Missing dependency: scapy. Install with `pip install -r requirements.txt`")
    sys.exit(1)


def load_rules(path: str):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    rules = data.get("rules", {})
    policy = {
        "mode": data.get("mode", "monitor"),
        "interfaces": data.get("interfaces", []),
        "log_file": data.get("log_file", "logs/firewall.log"),
        "allow": {
            "ips": set(rules.get("allow", {}).get("ips", []) or []),
            "ports": set(rules.get("allow", {}).get("ports", []) or []),
            "protocols": set((rules.get("allow", {}).get("protocols", []) or [])),
        },
        "block": {
            "ips": set(rules.get("block", {}).get("ips", []) or []),
            "ports": set(rules.get("block", {}).get("ports", []) or []),
            "protocols": set((rules.get("block", {}).get("protocols", []) or [])),
        },
    }
    return policy


def setup_logging(log_file: str, verbose: bool):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handlers = [logging.FileHandler(log_file, encoding="utf-8")]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=handlers,
    )


def ip_in_list(ip_str: str, ip_list):
    for item in ip_list:
        try:
            if "/" in item:
                if ipaddress.ip_address(ip_str) in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if ip_str == item:
                    return True
        except Exception:
            # Ignore malformed rule entries
            continue
    return False


def packet_meta(pkt):
    # Return (src_ip, dst_ip, proto, sport, dport) best-effort
    src_ip = dst_ip = proto = sport = dport = None
    if IP in pkt:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

    if TCP in pkt:
        proto = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    elif ICMP in pkt or ICMPv6EchoRequest in pkt:
        proto = "ICMP"
    return src_ip, dst_ip, proto, sport, dport


def evaluate(pkt, policy):
    src_ip, dst_ip, proto, sport, dport = packet_meta(pkt)

    # Quick block checks
    if proto and proto in policy["block"]["protocols"]:
        return "BLOCK", {"reason": f"protocol:{proto}", "peer": src_ip or dst_ip}
    if src_ip and ip_in_list(src_ip, policy["block"]["ips"]):
        return "BLOCK", {"reason": f"src_ip:{src_ip}", "peer": src_ip}
    if dst_ip and ip_in_list(dst_ip, policy["block"]["ips"]):
        return "BLOCK", {"reason": f"dst_ip:{dst_ip}", "peer": dst_ip}
    if sport and sport in policy["block"]["ports"]:
        return "BLOCK", {"reason": f"sport:{sport}", "peer": src_ip}
    if dport and dport in policy["block"]["ports"]:
        return "BLOCK", {"reason": f"dport:{dport}", "peer": dst_ip}

    # Allow logic. If any allow list is non-empty, require at least one allow match.
    allow_sets_present = any([policy["allow"]["ips"], policy["allow"]["ports"], policy["allow"]["protocols"]])
    if allow_sets_present:
        allow_hit = False
        if proto and policy["allow"]["protocols"] and proto in policy["allow"]["protocols"]:
            allow_hit = True
        if not allow_hit and src_ip and ip_in_list(src_ip, policy["allow"]["ips"]):
            allow_hit = True
        if not allow_hit and dst_ip and ip_in_list(dst_ip, policy["allow"]["ips"]):
            allow_hit = True
        if not allow_hit and sport and sport in policy["allow"]["ports"]:
            allow_hit = True
        if not allow_hit and dport and dport in policy["allow"]["ports"]:
            allow_hit = True

        if not allow_hit:
            return "BLOCK", {"reason": "default_deny", "peer": src_ip or dst_ip}

    return "ALLOW", {"reason": "rule_match_or_allow_all", "peer": src_ip or dst_ip}


def os_block_ip(peer_ip: str):
    system = platform.system().lower()
    try:
        if system.startswith("win"):
            # Add inbound and outbound block rules
            for direction in ("in", "out"):
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=PyFirewallBlock_{peer_ip}_{direction}",
                    f"dir={direction}", "action=block", f"remoteip={peer_ip}"
                ], check=False, capture_output=True)
            return True, "windows"
        elif system == "linux":
            # Block via iptables (requires root)
            cmds = [
                ["iptables", "-A", "INPUT", "-s", peer_ip, "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", peer_ip, "-j", "DROP"],
            ]
            ok = True
            for cmd in cmds:
                res = subprocess.run(cmd, check=False, capture_output=True)
                ok = ok and (res.returncode == 0)
            return ok, "linux"
        elif system == "darwin":
            # pf requires pre-created tables; give guidance instead of failing.
            return False, "macos_pf_not_configured"
        else:
            return False, "unsupported_os"
    except Exception as e:
        return False, f"error:{e}"


def main():
    parser = argparse.ArgumentParser(description="PyFirewall — basic packet filter with Scapy + YAML rules")
    parser.add_argument("-r", "--rules", default="rules.yaml", help="Path to rules YAML")
    parser.add_argument("-i", "--interface", action="append", help="Interface to sniff (can repeat). Default: from YAML or all up interfaces")
    parser.add_argument("--enforce", action="store_true", help="Force enforce mode (overrides YAML)")
    parser.add_argument("--monitor", action="store_true", help="Force monitor mode (overrides YAML)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log to console as well as file")
    args = parser.parse_args()

    policy = load_rules(args.rules)
    if args.enforce and args.monitor:
        print("Choose either --enforce or --monitor, not both.")
        sys.exit(2)
    if args.enforce:
        policy["mode"] = "enforce"
    if args.monitor:
        policy["mode"] = "monitor"

    setup_logging(policy["log_file"], verbose=args.verbose)
    logging.info("PyFirewall starting in %s mode", policy["mode"])

    interfaces = args.interface or policy.get("interfaces") or []
    if not interfaces:
        interfaces = None  # sniff decides

    # Ensure we're in promiscuous sniff mode only if supported
    conf.sniff_promisc = True

    def handle(pkt):
        try:
            decision, info = evaluate(pkt, policy)
            src_ip, dst_ip, proto, sport, dport = packet_meta(pkt)
            msg = f"{decision} | proto={proto} {src_ip}:{sport} -> {dst_ip}:{dport} | reason={info['reason']}"
            logging.info(msg)

            if decision == "BLOCK" and policy["mode"] == "enforce" and info.get("peer"):
                ok, how = os_block_ip(info["peer"])
                if ok:
                    logging.info("Enforce: added OS firewall block for %s via %s", info["peer"], how)
                else:
                    logging.warning("Enforce failed for %s (%s). Running in monitor-only for this packet.", info["peer"], how)
        except Exception as e:
            logging.exception("Error handling packet: %s", e)

    try:
        sniff(iface=interfaces, prn=handle, store=False)
    except PermissionError:
        print("Permission error: sniffing requires Administrator/root privileges and npcap (Windows) or libpcap (Linux/macOS).")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("PyFirewall stopped by user.")
        print("\nPyFirewall stopped. Logs saved at", policy["log_file"])


if __name__ == "__main__":
    main()
