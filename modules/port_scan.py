#!/usr/bin/env python3
"""
port_scan.py - Active recon module: socket-based port scanner.
Checks which TCP ports are open on a target. Supports common ports,
top-100, top-1000, or a custom range. Part of the LambdaEye tool.

Contract: exposes run(target, verbose=False, ports=None) and returns a dict.
"""

import socket

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-alt",
}

# Top 100 most common ports (nmap-style short list).
TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 20, 69, 123, 161, 162,
    389, 636, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3000,
    3128, 3268, 4444, 5000, 5060, 5432, 5601, 5985, 5986, 6379, 6443, 7001,
    8000, 8008, 8081, 8181, 8291, 8834, 9000, 9090, 9200, 9300, 10000,
    11211, 27017, 27018, 50000, 465, 587, 514, 873, 902, 990, 1080, 1194,
    1701, 1900, 2000, 2121, 3690, 4022, 4433, 5222, 5269, 5555, 5672, 5800,
    6000, 6667, 7000, 7070, 7443, 8009, 8010, 8443, 8880, 9091, 9999,
]


def scan_port(ip, port, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def _resolve_port_list(ports, port_range, profile):
    """Decide which ports to scan based on the options given."""
    if ports:
        return list(ports)
    if port_range:
        # port_range is a string like "1-1024"
        try:
            start, end = port_range.split("-")
            return list(range(int(start), int(end) + 1))
        except Exception:
            return list(COMMON_PORTS.keys())
    if profile == "top100":
        return sorted(set(TOP_100))
    if profile == "top1000":
        return list(range(1, 1001))
    return list(COMMON_PORTS.keys())


def run(target, verbose=False, ports=None, port_range=None, profile="common"):
    """
    Main entry point (matches the team contract).
    Improvement 2: supports profile='common'|'top100'|'top1000' and
    port_range='1-65535'.
    """
    results = {
        "module": "port_scan", "status": "success", "target": target,
        "data": {"resolved_ip": None, "open_ports": [], "scanned_count": 0},
    }

    try:
        ip = socket.gethostbyname(target)
        results["data"]["resolved_ip"] = ip
    except socket.gaierror:
        results["status"] = "error"
        results["data"]["error"] = f"Could not resolve host: {target}"
        print(f"[PORTS]  ERROR: could not resolve host -> {target}")
        return results

    ports_to_scan = _resolve_port_list(ports, port_range, profile)
    results["data"]["scanned_count"] = len(ports_to_scan)

    if verbose:
        print(f"[PORTS] Resolved {target} -> {ip}")
        print(f"[PORTS] Scanning {len(ports_to_scan)} ports...\n")

    for port in ports_to_scan:
        if scan_port(ip, port):
            service = COMMON_PORTS.get(port, "unknown")
            results["data"]["open_ports"].append({"port": port, "service": service})
            print(f"[PORTS] Port {port:<5} OPEN   ({service})")
        elif verbose:
            print(f"[PORTS] Port {port:<5} closed")

    found = len(results["data"]["open_ports"])
    if verbose:
        print(f"\n[PORTS] Done. {found} open port(s) found.")
    elif found == 0:
        print("[PORTS] No open ports found.")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"[*] Standalone port scan on {t}\n")
    print(json.dumps(run(t, verbose=True), indent=2))
