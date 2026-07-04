#!/usr/bin/env python3
"""
port_scan.py — Active recon module: socket-based port scanner.

Checks which TCP ports are open on a target by attempting a connection
to each one. Part of the LambdaRecon tool (active recon).

Contract: exposes run(target, verbose=False) and returns a dict.
"""

import socket    # built-in: lets us open network connections
import time      # built-in: to timestamp the scan


# A small set of the most common ports, with what usually runs on them.
# We scan these by default so a beginner run is fast and readable.
COMMON_PORTS = {
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-alt",
}


def scan_port(ip, port, timeout=1.0):
    """
    Try to connect to ONE port on the target IP.
    Returns True if the port is open, False otherwise.
    """
    # AF_INET = IPv4, SOCK_STREAM = TCP (the reliable, connection-based type).
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Don't wait forever on a dead port — give up after `timeout` seconds.
    sock.settimeout(timeout)

    # connect_ex returns 0 if the connection succeeded (port open),
    # or an error number if it failed (port closed/filtered).
    # We use connect_ex instead of connect() because it doesn't crash
    # on failure — it just returns a code, which is easier to handle.
    result = sock.connect_ex((ip, port))

    sock.close()   # always close the door behind us

    return result == 0


def run(target, verbose=False, ports=None):
    """
    Main entry point for this module (matches the team contract).

    target  : domain or IP string, e.g. "scanme.nmap.org"
    verbose : if True, print each port as we check it
    ports   : optional list of ports to scan; defaults to COMMON_PORTS

    Returns a dict of results.
    """
    # This is the standard result skeleton every module returns,
    # so the report module can treat all modules the same way.
    results = {
        "module": "port_scan",
        "status": "success",
        "target": target,
        "data": {
            "resolved_ip": None,
            "open_ports": [],
            "scanned_count": 0,
        },
    }

    # STEP 1: turn the domain name into an IP address.
    # Sockets connect to IPs, not names, so we resolve first.
    # This also satisfies the task's "IP resolution details" requirement.
    try:
        ip = socket.gethostbyname(target)
        results["data"]["resolved_ip"] = ip
    except socket.gaierror:
        # Couldn't resolve the name — record the failure and stop.
        results["status"] = "error"
        results["data"]["error"] = f"Could not resolve host: {target}"
        return results

    if verbose:
        print(f"[PORTS] Resolved {target} -> {ip}")
        print(f"[PORTS] Scanning {len(ports or COMMON_PORTS)} ports...\n")

    # STEP 2: decide which ports to scan.
    ports_to_scan = ports if ports else list(COMMON_PORTS.keys())
    results["data"]["scanned_count"] = len(ports_to_scan)

    # STEP 3: try each port, one by one.
    for port in ports_to_scan:
        is_open = scan_port(ip, port)

        if is_open:
            service = COMMON_PORTS.get(port, "unknown")
            port_info = {"port": port, "service": service}
            results["data"]["open_ports"].append(port_info)

            # Always announce an OPEN port (this is the important signal).
            print(f"[PORTS] Port {port:<5} OPEN   ({service})")
        elif verbose:
            # Only mention CLOSED ports in verbose mode, to avoid noise.
            print(f"[PORTS] Port {port:<5} closed")

    if verbose:
        found = len(results["data"]["open_ports"])
        print(f"\n[PORTS] Done. {found} open port(s) found.")

    return results


# Lets you test THIS module by itself, without the full tool:
#   python3 modules/port_scan.py
if __name__ == "__main__":
    import json
    test_target = "scanme.nmap.org"   # Nmap's legal test host
    print(f"[*] Standalone test scan on {test_target}\n")
    output = run(test_target, verbose=True)
    print("\n[*] Returned dictionary:")
    print(json.dumps(output, indent=2))
