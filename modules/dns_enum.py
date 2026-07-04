#!/usr/bin/env python3
"""
dns_enum.py - Passive recon module: DNS enumeration.
Queries common DNS record types (A, MX, TXT, NS) and resolves the domain's
primary IP address.

Adapted to the LambdaEye contract: run(target, verbose=False) -> dict.
Original passive-recon logic by the Lambda passive team.

Dependency: dnspython (pip install dnspython)
"""

import socket

try:
    import dns.resolver
except ImportError:
    dns = None

RECORD_TYPES = ["A", "MX", "TXT", "NS"]


def run(target, verbose=False):
    """Contract entry point: returns the standard LambdaEye result dict."""
    results = {
        "module": "dns_enum",
        "status": "success",
        "target": target,
        "data": {"resolved_ip": None},
    }

    if dns is None:
        results["status"] = "error"
        results["data"]["error"] = "dnspython not installed (pip install dnspython)"
        print("[DNS]    ERROR: dnspython not installed.")
        return results

    resolver = dns.resolver.Resolver()

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            results["data"][rtype] = [a.to_text() for a in answers]
        except dns.resolver.NoAnswer:
            results["data"][rtype] = []
        except dns.resolver.NXDOMAIN:
            results["status"] = "error"
            results["data"]["error"] = "NXDOMAIN (domain does not exist)"
            print(f"[DNS]    ERROR: {target} does not exist (NXDOMAIN)")
            return results
        except Exception as e:
            results["data"][rtype] = []
            if verbose:
                print(f"[DNS]    ({rtype} lookup error: {e})")

    # Resolve primary IP (feeds the report's IP resolution detail)
    try:
        results["data"]["resolved_ip"] = socket.gethostbyname(target)
    except Exception:
        results["data"]["resolved_ip"] = "N/A"

    # Live output
    print(f"[DNS]    Records for {target}:")
    ip = results["data"].get("resolved_ip")
    if ip and ip != "N/A":
        print(f"[DNS]      Resolved IP : {ip}")
    for rtype in RECORD_TYPES:
        vals = results["data"].get(rtype, [])
        if vals:
            for v in vals:
                print(f"[DNS]      {rtype:<4} {v}")
        elif verbose:
            print(f"[DNS]      {rtype:<4} (none)")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"[*] Standalone DNS test on {t}\n")
    print(json.dumps(run(t, verbose=True), indent=2))
