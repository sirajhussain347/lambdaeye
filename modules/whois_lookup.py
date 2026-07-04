#!/usr/bin/env python3
"""
whois_lookup.py - Passive recon module: WHOIS lookup.
Performs a WHOIS lookup and returns parsed registration data (registrar,
creation/expiration dates, name servers, status, etc.).

Adapted to the LambdaEye contract: run(target, verbose=False) -> dict.
Original passive-recon logic by the Lambda passive team.

Dependency: python-whois (pip install python-whois)
"""

try:
    import whois as pywhois
except ImportError:
    pywhois = None


def _stringify(value):
    """Normalize whois fields (lists, dates, or None) into readable strings."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def run(target, verbose=False):
    """Contract entry point: returns the standard LambdaEye result dict."""
    results = {
        "module": "whois_lookup",
        "status": "success",
        "target": target,
        "data": {},
    }

    if pywhois is None:
        results["status"] = "error"
        results["data"]["error"] = "python-whois not installed (pip install python-whois)"
        print("[WHOIS]  ERROR: python-whois not installed.")
        return results

    try:
        data = pywhois.whois(target)
        fields = {
            "domain_name": _stringify(data.domain_name),
            "registrar": _stringify(data.registrar),
            "creation_date": _stringify(data.creation_date),
            "expiration_date": _stringify(data.expiration_date),
            "updated_date": _stringify(data.updated_date),
            "name_servers": _stringify(data.name_servers),
            "status": _stringify(data.status),
            "emails": _stringify(data.emails),
            "org": _stringify(getattr(data, "org", None)),
            "country": _stringify(getattr(data, "country", None)),
        }
        results["data"] = fields
    except Exception as e:
        results["status"] = "error"
        results["data"]["error"] = str(e)
        print(f"[WHOIS]  ERROR: {e}")
        return results

    # Live output
    print(f"[WHOIS]  Lookup for {target}:")
    labels = [
        ("Registrar", "registrar"), ("Organization", "org"),
        ("Country", "country"), ("Creation", "creation_date"),
        ("Expiration", "expiration_date"), ("Name Servers", "name_servers"),
    ]
    for label, key in labels:
        val = results["data"].get(key, "N/A")
        if val and val != "N/A":
            print(f"[WHOIS]    {label:<14}: {val}")
        elif verbose:
            print(f"[WHOIS]    {label:<14}: N/A")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"[*] Standalone WHOIS test on {t}\n")
    print(json.dumps(run(t, verbose=True), indent=2, default=str))
