#!/usr/bin/env python3
"""
whois_lookup.py - Passive recon module: WHOIS lookup.
Performs a WHOIS lookup and returns parsed registration data (registrar,
creation/expiration dates, name servers, status, etc.).
Adapted to the LambdaEye contract: run(target, verbose=False) -> dict.
Original passive-recon logic by the Lambda passive team.
Dependency: python-whois (pip install python-whois)
"""
import re
import socket

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



PKNIC_SERVER = "whois.pknic.net.pk"
PK_REGEX = {
    "domain_name": r"Domain:\s*(.+)",
    "status": r"Status:\s*(.+)",
    "creation_date": r"Creation Date:\s*(.+)",
    "expiration_date": r"Expiry Date:\s*(.+)",
    "name_servers": r"Name Server:\s*(.+)",
}


def _raw_whois_query(server, domain, timeout=10):
    """Manual RFC 3912 WHOIS query for TLDs python-whois can't parse."""
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((domain + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def _parse_pk(text):
    fields = {}
    for key, pattern in PK_REGEX.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if not matches:
            fields[key] = None
        elif key == "name_servers":
            fields[key] = ", ".join(m.strip() for m in matches)
        else:
            fields[key] = matches[0].strip()
    return fields


def _run_pk(target, verbose):
    """WHOIS lookup path for .pk / .com.pk / .net.pk / etc. domains."""
    results = {
        "module": "whois_lookup",
        "status": "success",
        "target": target,
        "data": {},
    }
    try:
        text = _raw_whois_query(PKNIC_SERVER, target)
    except (socket.timeout, socket.error, OSError) as e:
        results["status"] = "error"
        results["data"]["error"] = f"PKNIC WHOIS connection failed: {e}"
        print(f"[WHOIS]  ERROR: {results['data']['error']}")
        return results

    parsed = _parse_pk(text)
    if not parsed.get("domain_name") or "not registered" in text.lower():
        results["status"] = "not_found"
        results["data"]["error"] = "WHOIS: No registration record found."
        print(f"[WHOIS]  Domain not found: {target}")
        return results

    results["data"] = {
        "domain_name": _stringify(parsed.get("domain_name")),
        "registrar": "PKNIC",
        "creation_date": _stringify(parsed.get("creation_date")),
        "expiration_date": _stringify(parsed.get("expiration_date")),
        "updated_date": "N/A",
        "name_servers": _stringify(parsed.get("name_servers")),
        "status": _stringify(parsed.get("status")),
        "emails": "N/A",
        "org": "N/A",
        "country": "PK",
    }

    print(f"[WHOIS]  Lookup for {target}:")
    labels = [
        ("Status", "status"), ("Creation", "creation_date"),
        ("Expiration", "expiration_date"), ("Name Servers", "name_servers"),
    ]
    for label, key in labels:
        val = results["data"].get(key, "N/A")
        if val and val != "N/A":
            print(f"[WHOIS]    {label:<14}: {val}")
        elif verbose:
            print(f"[WHOIS]    {label:<14}: N/A")
    return results


def run(target, verbose=False):
    """Contract entry point: returns the standard LambdaEye result dict."""
    results = {
        "module": "whois_lookup",
        "status": "success",
        "target": target,
        "data": {},
    }
    # PKNIC (.pk) has no dedicated parser in python-whois and a different
    # field format -- handle it separately with a raw WHOIS query.
    tld = target.lower().rstrip(".").split(".")[-1]
    if tld == "pk":
        return _run_pk(target, verbose)
    if pywhois is None:
        results["status"] = "error"
        results["data"]["error"] = "python-whois not installed (pip install python-whois)"
        print("[WHOIS]  ERROR: python-whois not installed.")
        return results
    try:
        data = pywhois.whois(target)
       
        if not data.domain_name:
            results["status"] = "not_found"
            results["data"]["error"] = "WHOIS: No registration record found."
            print(f"[WHOIS]  Domain not found: {target}")
            return results
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
        err_text = str(e)
       
        _NOT_FOUND_MARKERS = (
            "no match for",
            "not found",
            "no data found",
            "no entries found",
            "domain not found",
            "no information available",
        )
        if any(marker in err_text.lower() for marker in _NOT_FOUND_MARKERS):
            results["status"] = "not_found"
            results["data"]["error"] = "WHOIS: No registration record found."
            print(f"[WHOIS]  Domain not found: {target}")
        else:
            results["status"] = "error"
            results["data"]["error"] = err_text
            print(f"[WHOIS]  ERROR: {err_text}")
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
