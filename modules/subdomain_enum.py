#!/usr/bin/env python3
"""
subdomain_enum.py - Passive recon module: subdomain enumeration.
Passive subdomain discovery via public OSINT sources: crt.sh (certificate
transparency), AlienVault OTX (passive DNS), HackerTarget, and Anubis.
No brute forcing or active probing -- purely passive.

Adapted to the LambdaEye contract: run(target, verbose=False) -> dict.
Original passive-recon logic by the Lambda passive team.

Dependency: requests (pip install requests)
"""

import requests

TIMEOUT = 15
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


def _query_crtsh(domain, verbose):
    subs = set()
    try:
        resp = requests.get(CRTSH_URL.format(domain=domain), timeout=TIMEOUT)
        resp.raise_for_status()
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    subs.add(name)
    except Exception as e:
        if verbose:
            print(f"[SUBDOM] crt.sh query failed: {e}")
    return subs


def _query_otx(domain, verbose):
    subs = set()
    try:
        resp = requests.get(OTX_URL.format(domain=domain), timeout=TIMEOUT)
        resp.raise_for_status()
        for entry in resp.json().get("passive_dns", []):
            host = entry.get("hostname")
            if host and domain in host:
                subs.add(host)
    except Exception as e:
        if verbose:
            print(f"[SUBDOM] AlienVault OTX query failed: {e}")
    return subs


def _query_hackertarget(domain, verbose):
    subs = set()
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                            timeout=TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()
        if text and "API count exceed" not in text:
            for line in text.split("\n"):
                host = line.split(",")[0].strip()
                if host and domain in host:
                    subs.add(host)
    except Exception as e:
        if verbose:
            print(f"[SUBDOM] HackerTarget query failed: {e}")
    return subs


def _query_anubis(domain, verbose):
    subs = set()
    try:
        resp = requests.get(f"https://jldc.me/anubis/subdomains/{domain}",
                            timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            for sub in data:
                sub = sub.strip()
                if sub and domain in sub:
                    subs.add(sub)
    except Exception as e:
        if verbose:
            print(f"[SUBDOM] Anubis query failed: {e}")
    return subs


def run(target, verbose=False):
    """Contract entry point: returns the standard LambdaEye result dict."""
    results = {
        "module": "subdomain_enum",
        "status": "success",
        "target": target,
        "data": {"total_found": 0, "subdomains": [], "sources": {}},
    }

    print(f"[SUBDOM] Querying passive sources for {target}...")

    crtsh = _query_crtsh(target, verbose)
    otx = _query_otx(target, verbose)
    ht = _query_hackertarget(target, verbose)
    anubis = _query_anubis(target, verbose)

    combined = sorted(crtsh | otx | ht | anubis)

    results["data"]["total_found"] = len(combined)
    results["data"]["subdomains"] = combined
    results["data"]["sources"] = {
        "crt.sh": len(crtsh),
        "alienvault_otx": len(otx),
        "hackertarget": len(ht),
        "anubis": len(anubis),
    }

    # Live output
    print(f"[SUBDOM] Found {len(combined)} unique subdomain(s).")
    src = results["data"]["sources"]
    print(f"[SUBDOM] Sources -> " +
          ", ".join(f"{k}: {v}" for k, v in src.items()))
    if combined:
        for sub in combined:
            print(f"[SUBDOM]   - {sub}")
    elif verbose:
        print("[SUBDOM]   (none discovered)")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"[*] Standalone subdomain test on {t}\n")
    out = run(t, verbose=True)
    print(f"\n[*] Total: {out['data']['total_found']}")
