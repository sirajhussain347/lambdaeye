#!/usr/bin/env python3
"""
subdomain_enum.py - Passive recon module: subdomain enumeration.
Passive subdomain discovery via public OSINT sources: crt.sh (certificate
transparency), AlienVault OTX (passive DNS), HackerTarget, and RapidDNS.
No brute forcing or active probing -- purely passive.

Adapted to the LambdaEye contract: run(target, verbose=False) -> dict.
Original passive-recon logic by the Lambda passive team.

Dependency: requests (pip install requests)
"""

import re
import time
import requests

TIMEOUT = 30
MAX_RETRIES = 2
RETRY_BACKOFF = 3  # seconds between retries
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Accept": "application/json",
}
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


def _request_with_retry(url, verbose, source_name, headers=None, timeout=TIMEOUT):
    """GET *url* with automatic retries on transient HTTP errors."""
    hdrs = dict(HEADERS)
    if headers:
        hdrs.update(headers)
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=hdrs, timeout=timeout)
            if resp.status_code == 429:
                # Rate-limited — back off and retry.
                if verbose:
                    print(f"[SUBDOM] {source_name}: rate-limited (429), "
                          f"retrying in {RETRY_BACKOFF}s "
                          f"(attempt {attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < MAX_RETRIES:
                if verbose:
                    print(f"[SUBDOM] {source_name}: attempt {attempt} failed "
                          f"({e}), retrying in {RETRY_BACKOFF}s…")
                time.sleep(RETRY_BACKOFF)
    if verbose:
        print(f"[SUBDOM] {source_name} query failed after {MAX_RETRIES} "
              f"attempts: {last_err}")
    return None


def _query_crtsh(domain, verbose):
    subs = set()
    resp = _request_with_retry(
        CRTSH_URL.format(domain=domain), verbose, "crt.sh"
    )
    if resp is None:
        return subs
    try:
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    subs.add(name)
    except ValueError as e:
        if verbose:
            print(f"[SUBDOM] crt.sh: failed to parse JSON: {e}")
    return subs


def _query_otx(domain, verbose):
    subs = set()
    resp = _request_with_retry(
        OTX_URL.format(domain=domain), verbose, "AlienVault OTX"
    )
    if resp is None:
        return subs
    try:
        for entry in resp.json().get("passive_dns", []):
            host = entry.get("hostname")
            if host and domain in host:
                subs.add(host)
    except ValueError as e:
        if verbose:
            print(f"[SUBDOM] AlienVault OTX: failed to parse JSON: {e}")
    return subs


def _query_hackertarget(domain, verbose):
    subs = set()
    resp = _request_with_retry(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        verbose, "HackerTarget"
    )
    if resp is None:
        return subs
    text = resp.text.strip()
    if text and "API count exceed" not in text:
        for line in text.split("\n"):
            host = line.split(",")[0].strip()
            if host and domain in host:
                subs.add(host)
    return subs


def _query_rapiddns(domain, verbose):
    """Query rapiddns.io (replaces the defunct Anubis / jldc.me API)."""
    subs = set()
    resp = _request_with_retry(
        f"https://rapiddns.io/subdomain/{domain}?full=1#result",
        verbose, "RapidDNS",
        headers={"Accept": "text/html"},
    )
    if resp is None:
        return subs
    try:
        # RapidDNS returns an HTML page; extract subdomain names from the
        # table cells that contain domain strings.
        for match in re.findall(
            r"(?:target=\"_blank\">|<td>)([a-zA-Z0-9._-]+\." +
            re.escape(domain) + r")</(?:a|td)>", resp.text
        ):
            name = match.strip().lower()
            if name and domain in name:
                subs.add(name)
    except Exception as e:
        if verbose:
            print(f"[SUBDOM] RapidDNS parse failed: {e}")
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
    rapiddns = _query_rapiddns(target, verbose)

    combined = sorted(crtsh | otx | ht | rapiddns)

    results["data"]["total_found"] = len(combined)
    results["data"]["subdomains"] = combined
    results["data"]["sources"] = {
        "crt.sh": len(crtsh),
        "alienvault_otx": len(otx),
        "hackertarget": len(ht),
        "rapiddns": len(rapiddns),
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
