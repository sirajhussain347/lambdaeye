#!/usr/bin/env python3
"""
Improved LambdaEye passive subdomain enumeration module.
Compatible with existing LambdaEye interface.
"""
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 10
MAX_RETRIES = 2
RETRY_BACKOFF = 2

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
}

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


def _request_with_retry(url, verbose, source_name, headers=None, timeout=TIMEOUT):
    hdrs = dict(HEADERS)
    if headers:
        hdrs.update(headers)
    last = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(url, headers=hdrs, timeout=timeout)
            if verbose:
                print(f"[SUBDOM] {source_name}: HTTP {r.status_code}")
            if r.status_code == 429:
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            last = e
            if attempt < MAX_RETRIES:
                if verbose:
                    print(f"[SUBDOM] {source_name}: retry {attempt}")
                time.sleep(RETRY_BACKOFF)
    if verbose:
        print(f"[SUBDOM] {source_name}: failed ({last})")
    return None


def _query_crtsh(domain, verbose):
    out=set()
    r=_request_with_retry(CRTSH_URL.format(domain=domain),verbose,"crt.sh")
    if not r: return out
    try:
        for e in r.json():
            for n in e.get("name_value","").splitlines():
                n=n.strip().lstrip("*.").lower()
                if n.endswith(domain.lower()):
                    out.add(n)
    except Exception as e:
        if verbose: print(e)
    return out


def _query_otx(domain, verbose):
    out=set()
    r=_request_with_retry(OTX_URL.format(domain=domain),verbose,"AlienVault OTX")
    if not r: return out
    try:
        for e in r.json().get("passive_dns",[]):
            h=(e.get("hostname") or "").lower()
            if h.endswith(domain.lower()):
                out.add(h)
    except Exception as e:
        if verbose: print(e)
    return out


def _query_hackertarget(domain, verbose):
    out=set()
    r=_request_with_retry(f"https://api.hackertarget.com/hostsearch/?q={domain}",verbose,"HackerTarget")
    if not r: return out
    if "API count exceeded" in r.text:
        return out
    for line in r.text.splitlines():
        h=line.split(",")[0].strip().lower()
        if h.endswith(domain.lower()):
            out.add(h)
    return out


def _query_rapiddns(domain, verbose):
    out=set()
    r=_request_with_retry(f"https://rapiddns.io/subdomain/{domain}?full=1#result",verbose,"RapidDNS",headers={"Accept":"text/html"})
    if not r: return out
    pattern=rf'([A-Za-z0-9._-]+\.{re.escape(domain)})'
    for m in re.findall(pattern,r.text,re.I):
        out.add(m.lower())
    return out


def run(target, verbose=False):
    results={
        "module":"subdomain_enum",
        "status":"success",
        "target":target,
        "data":{"total_found":0,"subdomains":[],"sources":{}}
    }
    print(f"[SUBDOM] Querying passive sources for {target}...")

    funcs={
        "crt.sh":_query_crtsh,
        "alienvault_otx":_query_otx,
        "hackertarget":_query_hackertarget,
        "rapiddns":_query_rapiddns,
    }

    combined=set()
    counts={}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs={ex.submit(fn,target,verbose):name for name,fn in funcs.items()}
        for fut in as_completed(futs):
            name=futs[fut]
            try:
                data=fut.result()
            except Exception:
                data=set()
            counts[name]=len(data)
            combined.update(data)

    subs=sorted(combined)
    results["data"]["total_found"]=len(subs)
    results["data"]["subdomains"]=subs
    results["data"]["sources"]=counts

    print(f"[SUBDOM] Found {len(subs)} unique subdomain(s).")
    print("[SUBDOM] Sources -> "+", ".join(f"{k}: {counts.get(k,0)}" for k in funcs))
    if subs:
        for s in subs:
            print(f"[SUBDOM]   - {s}")
    elif verbose:
        print("[SUBDOM]   (none discovered)")
    return results


if __name__=="__main__":
    import sys
    t=sys.argv[1] if len(sys.argv)>1 else "example.com"
    run(t,True)
