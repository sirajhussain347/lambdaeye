#!/usr/bin/env python3
"""
tech_detect.py - Active recon module: web technology detection.
Production-ready version with rigorous fingerprinting, SSL retries, and evidence trailing.
"""

import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Category Constants ---
WEB_SERVER = "Web Server"
LANGUAGE = "Programming Language"
FRAMEWORK = "Framework"
CMS = "CMS"
FRONTEND = "Frontend"
CDN = "CDN / Proxy"
SECURITY = "Security"
API = "API"
OTHER = "Other"

# --- Rigorous Signatures (Cleaned from Weak/Generic Entries) ---
SERVER_SIGNATURES = {
    "nginx": ("Nginx", WEB_SERVER),
    "apache": ("Apache", WEB_SERVER),
    "openresty": ("OpenResty", WEB_SERVER),
    "litespeed": ("LiteSpeed", WEB_SERVER),
    "microsoft-iis": ("Microsoft IIS", WEB_SERVER),
    "cloudflare": ("Cloudflare (CDN)", CDN),
}

VALUE_HEADERS = {
    "x-powered-by": ("X-Powered-By", LANGUAGE),
    "x-generator": ("Generator", CMS),
    "x-aspnet-version": ("ASP.NET", LANGUAGE),
    "x-runtime": ("X-Runtime Header Detected", OTHER), 
}

PRESENCE_HEADERS = {
    "x-github-request-id": ("GitHub Infrastructure", OTHER),
    "cf-ray": ("Cloudflare (CDN)", CDN),
    "x-pjax-version": ("PJAX (GitHub Frontend)", FRONTEND),
    "via": ("Proxy/CDN present", CDN),
}

COOKIE_SIGNATURES = {
    "phpsessid": ("PHP (PHPSESSID)", LANGUAGE),
    "wordpress_": ("WordPress Cookie", CMS),
    "wp-settings": ("WordPress Cookie", CMS),
}

BODY_SIGNATURES = {
    "/wp-content/": ("WordPress", CMS),
    "/wp-includes/": ("WordPress", CMS),
    "__next_data__": ("Next.js (React)", FRAMEWORK),
    "data-turbo-track": ("Turbo/Hotwire Engine", FRAMEWORK), 
    "react-pages": ("React Framework", FRONTEND),
}

JS_REGEX = {
    r"jquery": ("jQuery", FRONTEND),
    r"bootstrap": ("Bootstrap", FRONTEND),
}

PROBE_PATHS = {
    "/wp-login.php": ("", ("WordPress Login Page", CMS)),
    "/.env": ("APP_KEY", ("Exposed .env File (!)", SECURITY)),
    "/.git/config": ("[core]", ("Exposed .git Directory (!)", SECURITY)),
    "/graphql": ("", ("GraphQL Endpoint", API)), 
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _add(found, tech, category, evidence):
    key = (tech, category)
    if key not in found:
        found[key] = set()
    found[key].add(evidence)


def _match_server(server_value, hostname):
    low = server_value.lower()
    if low == hostname.lower():
        return None
    for needle, (clean, category) in SERVER_SIGNATURES.items():
        if needle in low:
            m = re.search(r"[\d]+\.[\d]+", server_value)
            version = f" {m.group(0)}" if m else ""
            return (f"{clean}{version}", category)
    return (f"{server_value}", WEB_SERVER)


def _scan_response(resp, found, hostname):
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}

    if "server" in lower_headers and lower_headers["server"].strip():
        srv = _match_server(lower_headers["server"], hostname)
        if srv:
            _add(found, srv[0], srv[1], f"Server header: '{lower_headers['server']}'")

    for hkey, (label, cat) in VALUE_HEADERS.items():
        if hkey in lower_headers and lower_headers[hkey].strip():
            _add(found, label, cat, f"Header '{hkey}: {lower_headers[hkey].strip()}'")

    for hkey, (label, cat) in PRESENCE_HEADERS.items():
        if hkey in lower_headers:
            _add(found, label, cat, f"Presence of '{hkey}' header")

    for cookie in resp.cookies:
        cname = cookie.name.lower()
        for needle, (label, cat) in COOKIE_SIGNATURES.items():
            if needle in cname:
                _add(found, label, cat, f"Cookie named '{cookie.name}'")

    body = resp.text.lower()
    for needle, (label, cat) in BODY_SIGNATURES.items():
        if needle in body:
            _add(found, label, cat, f"HTML body contains '{needle}'")

    for pattern, (label, cat) in JS_REGEX.items():
        if re.search(pattern, body):
            _add(found, label, cat, f"Script src match: '{pattern}'")


def run(target, verbose=False):
    results = {
        "module": "tech_detect", "status": "success", "target": target,
        "data": {"url": None, "status_code": None, "technologies": [], "by_category": {}, "security_headers": {}}
    }

    base = target if target.startswith("http") else f"https://{target}"
    results["data"]["url"] = base
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LambdaEye/2.0"}
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]

    
    try:
        resp = requests.get(base, headers=ua, timeout=8, allow_redirects=True, verify=True)
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(base, headers=ua, timeout=8, allow_redirects=True, verify=False)
        except requests.exceptions.RequestException:
            results["status"] = "error"
            results["data"]["error"] = f"SSL Retry failed on {target}"
            return results
    except requests.exceptions.RequestException:
        try:
            base = f"http://{target}"
            resp = requests.get(base, headers=ua, timeout=8, allow_redirects=True)
            results["data"]["url"] = base
        except requests.exceptions.RequestException:
            results["status"] = "error"
            results["data"]["error"] = f"Connection failed to {target}"
            return results

    results["data"]["status_code"] = resp.status_code
    found = {}
    
    _scan_response(resp, found, hostname)

    if verbose:
        root = results["data"]["url"].rstrip("/")
        for path, (marker, (label, cat)) in PROBE_PATHS.items():
            try:
                pr = requests.get(root + path, headers=ua, timeout=4, allow_redirects=False, verify=False)
                if pr.status_code == 200 and (marker == "" or marker in pr.text.lower()):
                    _add(found, label, cat, f"Active probe '{path}' responded HTTP 200")
            except requests.exceptions.RequestException:
                pass

    lower_keys = {k.lower() for k in resp.headers.keys()}
    results["data"]["security_headers"] = {name: (hkey in lower_keys) for hkey, name in SECURITY_HEADERS.items()}

    by_category = {}
    detections = []
    flat = []
    
    for (tech, category), evidence in sorted(found.items()):
        by_category.setdefault(category, []).append(tech)
        detections.append({
            "technology": tech,
            "category": category,
            "evidence": sorted(list(evidence))
        })
        flat.append(tech)

    results["data"]["by_category"] = by_category
    results["data"]["technologies"] = sorted(set(flat))

   
    print(f"[TECH] Target URL: {results['data']['url']} (HTTP {resp.status_code})")
    
   
    categories_order = [WEB_SERVER, LANGUAGE, FRAMEWORK, CMS, FRONTEND, CDN, API, SECURITY, OTHER]
    has_tech = False
    
    for category in categories_order:
        if category in by_category:
            has_tech = True
            print(f"[TECH] {category}:")
            for tech in sorted(set(by_category[category])):
                print(f"[TECH]   -> {tech}")
               
                for det in detections:
                    if det["technology"] == tech:
                        for ev in det["evidence"]:
                            print(f"[TECH]      [Evidence] {ev}")
                            
    if not has_tech:
        print("[TECH] No standard infrastructure signatures leaked directly.")

    print(f"[TECH] Security Headers Status:")
    for name, present in results["data"]["security_headers"].items():
        mark = "✔ OK " if present else "✖ -- "
        print(f"[TECH]   [{mark}] {name}")

    return results


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    run(t, verbose=True)
