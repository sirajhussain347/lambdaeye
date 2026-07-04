#!/usr/bin/env python3
"""
tech_detect.py - Active recon module: web technology detection.
Fingerprints a website's tech stack from headers, cookies, HTML body,
and a few well-known probe paths. Extracts version numbers and reports
raw values of revealing headers so nothing useful is discarded.
Contract: exposes run(target, verbose=False) and returns a dict.
Requires: requests
"""

import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_SIGNATURES = {
    "nginx": "nginx", "apache": "Apache", "openresty": "OpenResty (nginx + Lua)",
    "litespeed": "LiteSpeed", "microsoft-iis": "Microsoft IIS", "iis": "Microsoft IIS",
    "cloudflare": "Cloudflare (CDN)", "cloudfront": "AWS CloudFront (CDN)",
    "gws": "Google Web Server", "caddy": "Caddy", "tengine": "Tengine (nginx fork)",
    "gunicorn": "Gunicorn (Python)", "werkzeug": "Werkzeug (Python/Flask)",
    "kestrel": "Kestrel (ASP.NET Core)", "vercel": "Vercel",
}

REVEALING_HEADERS = {
    "x-powered-by": "X-Powered-By", "x-generator": "Generator",
    "x-aspnet-version": "ASP.NET version", "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-drupal-cache": "Drupal (cache header)", "x-drupal-dynamic-cache": "Drupal",
    "x-shopify-stage": "Shopify", "x-varnish": "Varnish (cache)",
    "via": "Proxy/CDN (Via)", "x-served-by": "Served-By (CDN)",
    "cf-cache-status": "Cloudflare (CDN)", "x-vercel-id": "Vercel (hosting)",
    "x-nextjs-cache": "Next.js", "x-github-request-id": "GitHub",
    "fastly-debug-digest": "Fastly (CDN)",
}

COOKIE_SIGNATURES = {
    "phpsessid": "PHP", "wordpress_": "WordPress", "wp-settings": "WordPress",
    "woocommerce": "WooCommerce (WordPress)", "laravel_session": "Laravel (PHP)",
    "xsrf-token": "Laravel/Angular (XSRF token)", "ci_session": "CodeIgniter (PHP)",
    "asp.net_sessionid": "ASP.NET", ".aspxauth": "ASP.NET",
    "jsessionid": "Java (JSP/Servlet)", "connect.sid": "Express.js (Node)",
    "__cfduid": "Cloudflare (CDN)", "_shopify": "Shopify",
    "django": "Django (Python)", "csrftoken": "Django (Python)",
}

BODY_SIGNATURES = {
    "/wp-content/": "WordPress", "/wp-includes/": "WordPress", "wp-json": "WordPress",
    'content="wordpress': "WordPress", 'content="drupal': "Drupal",
    'content="joomla': "Joomla", "__next_data__": "Next.js (React)",
    "/_next/static": "Next.js (React)", "ng-version": "Angular",
    "data-reactroot": "React", "react.production.min": "React",
    "__nuxt__": "Nuxt.js (Vue)", "vue.runtime": "Vue.js", "csrf-param": "Ruby on Rails",
    "cdn.shopify.com": "Shopify", "static.parastorage.com": "Wix",
    "squarespace.com": "Squarespace", "gatsby": "Gatsby (React)",
    "bootstrap.min.css": "Bootstrap (CSS)", "jquery": "jQuery",
}

# Well-known probe paths: if they exist / contain a marker, they confirm a stack.
# Format: path -> (marker_substring_in_response, technology_label)
# marker "" means "a 200 OK on this path alone is the signal".
PROBE_PATHS = {
    "/wp-login.php":     ("", "WordPress (login page present)"),
    "/administrator/":   ("joomla", "Joomla (admin present)"),
    "/robots.txt":       ("wp-admin", "WordPress (robots.txt)"),
    "/.git/config":      ("[core]", "Exposed .git directory (!)"),
    "/wp-json/":         ("wp/v2", "WordPress REST API"),
}


def _match_server(server_value):
    low = server_value.lower()
    for needle, label in SERVER_SIGNATURES.items():
        if needle in low:
            m = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", server_value)
            version = f" {m.group(0)}" if m else ""
            return f"{label}{version}"
    return f"Server: {server_value}"


def _scan_response(resp, found):
    """Inspect one response's headers, cookies, and body; add hits to `found`."""
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}

    if "server" in lower_headers and lower_headers["server"].strip():
        found.add(_match_server(lower_headers["server"]))

    for hkey, label in REVEALING_HEADERS.items():
        if hkey in lower_headers:
            val = lower_headers[hkey].strip()
            found.add(f"{label}: {val}" if val else label)

    for cookie in resp.cookies:
        cname = cookie.name.lower()
        for needle, label in COOKIE_SIGNATURES.items():
            if needle in cname:
                found.add(label)

    body = resp.text.lower()
    for needle, label in BODY_SIGNATURES.items():
        if needle in body:
            found.add(label)


def run(target, verbose=False):
    """Main entry point (matches the team contract)."""
    results = {
        "module": "tech_detect", "status": "success", "target": target,
        "data": {"url": None, "status_code": None, "technologies": [],
                 "raw_headers": {}, "probes": []},
    }

    base = target if target.startswith("http") else f"https://{target}"
    results["data"]["url"] = base
    ua = {"User-Agent": "Mozilla/5.0 (LambdaRecon)"}

    # --- Main page fetch (with http fallback) ---
    try:
        resp = requests.get(base, headers=ua, timeout=10,
                            allow_redirects=True, verify=False)
    except requests.exceptions.RequestException as e:
        try:
            base = f"http://{target}"
            resp = requests.get(base, headers=ua, timeout=10, allow_redirects=True)
            results["data"]["url"] = base
        except requests.exceptions.RequestException:
            results["status"] = "error"
            results["data"]["error"] = f"Could not connect: {e}"
            print(f"[TECH]   ERROR: could not connect to {target}")
            return results

    results["data"]["status_code"] = resp.status_code
    results["data"]["raw_headers"] = dict(resp.headers)

    found = set()
    _scan_response(resp, found)              # scan the homepage

    # --- Probe well-known paths for extra confirmation ---
    root = results["data"]["url"].rstrip("/")
    for path, (marker, label) in PROBE_PATHS.items():
        try:
            pr = requests.get(root + path, headers=ua, timeout=6,
                              allow_redirects=False, verify=False)
            hit = False
            if pr.status_code == 200:
                if marker == "" or marker in pr.text.lower():
                    hit = True
            if hit:
                found.add(label)
                results["data"]["probes"].append({"path": path, "status": pr.status_code})
                if verbose:
                    print(f"[TECH]   Probe {path} -> {pr.status_code}  MATCH ({label})")
            elif verbose:
                print(f"[TECH]   Probe {path} -> {pr.status_code}")
        except requests.exceptions.RequestException:
            if verbose:
                print(f"[TECH]   Probe {path} -> (no response)")

    results["data"]["technologies"] = sorted(found)

    # --- Output ---
    print(f"[TECH]   URL: {results['data']['url']}  (HTTP {resp.status_code})")
    if found:
        for tech in sorted(found):
            print(f"[TECH]   Detected -> {tech}")
    else:
        print("[TECH]   No technologies disclosed by target.")

    if verbose:
        print("\n[TECH]   Notable response headers:")
        for h in ("Server", "X-Powered-By", "X-Generator", "Via",
                  "X-Served-By", "CF-Cache-Status", "Set-Cookie"):
            if h in resp.headers:
                print(f"[TECH]     {h}: {resp.headers[h][:110]}")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "wordpress.org"
    print(f"[*] Standalone tech-detect test on {t}\n")
    out = run(t, verbose=True)
    print("\n[*] Detected technologies:")
    print(json.dumps(out["data"]["technologies"], indent=2))
