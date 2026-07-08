#!/usr/bin/env python3
"""
tech_detect.py - Active recon module: web technology detection.

Fingerprints a website's tech stack from HTTP headers, cookies, HTML body
signatures, and well-known probe paths. Reports results grouped by category
grouped by category, with the evidence behind each detection.

Part of the LambdaEye tool (active recon).
Contract: exposes run(target, verbose=False) and returns a dict.
Requires: requests
"""

import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Category constants (for grouped output, improvement #13) ---------------
WEB_SERVER = "Web Server"
LANGUAGE = "Programming Language"
FRAMEWORK = "Framework"
CMS = "CMS"
FRONTEND = "Frontend"
CDN = "CDN / Proxy"
SECURITY = "Security"
OTHER = "Other"


# --- Server header signatures: needle -> (clean name, category) -------------
SERVER_SIGNATURES = {
    "nginx": ("Nginx", WEB_SERVER),
    "apache": ("Apache", WEB_SERVER),
    "openresty": ("OpenResty (nginx + Lua)", WEB_SERVER),
    "litespeed": ("LiteSpeed", WEB_SERVER),
    "microsoft-iis": ("Microsoft IIS", WEB_SERVER),
    "iis": ("Microsoft IIS", WEB_SERVER),
    "caddy": ("Caddy", WEB_SERVER),
    "tengine": ("Tengine (nginx fork)", WEB_SERVER),
    "gunicorn": ("Gunicorn (Python)", WEB_SERVER),
    "werkzeug": ("Werkzeug (Python/Flask)", WEB_SERVER),
    "kestrel": ("Kestrel (ASP.NET Core)", WEB_SERVER),
    "cloudflare": ("Cloudflare (CDN)", CDN),
    "cloudfront": ("AWS CloudFront (CDN)", CDN),
    "gws": ("Google Web Server", WEB_SERVER),
    "vercel": ("Vercel", CDN),
}

# VALUE headers: value is a version/name -> keep the value. (label, category)
VALUE_HEADERS = {
    "x-powered-by": ("X-Powered-By", LANGUAGE),
    "x-generator": ("Generator", CMS),
    "x-aspnet-version": ("ASP.NET", LANGUAGE),
    "x-aspnetmvc-version": ("ASP.NET MVC", FRAMEWORK),
    "x-runtime": ("Ruby (X-Runtime)", LANGUAGE),
}

# PRESENCE headers (Bug 3 fix): value is a trace/ID -> report label only.
# (label, category)
PRESENCE_HEADERS = {
    "x-github-request-id": ("GitHub", OTHER),
    "cf-ray": ("Cloudflare (CDN)", CDN),
    "cf-cache-status": ("Cloudflare (CDN)", CDN),
    "x-vercel-id": ("Vercel", CDN),
    "x-served-by": ("CDN (Served-By)", CDN),
    "x-fastly-request-id": ("Fastly (CDN)", CDN),
    "fastly-debug-digest": ("Fastly (CDN)", CDN),
    "x-akamai-request-id": ("Akamai (CDN)", CDN),
    "x-sucuri-id": ("Sucuri (WAF/CDN)", SECURITY),
    "x-imperva-id": ("Imperva (WAF)", SECURITY),
    "x-bunnycdn": ("BunnyCDN", CDN),
    "x-drupal-cache": ("Drupal", CMS),
    "x-drupal-dynamic-cache": ("Drupal", CMS),
    "x-shopify-stage": ("Shopify", CMS),
    "x-varnish": ("Varnish (cache)", CDN),
    "x-nextjs-cache": ("Next.js", FRAMEWORK),
    "x-request-id": ("Rails/Request-ID", FRAMEWORK),
    "via": ("Proxy/CDN present", CDN),
    "alt-svc": ("HTTP/3 (alt-svc)", OTHER),
}

# Cookie name substring -> (tech, category)
COOKIE_SIGNATURES = {
    "phpsessid": ("PHP", LANGUAGE),
    "wordpress_": ("WordPress", CMS),
    "wp-settings": ("WordPress", CMS),
    "woocommerce": ("WooCommerce", CMS),
    "laravel_session": ("Laravel (PHP)", FRAMEWORK),
    "ci_session": ("CodeIgniter (PHP)", FRAMEWORK),
    "asp.net_sessionid": ("ASP.NET", LANGUAGE),
    ".aspxauth": ("ASP.NET", LANGUAGE),
    "jsessionid": ("Java (JSP/Servlet)", LANGUAGE),
    "connect.sid": ("Express.js (Node)", FRAMEWORK),
    "__cfduid": ("Cloudflare (CDN)", CDN),
    "_shopify": ("Shopify", CMS),
    "django": ("Django (Python)", FRAMEWORK),
    "csrftoken": ("Django (Python)", FRAMEWORK),
}

# Body substring -> (tech, category)
BODY_SIGNATURES = {
    "/wp-content/": ("WordPress", CMS),
    "/wp-includes/": ("WordPress", CMS),
    "wp-json": ("WordPress", CMS),
    'content="drupal': ("Drupal", CMS),
    'content="joomla': ("Joomla", CMS),
    "__next_data__": ("Next.js (React)", FRAMEWORK),
    "/_next/static": ("Next.js (React)", FRAMEWORK),
    'id="__next"': ("Next.js (React)", FRAMEWORK),
    "ng-version": ("Angular", FRAMEWORK),
    "ng-app": ("Angular", FRAMEWORK),
    "data-reactroot": ("React", FRONTEND),
    'id="root"': ("React (likely)", FRONTEND),
    "__nuxt__": ("Nuxt.js (Vue)", FRAMEWORK),
    "data-v-": ("Vue.js", FRONTEND),
    "csrf-param": ("Ruby on Rails", FRAMEWORK),
    "cdn.shopify.com": ("Shopify", CMS),
    "static.parastorage.com": ("Wix", CMS),
    "squarespace.com": ("Squarespace", CMS),
    "gatsby": ("Gatsby (React)", FRAMEWORK),
    # More CMS (improvement #11)
    "/skin/frontend/": ("Magento", CMS),
    "mage/cookies": ("Magento", CMS),
    "ghost-": ("Ghost", CMS),
    "content=\"typo3": ("TYPO3", CMS),
    "/typo3temp/": ("TYPO3", CMS),
    "craftcms": ("Craft CMS", CMS),
    "prestashop": ("PrestaShop", CMS),
    "opencart": ("OpenCart", CMS),
    "/mediawiki/": ("MediaWiki", CMS),
    "blogger.com": ("Blogger", CMS),
}

# JS library regexes (improvement #1) -> (tech, category)
JS_REGEX = {
    r"jquery(?:[-.]\d+\.\d+\.\d+)?(?:\.min)?\.js": ("jQuery", FRONTEND),
    r"bootstrap(?:\.bundle)?(?:[-.]\d+\.\d+\.\d+)?(?:\.min)?\.(?:js|css)": ("Bootstrap", FRONTEND),
    r"vue(?:\.runtime)?(?:\.min)?\.js": ("Vue.js", FRONTEND),
    r"react(?:\.production)?(?:\.min)?\.js": ("React", FRONTEND),
    r"angular(?:\.min)?\.js": ("Angular", FRAMEWORK),
    r"font-?awesome": ("Font Awesome", FRONTEND),
}

# Probe paths (improvement #9): path -> (marker, tech, category)
# marker "" means a 200 alone is the signal.
PROBE_PATHS = {
    "/wp-login.php":   ("", ("WordPress (login page)", CMS)),
    "/robots.txt":     ("wp-admin", ("WordPress (robots.txt)", CMS)),
    "/wp-json/":       ("wp/v2", ("WordPress REST API", CMS)),
    "/administrator/": ("joomla", ("Joomla (admin)", CMS)),
    "/sitemap.xml":    ("<urlset", ("XML sitemap present", OTHER)),
    "/.git/config":    ("[core]", ("Exposed .git directory (!)", SECURITY)),
    "/.env":           ("APP_KEY", ("Exposed .env file (!)", SECURITY)),
    "/server-status":  ("Apache Server Status", ("Apache mod_status exposed (!)", SECURITY)),
    "/graphql":        ("", ("GraphQL endpoint", FRAMEWORK)),
}

# Security headers to check (improvement #6): header -> friendly name
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _add(found, tech, category, evidence):
    """Record a detection with its category and accumulate evidence."""
    key = (tech, category)
    if key not in found:
        found[key] = set()
    found[key].add(evidence)


def _match_server(server_value, hostname):
    low = server_value.lower()
    if low == hostname.lower():
        return None  # hostname echo, not a real banner (Bug 5-adjacent)
    for needle, (clean, category) in SERVER_SIGNATURES.items():
        if needle in low:
            m = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", server_value)
            version = f" {m.group(0)}" if m else ""
            return (f"{clean}{version}", category)
    return (f"{server_value}", WEB_SERVER)


def _scan_response(resp, found, hostname):
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}

    # Server header (improvement #5: clean names)
    if "server" in lower_headers and lower_headers["server"].strip():
        srv = _match_server(lower_headers["server"], hostname)
        if srv:
            _add(found, srv[0], srv[1], f"Server header: {lower_headers['server']}")

    # Value headers
    for hkey, (label, cat) in VALUE_HEADERS.items():
        if hkey in lower_headers and lower_headers[hkey].strip():
            _add(found, f"{label}: {lower_headers[hkey].strip()}", cat,
                 f"{hkey} header")

    # Presence headers (Bug 3: label only)
    for hkey, (label, cat) in PRESENCE_HEADERS.items():
        if hkey in lower_headers:
            _add(found, label, cat, f"{hkey} header present")

    # Cookies
    for cookie in resp.cookies:
        cname = cookie.name.lower()
        for needle, (label, cat) in COOKIE_SIGNATURES.items():
            if needle in cname:
                _add(found, label, cat, f"cookie: {cookie.name}")

    # Body signatures
    body = resp.text.lower()
    for needle, (label, cat) in BODY_SIGNATURES.items():
        if needle in body:
            _add(found, label, cat, f"body contains '{needle}'")

    # JS library regexes (improvement #1)
    for pattern, (label, cat) in JS_REGEX.items():
        if re.search(pattern, body):
            _add(found, label, cat, f"JS/CSS match: {pattern}")


def _check_security_headers(resp):
    """Improvement #6: return dict of {friendly_name: present_bool}."""
    lower = {k.lower() for k in resp.headers.keys()}
    return {name: (hkey in lower) for hkey, name in SECURITY_HEADERS.items()}


def run(target, verbose=False):
    """Main entry point (matches the team contract)."""
    results = {
        "module": "tech_detect", "status": "success", "target": target,
        "data": {"url": None, "status_code": None,
                 "technologies": [],        # flat list (backwards-compatible)
                 "by_category": {},         # grouped (improvement #13)
                 "detections": [],          # with evidence (#17)
                 "security_headers": {},    # improvement #6
                 "probes": [], "raw_headers": {}},
    }

    base = target if target.startswith("http") else f"https://{target}"
    results["data"]["url"] = base
    ua = {"User-Agent": "Mozilla/5.0 (LambdaEye)"}
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        resp = requests.get(base, headers=ua, timeout=10,
                            allow_redirects=True, verify=False)
    except requests.exceptions.RequestException as e:
        try:
            base = f"http://{target}"
            resp = requests.get(base, headers=ua, timeout=10, allow_redirects=True)
            results["data"]["url"] = base
        except requests.exceptions.RequestException as e2:
            results["status"] = "error"
            # Improvement #16: clearer error category
            msg = str(e2)
            if "timed out" in msg.lower():
                reason = "connection timed out"
            elif "name or service" in msg.lower() or "resolve" in msg.lower():
                reason = "DNS resolution failed"
            elif "ssl" in msg.lower():
                reason = "SSL/TLS error"
            else:
                reason = "connection failed"
            results["data"]["error"] = f"{reason}: {target}"
            print(f"[TECH]   ERROR: {reason} -> {target}")
            return results

    results["data"]["status_code"] = resp.status_code
    results["data"]["raw_headers"] = dict(resp.headers)

    found = {}   # {(tech, category): set(evidence)}
    _scan_response(resp, found, hostname)

    # Probe paths
    root = results["data"]["url"].rstrip("/")
    for path, (marker, (label, cat)) in PROBE_PATHS.items():
        try:
            pr = requests.get(root + path, headers=ua, timeout=6,
                              allow_redirects=False, verify=False)
            if pr.status_code == 200 and (marker == "" or marker in pr.text.lower()):
                _add(found, label, cat, f"path {path} -> 200")
                results["data"]["probes"].append({"path": path, "status": 200})
                if verbose:
                    print(f"[TECH]   Probe {path} -> 200  MATCH ({label})")
            elif verbose:
                print(f"[TECH]   Probe {path} -> {pr.status_code}")
        except requests.exceptions.RequestException:
            if verbose:
                print(f"[TECH]   Probe {path} -> (no response)")

    # Security headers (improvement #6)
    results["data"]["security_headers"] = _check_security_headers(resp)

    # Build the three output views
    by_category = {}
    detections = []
    flat = []
    for (tech, category), evidence in sorted(found.items()):
        by_category.setdefault(category, []).append(tech)
        detections.append({
            "technology": tech, "category": category,
            "evidence": sorted(evidence),
        })
        flat.append(tech)

    results["data"]["by_category"] = by_category
    results["data"]["detections"] = detections
    results["data"]["technologies"] = sorted(set(flat))

    # --- Output (improvement #13: grouped by category) ---
    print(f"[TECH]   URL: {results['data']['url']}  (HTTP {resp.status_code})")
    if by_category:
        for category in [WEB_SERVER, LANGUAGE, FRAMEWORK, CMS, FRONTEND, CDN, SECURITY, OTHER]:
            if category in by_category:
                print(f"[TECH]   {category}:")
                for tech in sorted(set(by_category[category])):
                    print(f"[TECH]     - {tech}")
    else:
        print("[TECH]   No technologies disclosed by target.")

    # Security header summary
    sec = results["data"]["security_headers"]
    print(f"[TECH]   Security headers:")
    for name, present in sec.items():
        mark = "OK " if present else "-- "
        print(f"[TECH]     [{mark}] {name}")

    if verbose and detections:
        print("\n[TECH]   Evidence:")
        for d in detections:
            print(f"[TECH]     {d['technology']}: "
                  f"{', '.join(d['evidence'])}")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "wordpress.org"
    print(f"[*] Standalone tech-detect test on {t}\n")
    out = run(t, verbose=True)
    print("\n[*] By category:", json.dumps(out["data"]["by_category"], indent=2))
