#!/usr/bin/env python3
"""
reporter.py - Shared utility: turns collected scan results into reports.
Takes the all_results dict that recon.py assembles from every module and
writes it as both a plain-text (.txt) and styled HTML (.html) report.
Every report includes a timestamp and the resolved target IP.

Handles all six modules: ports, banner, tech (active) and
whois, dns, subdomains (passive).
"""

import os
import html
from datetime import datetime


def _find_resolved_ip(all_results):
    """Any module that resolved the target stored its IP; grab the first."""
    for mod in all_results.values():
        if isinstance(mod, dict):
            ip = mod.get("data", {}).get("resolved_ip")
            if ip and ip != "N/A":
                return ip
    return "N/A"


# ---------- helpers that turn one module's data into a list of text lines ----

def _lines_for_module(name, data):
    """Return a list of plain-text lines for a given module's data."""
    out = []

    if name == "ports":
        ports = data.get("open_ports", [])
        if ports:
            for p in ports:
                out.append(f"  Port {p['port']:<6} OPEN   {p.get('service','')}")
        else:
            out.append("  No open ports found.")

    elif name == "banner":
        banners = data.get("banners", [])
        if banners:
            for b in banners:
                out.append(f"  Port {b['port']:<6} {b['banner']}")
        else:
            out.append("  No banners retrieved.")

    elif name == "tech":
        out.append(f"  URL: {data.get('url','')}  (HTTP {data.get('status_code','')})")
        techs = data.get("technologies", [])
        if techs:
            for t in techs:
                out.append(f"  - {t}")
        else:
            out.append("  No technologies disclosed.")

    elif name == "whois":
        labels = [
            ("Domain", "domain_name"), ("Registrar", "registrar"),
            ("Organization", "org"), ("Country", "country"),
            ("Creation", "creation_date"), ("Expiration", "expiration_date"),
            ("Updated", "updated_date"), ("Name Servers", "name_servers"),
            ("Status", "status"), ("Emails", "emails"),
        ]
        for label, key in labels:
            val = data.get(key)
            if val and val != "N/A":
                out.append(f"  {label:<15}: {val}")
        if not out:
            out.append("  No WHOIS data.")

    elif name == "dns":
        ip = data.get("resolved_ip")
        if ip and ip != "N/A":
            out.append(f"  Resolved IP    : {ip}")
        for rtype in ("A", "MX", "TXT", "NS"):
            vals = data.get(rtype, [])
            if vals:
                out.append(f"  {rtype} records:")
                for v in vals:
                    out.append(f"      {v}")

    elif name == "subdomains":
        total = data.get("total_found", 0)
        sources = data.get("sources", {})
        out.append(f"  Total found    : {total}")
        if sources:
            src = ", ".join(f"{k}: {v}" for k, v in sources.items())
            out.append(f"  Sources        : {src}")
        for sub in data.get("subdomains", []):
            out.append(f"      - {sub}")

    else:
        for k, v in data.items():
            out.append(f"  {k}: {v}")

    if data.get("error"):
        out.append(f"  ERROR: {data['error']}")

    return out


def _items_for_module_html(name, data):
    """Return a list of HTML-escaped strings (list items) for a module."""
    esc = html.escape
    items = []

    if name == "ports":
        for p in data.get("open_ports", []):
            items.append(f"Port <code>{p['port']}</code> OPEN &mdash; {esc(str(p.get('service','')))}")
    elif name == "banner":
        for b in data.get("banners", []):
            items.append(f"Port <code>{b['port']}</code>: {esc(str(b['banner']))}")
    elif name == "tech":
        items.append(f"URL: {esc(str(data.get('url','')))} (HTTP {esc(str(data.get('status_code','')))})")
        for t in data.get("technologies", []):
            items.append(esc(str(t)))
    elif name == "whois":
        labels = [
            ("Domain", "domain_name"), ("Registrar", "registrar"),
            ("Organization", "org"), ("Country", "country"),
            ("Creation", "creation_date"), ("Expiration", "expiration_date"),
            ("Updated", "updated_date"), ("Name Servers", "name_servers"),
            ("Status", "status"), ("Emails", "emails"),
        ]
        for label, key in labels:
            val = data.get(key)
            if val and val != "N/A":
                items.append(f"<strong>{esc(label)}:</strong> {esc(str(val))}")
    elif name == "dns":
        ip = data.get("resolved_ip")
        if ip and ip != "N/A":
            items.append(f"<strong>Resolved IP:</strong> <code>{esc(str(ip))}</code>")
        for rtype in ("A", "MX", "TXT", "NS"):
            for v in data.get(rtype, []):
                items.append(f"<strong>{rtype}:</strong> {esc(str(v))}")
    elif name == "subdomains":
        items.append(f"<strong>Total found:</strong> {esc(str(data.get('total_found', 0)))}")
        sources = data.get("sources", {})
        if sources:
            items.append("<strong>Sources:</strong> " +
                         esc(", ".join(f"{k}: {v}" for k, v in sources.items())))
        for sub in data.get("subdomains", []):
            items.append(esc(str(sub)))
    else:
        for k, v in data.items():
            items.append(f"{esc(str(k))}: {esc(str(v))}")

    if data.get("error"):
        items.append(f"<em>ERROR: {esc(str(data['error']))}</em>")

    return items


# ---------- report builders --------------------------------------------------

MODULE_ORDER = ["ports", "banner", "tech", "whois", "dns", "subdomains"]
MODULE_TITLES = {
    "ports": "PORT SCAN", "banner": "BANNER GRABBING",
    "tech": "TECHNOLOGY DETECTION", "whois": "WHOIS LOOKUP",
    "dns": "DNS ENUMERATION", "subdomains": "SUBDOMAIN ENUMERATION",
}


def _ordered(all_results):
    """Yield (name, result) in a sensible order, extras last."""
    seen = set()
    for name in MODULE_ORDER:
        if name in all_results:
            seen.add(name)
            yield name, all_results[name]
    for name, result in all_results.items():
        if name not in seen:
            yield name, result


def _build_text_report(target, all_results, timestamp, resolved_ip):
    lines = []
    lines.append("=" * 62)
    lines.append("        LambdaEye - Reconnaissance Report")
    lines.append("=" * 62)
    lines.append(f"Target        : {target}")
    lines.append(f"Resolved IP   : {resolved_ip}")
    lines.append(f"Generated     : {timestamp}")
    lines.append("=" * 62)
    lines.append("")

    if not all_results:
        lines.append("No modules were run.")
        return "\n".join(lines)

    for name, result in _ordered(all_results):
        data = result.get("data", {}) if isinstance(result, dict) else {}
        status = result.get("status", "unknown") if isinstance(result, dict) else "?"
        title = MODULE_TITLES.get(name, name.upper())
        lines.append(f"[ {title} ]  (status: {status})")
        lines.append("-" * 62)
        lines.extend(_lines_for_module(name, data))
        lines.append("")

    lines.append("=" * 62)
    lines.append("End of report.")
    return "\n".join(lines)


def _build_html_report(target, all_results, timestamp, resolved_ip):
    esc = html.escape
    rows = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>LambdaEye Report - {esc(target)}</title>
<style>
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f1117;
         color:#e4e6eb; margin:0; padding:2rem; }}
  .card {{ max-width:900px; margin:0 auto; }}
  h1 {{ color:#7c9eff; margin-bottom:0.2rem; }}
  .meta {{ color:#9aa0a6; font-size:0.9rem; margin-bottom:1.5rem;
          border-bottom:1px solid #2a2d36; padding-bottom:1rem; }}
  .module {{ background:#171923; border:1px solid #2a2d36; border-radius:10px;
            padding:1.2rem 1.4rem; margin-bottom:1.2rem; }}
  .module h2 {{ margin:0 0 0.8rem; font-size:1.1rem; color:#a6f3c0; }}
  .status {{ font-size:0.72rem; padding:2px 8px; border-radius:12px;
            background:#233; color:#8fd; margin-left:8px; }}
  ul {{ margin:0; padding-left:1.2rem; }} li {{ margin:0.2rem 0; word-break:break-all; }}
  .empty {{ color:#777; font-style:italic; }}
  code {{ background:#0d0f14; padding:1px 6px; border-radius:4px; color:#ffd479; }}
</style></head><body><div class="card">
<h1>LambdaEye Report</h1>
<div class="meta">
  <strong>Target:</strong> {esc(target)} &nbsp;|&nbsp;
  <strong>Resolved IP:</strong> <code>{esc(resolved_ip)}</code> &nbsp;|&nbsp;
  <strong>Generated:</strong> {esc(timestamp)}
</div>"""]

    for name, result in _ordered(all_results):
        data = result.get("data", {}) if isinstance(result, dict) else {}
        status = result.get("status", "unknown") if isinstance(result, dict) else "?"
        title = MODULE_TITLES.get(name, name.upper())
        rows.append(f'<div class="module"><h2>{esc(title)}'
                    f'<span class="status">{esc(status)}</span></h2>')
        items = _items_for_module_html(name, data)
        if items:
            rows.append("<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>")
        else:
            rows.append('<p class="empty">No data.</p>')
        rows.append("</div>")

    rows.append("</div></body></html>")
    return "\n".join(rows)


def generate_report(target, all_results, out_dir="reports"):
    """Write both .txt and .html reports. Returns (txt_path, html_path)."""
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    resolved_ip = _find_resolved_ip(all_results)

    safe = target.replace("http://", "").replace("https://", "").replace("/", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(out_dir, f"{safe}_{stamp}")
    txt_path, html_path = base + ".txt", base + ".html"

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_build_text_report(target, all_results, timestamp, resolved_ip))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html_report(target, all_results, timestamp, resolved_ip))

    return txt_path, html_path
