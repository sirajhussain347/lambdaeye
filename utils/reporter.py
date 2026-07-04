#!/usr/bin/env python3
"""
reporter.py - Shared utility: turns collected scan results into reports.
Takes the all_results dict that recon.py assembles and writes both a
plain-text (.txt) and styled HTML (.html) report. Every report includes a
timestamp and the resolved target IP, as required by the task.
"""

import os
import html
from datetime import datetime


def _find_resolved_ip(all_results):
    """Any module that resolved the target stored its IP; grab the first one."""
    for mod in all_results.values():
        if isinstance(mod, dict):
            ip = mod.get("data", {}).get("resolved_ip")
            if ip:
                return ip
    return "N/A"


def _build_text_report(target, all_results, timestamp, resolved_ip):
    lines = []
    lines.append("=" * 60)
    lines.append("        LambdaRecon - Reconnaissance Report")
    lines.append("=" * 60)
    lines.append(f"Target        : {target}")
    lines.append(f"Resolved IP   : {resolved_ip}")
    lines.append(f"Generated     : {timestamp}")
    lines.append("=" * 60)
    lines.append("")

    if not all_results:
        lines.append("No modules were run.")
        return "\n".join(lines)

    for name, result in all_results.items():
        title = name.upper()
        status = result.get("status", "unknown") if isinstance(result, dict) else "?"
        lines.append(f"[ {title} ]  (status: {status})")
        lines.append("-" * 60)

        data = result.get("data", {}) if isinstance(result, dict) else {}

        if name == "ports":
            open_ports = data.get("open_ports", [])
            if open_ports:
                for p in open_ports:
                    lines.append(f"  Port {p['port']:<6} OPEN   {p.get('service','')}")
            else:
                lines.append("  No open ports found.")

        elif name == "banner":
            banners = data.get("banners", [])
            if banners:
                for b in banners:
                    lines.append(f"  Port {b['port']:<6} {b['banner']}")
            else:
                lines.append("  No banners retrieved.")

        elif name == "tech":
            techs = data.get("technologies", [])
            lines.append(f"  URL: {data.get('url','')}  (HTTP {data.get('status_code','')})")
            if techs:
                for t in techs:
                    lines.append(f"  - {t}")
            else:
                lines.append("  No technologies disclosed.")

        else:
            for k, v in data.items():
                lines.append(f"  {k}: {v}")

        if data.get("error"):
            lines.append(f"  ERROR: {data['error']}")

        lines.append("")

    lines.append("=" * 60)
    lines.append("End of report.")
    return "\n".join(lines)


def _build_html_report(target, all_results, timestamp, resolved_ip):
    esc = html.escape
    rows = []
    rows.append(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>LambdaRecon Report - {esc(target)}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0f1117;
         color:#e4e6eb; margin:0; padding:2rem; }}
  .card {{ max-width:900px; margin:0 auto; }}
  h1 {{ color:#7c9eff; margin-bottom:0.2rem; }}
  .meta {{ color:#9aa0a6; font-size:0.9rem; margin-bottom:1.5rem;
          border-bottom:1px solid #2a2d36; padding-bottom:1rem; }}
  .module {{ background:#171923; border:1px solid #2a2d36; border-radius:10px;
            padding:1.2rem 1.4rem; margin-bottom:1.2rem; }}
  .module h2 {{ margin:0 0 0.8rem; font-size:1.1rem; color:#a6f3c0; }}
  .status {{ font-size:0.75rem; padding:2px 8px; border-radius:12px;
            background:#233; color:#8fd; margin-left:8px; }}
  ul {{ margin:0; padding-left:1.2rem; }} li {{ margin:0.2rem 0; }}
  .empty {{ color:#777; font-style:italic; }}
  code {{ background:#0d0f14; padding:1px 6px; border-radius:4px; color:#ffd479; }}
</style></head><body><div class="card">
<h1>LambdaRecon Report</h1>
<div class="meta">
  <strong>Target:</strong> {esc(target)} &nbsp;|&nbsp;
  <strong>Resolved IP:</strong> <code>{esc(resolved_ip)}</code> &nbsp;|&nbsp;
  <strong>Generated:</strong> {esc(timestamp)}
</div>""")

    for name, result in all_results.items():
        data = result.get("data", {}) if isinstance(result, dict) else {}
        status = result.get("status", "unknown") if isinstance(result, dict) else "?"
        rows.append(f'<div class="module"><h2>{esc(name.upper())}'
                    f'<span class="status">{esc(status)}</span></h2>')

        items = []
        if name == "ports":
            for p in data.get("open_ports", []):
                items.append(f"Port <code>{p['port']}</code> OPEN &mdash; {esc(str(p.get('service','')))}")
        elif name == "banner":
            for b in data.get("banners", []):
                items.append(f"Port <code>{b['port']}</code>: {esc(str(b['banner']))}")
        elif name == "tech":
            for t in data.get("technologies", []):
                items.append(esc(str(t)))
        else:
            for k, v in data.items():
                items.append(f"{esc(str(k))}: {esc(str(v))}")

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

    txt_path = base + ".txt"
    html_path = base + ".html"

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_build_text_report(target, all_results, timestamp, resolved_ip))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html_report(target, all_results, timestamp, resolved_ip))

    return txt_path, html_path
