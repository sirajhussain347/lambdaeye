#!/usr/bin/env python3
"""
banner_grab.py - Active recon module: service banner grabbing.
Connects to open ports and reads the banner the service sends back.
Handles plain HTTP, encrypted HTTPS (TLS), and talkative services
(SSH/FTP/SMTP). Part of the LambdaEye tool (active recon).

Contract: exposes run(target, verbose=False, ports=None) and returns a dict.
"""

import socket
import ssl

TLS_PORTS = {443, 8443}
HTTP_PORTS = {80, 8080}


def _read_all(sock, timeout=3.0):
    sock.settimeout(timeout)
    chunks = b""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks += data
        except socket.timeout:
            break
    return chunks


def _extract_http_server(raw_text, hostname):
    """
    Pull the Server header value from an HTTP response.
    Bug 5 fix: if the Server value is just the hostname (e.g. 'github.com'),
    that's not a real banner -- return the status line or a TLS note instead.
    """
    server = None
    for line in raw_text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break

    # Bug 5: reject useless "banners" that just echo the hostname.
    if server:
        if server.lower() == hostname.lower():
            # Not informative -- fall through to status line instead.
            server = None
        else:
            return server

    # Fall back to the HTTP status line (e.g. "HTTP/1.1 200 OK").
    lines = raw_text.splitlines()
    if lines and lines[0].startswith("HTTP"):
        return lines[0].strip()
    return None


def grab_banner(hostname, ip, port, timeout=3.0):
    try:
        sock = socket.create_connection((ip, port), timeout)

        if port in TLS_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=hostname)

        if port in TLS_PORTS or port in HTTP_PORTS:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: Mozilla/5.0 (LambdaEye)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            raw = _read_all(sock).decode(errors="ignore")
            sock.close()
            result = _extract_http_server(raw, hostname)
            # Bug 5: for TLS, if we still have nothing useful, note it's TLS.
            if result is None and port in TLS_PORTS:
                return "TLS service (no server banner disclosed)"
            return result
        else:
            raw = _read_all(sock).decode(errors="ignore").strip()
            sock.close()
            return raw.splitlines()[0].strip() if raw else None

    except Exception:
        return None


def run(target, verbose=False, ports=None):
    """Main entry point (matches the team contract)."""
    results = {
        "module": "banner_grab",
        "status": "success",
        "target": target,
        "data": {"resolved_ip": None, "banners": []},
    }

    # Bug 4 fix: resolve first, and if it fails, print a clear message
    # instead of returning silently.
    try:
        ip = socket.gethostbyname(target)
        results["data"]["resolved_ip"] = ip
    except socket.gaierror:
        results["status"] = "error"
        results["data"]["error"] = f"Target could not be resolved: {target}"
        print(f"[BANNER] ERROR: target could not be resolved -> {target}")
        return results

    # Improvement 1: if a list of open ports was passed in (from the port
    # scanner), only grab banners on those. Otherwise use a default set.
    if ports is None:
        ports = [21, 22, 25, 80, 110, 143, 443, 8080, 8443]

    if not ports:
        print("[BANNER] No open ports to grab banners from.")
        return results

    if verbose:
        print(f"[BANNER] Resolved {target} -> {ip}")
        print(f"[BANNER] Attempting banners on {len(ports)} port(s)...\n")

    for port in ports:
        banner = grab_banner(target, ip, port)
        if banner:
            short = banner.splitlines()[0][:120]
            results["data"]["banners"].append({"port": port, "banner": short})
            print(f"[BANNER] Port {port:<5} -> {short}")
        elif verbose:
            print(f"[BANNER] Port {port:<5} -> (no banner)")

    # Bug 4 (extended): if nothing was found at all, say so clearly.
    if not results["data"]["banners"]:
        print("[BANNER] No reachable services returned a banner.")
    elif verbose:
        print(f"\n[BANNER] Done. {len(results['data']['banners'])} banner(s) retrieved.")

    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"[*] Standalone banner test on {t}\n")
    print(json.dumps(run(t, verbose=True), indent=2))
