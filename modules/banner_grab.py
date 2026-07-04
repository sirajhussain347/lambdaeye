#!/usr/bin/env python3
"""
banner_grab.py — Active recon module: service banner grabbing.

Connects to open ports and reads the banner the service sends back,
revealing software name/version where the target discloses it.
Handles plain HTTP, encrypted HTTPS (TLS), and talkative services
(SSH/FTP/SMTP). Part of the LambdaRecon tool (active recon).

Contract: exposes run(target, verbose=False) and returns a dict.
"""

import socket   # built-in: networking
import ssl      # built-in: wraps a socket for encrypted (TLS) connections


# Ports that speak encrypted TLS and must be wrapped with ssl.
TLS_PORTS = {443, 8443}
# Plain-text web ports: need an HTTP request but no encryption.
HTTP_PORTS = {80, 8080}


def _read_all(sock, timeout=3.0):
    """
    Keep reading from the socket until the server stops sending.
    Servers often split their response across multiple packets, so a
    single recv() can miss data (Problem 2 from the review). This loops
    until the connection closes or times out, then returns all bytes.
    """
    sock.settimeout(timeout)
    chunks = b""
    while True:
        try:
            data = sock.recv(4096)
            if not data:          # empty = server finished sending
                break
            chunks += data
        except socket.timeout:
            break                 # no more data arriving; stop waiting
    return chunks


def _extract_server(raw_text):
    """
    Pull the value of the 'Server:' header out of an HTTP response.
    Returns just the software string (e.g. 'nginx/1.26.1'), or if the
    server hides its identity, falls back to the status line so we still
    report *something* (Problem 3 + Problem 5 from the review).
    """
    server = None
    for line in raw_text.splitlines():
        if line.lower().startswith("server:"):
            # split on the first colon, keep the value side, trim spaces
            server = line.split(":", 1)[1].strip()
            break

    if server:
        return server

    # No Server header (often deliberately hidden) — return status line.
    lines = raw_text.splitlines()
    return lines[0].strip() if lines else None


def grab_banner(hostname, ip, port, timeout=3.0):
    """
    Connect to ONE open port and try to read its banner.

    hostname : the domain (used in the Host header + TLS SNI)
    ip       : resolved IP to actually connect to
    port     : the port number

    Returns banner/server string, or None.
    """
    try:
        # create_connection handles the socket + connect in one step.
        sock = socket.create_connection((ip, port), timeout)

        # Encrypted ports: wrap the socket in TLS before talking.
        if port in TLS_PORTS:
            context = ssl.create_default_context()
            # We only want the banner, not to verify the cert, so relax checks.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # server_hostname (SNI) lets multi-site servers pick the right cert.
            sock = context.wrap_socket(sock, server_hostname=hostname)

        if port in TLS_PORTS or port in HTTP_PORTS:
            # --- Web ports: send a proper GET request ---
            # GET (not HEAD) tends to return more headers. The Host header
            # carries the DOMAIN NAME, not the IP, so virtual-hosted servers
            # know which site we mean (Problem 1 from the review).
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: Mozilla/5.0 (LambdaRecon)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            raw = _read_all(sock).decode(errors="ignore")
            sock.close()
            return _extract_server(raw)
        else:
            # --- Talkative services (SSH/FTP/SMTP): they greet first ---
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

    # Resolve the domain to an IP (sockets connect to IPs).
    try:
        ip = socket.gethostbyname(target)
        results["data"]["resolved_ip"] = ip
    except socket.gaierror:
        results["status"] = "error"
        results["data"]["error"] = f"Could not resolve host: {target}"
        return results

    if ports is None:
        ports = [21, 22, 25, 80, 110, 143, 443, 8080, 8443]

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

    if verbose:
        n = len(results["data"]["banners"])
        print(f"\n[BANNER] Done. {n} banner(s) retrieved.")

    return results


# Standalone test:  python3 modules/banner_grab.py [target]
if __name__ == "__main__":
    import json, sys
    test_target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"[*] Standalone banner test on {test_target}\n")
    output = run(test_target, verbose=True)
    print("\n[*] Returned dictionary:")
    print(json.dumps(output, indent=2))
