#!/usr/bin/env python3
"""
port_scan.py - Active recon module: socket-based port scanner.
Optimized & Approved by Code Review. Safe for external tools without changing recon.py.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_WORKERS = 12
DEFAULT_TIMEOUT = 0.8

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-alt",
}

TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 20, 69, 123, 161, 162,
    389, 636, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3000,
    3128, 3268, 4444, 5000, 5060, 5432, 5601, 5985, 5986, 6379, 6443, 7001,
    8000, 8008, 8081, 8181, 8291, 8834, 9000, 9090, 9200, 9300, 10000,
    11211, 27017, 27018, 50000, 465, 587, 514, 873, 902, 990, 1080, 1194,
    1701, 1900, 2000, 2121, 3690, 4022, 4433, 5222, 5269, 5555, 5672, 5800,
    6000, 6667, 7000, 7070, 7443, 8009, 8010, 8443, 8880, 9091, 9999,
]


def scan_port(ip, port, timeout=DEFAULT_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False


def _resolve_port_list(ports, port_range, profile):
    if ports:
        return list(ports)
    if port_range:
        try:
            start, end = port_range.split("-")
            return list(range(int(start), int(end) + 1))
        except Exception:
            return list(COMMON_PORTS.keys())
    if profile == "top100":
        return sorted(set(TOP_100))
    
    if profile == "top1000" or profile == "first1000":  
        return list(range(1, 1001))
    return list(COMMON_PORTS.keys())


def run(target, verbose=False, ports=None, port_range=None, profile="common"):
    results = {
        "module": "port_scan", "status": "success", "target": target,
        "data": {"resolved_ip": None, "open_ports": [], "scanned_count": 0},
    }

    try:
        ip = socket.gethostbyname(target)
        results["data"]["resolved_ip"] = ip
    except socket.gaierror:
        results["status"] = "error"
        results["data"]["error"] = f"Could not resolve host: {target}"
        print(f"[PORTS]  ERROR: could not resolve host -> {target}")
        return results

    ports_to_scan = _resolve_port_list(ports, port_range, profile)
    total_ports = len(ports_to_scan)
    results["data"]["scanned_count"] = total_ports

    print(f"[PORTS] Resolved {target} -> {ip}")
    print(f"[PORTS] Scanning {total_ports} ports (Balanced Threading Mode)...\n")

    open_ports_list = []
    processed_count = 0
    
    
    progress_interval = 100 if total_ports > 200 else 10

    with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports_to_scan}
        
        for future in as_completed(futures):
            port, is_open = future.result()
            processed_count += 1
            
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                open_ports_list.append({"port": port, "service": service})
                print(f"[PORTS] Port {port:<5} OPEN   ({service})")
            elif verbose:
                print(f"[PORTS] Port {port:<5} closed")
                
           
            if processed_count % progress_interval == 0 or processed_count == total_ports:
                print(f"[PORTS] Progress: {processed_count}/{total_ports} ports scanned...")


    results["data"]["open_ports"] = sorted(open_ports_list, key=lambda x: x["port"])

    found = len(results["data"]["open_ports"])
    print(f"\n[PORTS] Done. {found} open port(s) found.")
    return results


if __name__ == "__main__":
    import json, sys
    t = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    run(t, verbose=False, profile="top1000")
