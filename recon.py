#!/usr/bin/env python3
"""
LambdaEye - a modular reconnaissance tool for authorized pentesting.
Entry point: parses command-line flags and dispatches to each module.
"""

import argparse
import sys
import os

CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = rf"""{CYAN}
    __                  __        __      ______
   / /   ____ _____ ___/ /_  ____/ /___ _/ ____/_  _____
  / /   / __ `/ __ `__ \ '_ \/ __  / __ `/ __/ / / / / _ \
 / /___/ /_/ / / / / / / /_/ / /_/ / /_/ / /___/ /_/ /  __/
/_____/\__,_/_/ /_/ /_/_.___/\__,_/\__,_/_____/\__, /\___/
                                              /____/
{RESET}{BOLD}          Modular Reconnaissance Tool{RESET}
{YELLOW}          Team Lambda  |  Authorized use only{RESET}
"""
    print(banner)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="LambdaEye - modular recon for authorized engagements.",
        epilog="Example: python3 recon.py example.com --all --report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional target
    parser.add_argument("target", help="The domain or IP to investigate")

    # --- Passive recon group ---
    passive = parser.add_argument_group("Passive Reconnaissance")
    passive.add_argument("--whois", action="store_true", help="Run a WHOIS lookup")
    passive.add_argument("--dns", action="store_true", help="Enumerate DNS records (A, MX, TXT, NS)")
    passive.add_argument("--subdomains", action="store_true", help="Passive subdomain enumeration")

    # --- Active recon group ---
    active = parser.add_argument_group("Active Reconnaissance")
    active.add_argument("--ports", action="store_true", help="Scan for open ports")
    active.add_argument("--banner", action="store_true", help="Grab service banners from open ports")
    active.add_argument("--tech", action="store_true", help="Detect web technologies in use")

    # --- Port scan options group ---
    portopts = parser.add_argument_group("Port Scan Options")
    portopts.add_argument("--port-profile", choices=["common", "top100", "top1000"],
                          default="common", help="Port set to scan (default: common)")
    portopts.add_argument("--port-range", help="Custom port range, e.g. 1-1024")

    # --- General options group ---
    general = parser.add_argument_group("General Options")
    general.add_argument("--all", action="store_true", help="Run every available module")
    general.add_argument("--report", action="store_true",
                         help="Save results to reports/ as .txt and .html")
    general.add_argument("-v", "--verbose", action="store_true",
                         help="Show detailed output while running")

    return parser.parse_args()


def run_recon(args):
    any_module = (args.ports or args.banner or args.tech or
                  args.whois or args.dns or args.subdomains or args.all)
    if not any_module:
        print("[!] No recon module selected. Use --ports, --banner, --tech, "
              "--whois, --dns, --subdomains, or --all.")
        print("    Run 'python3 recon.py -h' to see all options.")
        sys.exit(1)

    print(f"[*] Starting recon on target: {args.target}\n")
    all_results = {}

    open_ports = None
    if args.ports or args.all:
        from modules import port_scan
        res = port_scan.run(args.target, args.verbose,
                            port_range=args.port_range, profile=args.port_profile)
        all_results["ports"] = res
        open_ports = [p["port"] for p in res.get("data", {}).get("open_ports", [])]

    if args.banner or args.all:
        from modules import banner_grab
        all_results["banner"] = banner_grab.run(
            args.target, args.verbose,
            ports=open_ports if open_ports else None)

    if args.tech or args.all:
        from modules import tech_detect
        all_results["tech"] = tech_detect.run(args.target, args.verbose)

    if args.whois or args.all:
        from modules import whois_lookup
        all_results["whois"] = whois_lookup.run(args.target, args.verbose)

    if args.dns or args.all:
        from modules import dns_enum
        all_results["dns"] = dns_enum.run(args.target, args.verbose)

    if args.subdomains or args.all:
        from modules import subdomain_enum
        all_results["subdomains"] = subdomain_enum.run(args.target, args.verbose)

    if args.report and all_results:
        from utils import reporter
        txt_path, html_path = reporter.generate_report(args.target, all_results)
        print(f"\n[*] Report saved:")
        print(f"    {txt_path}")
        print(f"    {html_path}")

    print("\n[*] Recon complete.")


def main():
    print_banner()
    args = parse_arguments()
    try:
        run_recon(args)
    except KeyboardInterrupt:
        print("\n\n[!] Scan cancelled by user (Ctrl+C). Exiting cleanly.")
        sys.exit(130)


if __name__ == "__main__":
    main()
