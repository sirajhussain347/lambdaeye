#!/usr/bin/env python3
"""
LambdaEye - a modular reconnaissance tool for authorized pentesting.
Entry point: parses command-line flags and dispatches to each module.
"""

import argparse
import sys
import os

# ANSI colors for the banner
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
        epilog="Example: python3 recon.py example.com --all --report"
    )
    parser.add_argument("target", help="The domain or IP to investigate")

    # Active
    parser.add_argument("--ports", action="store_true", help="Scan for open ports")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--tech", action="store_true", help="Detect web technologies")

    # Passive
    parser.add_argument("--whois", action="store_true", help="Run a WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Enumerate DNS records")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")

    # Port scan options (Improvement 2)
    parser.add_argument("--port-profile", choices=["common", "top100", "top1000"],
                        default="common", help="Port set to scan (default: common)")
    parser.add_argument("--port-range", help="Custom port range, e.g. 1-1024")

    parser.add_argument("--all", action="store_true", help="Run every module")
    parser.add_argument("--report", action="store_true",
                        help="Save results to reports/ as .txt and .html")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detailed output")

    return parser.parse_args()


def run_recon(args):
    """The actual recon workflow (separated so Ctrl+C can wrap it cleanly)."""
    any_module = (args.ports or args.banner or args.tech or
                  args.whois or args.dns or args.subdomains or args.all)
    if not any_module:
        print("[!] No recon module selected. Use --ports, --banner, --tech, "
              "--whois, --dns, --subdomains, or --all.")
        print("    Run 'python3 recon.py -h' to see all options.")
        sys.exit(1)

    print(f"[*] Starting recon on target: {args.target}\n")
    all_results = {}

    # --- Active recon ---
    open_ports = None
    if args.ports or args.all:
        from modules import port_scan
        res = port_scan.run(args.target, args.verbose,
                            port_range=args.port_range, profile=args.port_profile)
        all_results["ports"] = res
        # Improvement 1: capture the open ports to reuse for banner grabbing.
        open_ports = [p["port"] for p in res.get("data", {}).get("open_ports", [])]

    if args.banner or args.all:
        from modules import banner_grab
        # Improvement 1: if we already scanned ports, only grab banners on the
        # open ones; otherwise the module uses its own default list.
        all_results["banner"] = banner_grab.run(
            args.target, args.verbose,
            ports=open_ports if open_ports else None)

    if args.tech or args.all:
        from modules import tech_detect
        all_results["tech"] = tech_detect.run(args.target, args.verbose)

    # --- Passive recon ---
    if args.whois or args.all:
        from modules import whois_lookup
        all_results["whois"] = whois_lookup.run(args.target, args.verbose)

    if args.dns or args.all:
        from modules import dns_enum
        all_results["dns"] = dns_enum.run(args.target, args.verbose)

    if args.subdomains or args.all:
        from modules import subdomain_enum
        all_results["subdomains"] = subdomain_enum.run(args.target, args.verbose)

    # --- Reporting ---
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

    # Bug 6 fix: handle Ctrl+C gracefully instead of dumping a traceback.
    try:
        run_recon(args)
    except KeyboardInterrupt:
        print("\n\n[!] Scan cancelled by user (Ctrl+C). Exiting cleanly.")
        # Bug 6: clean up any partial report left mid-write, if present.
        sys.exit(130)   # 130 = standard exit code for Ctrl+C


if __name__ == "__main__":
    main()
