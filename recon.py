#!/usr/bin/env python3
"""
LambdaRecon — a modular reconnaissance tool for authorized pentesting.
Entry point: parses command-line flags and dispatches to the right module.
"""

import argparse   # built-in: reads command-line flags
import sys         # built-in: lets us exit cleanly on errors


def parse_arguments():
    """Define and read all the command-line flags the tool accepts."""
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="LambdaRecon — modular recon for authorized engagements.",
        epilog="Example: python3 recon.py scanme.nmap.org --ports"
    )

    # The target is required — the domain or IP to scan.
    parser.add_argument(
        "target",
        help="The domain or IP to investigate (e.g. scanme.nmap.org)"
    )

    # Active recon flags (yours). Passive ones will be added when your
    # teammate's modules are merged in.
    parser.add_argument("--ports", action="store_true",
                        help="Scan for open ports")
    parser.add_argument("--banner", action="store_true",
                        help="Grab service banners from open ports")
    parser.add_argument("--tech", action="store_true",
                        help="Detect web technologies in use")
    parser.add_argument("--report", action="store_true",
                        help="Save results to reports/ as .txt and .html")
    # Run everything at once.
    parser.add_argument("--all", action="store_true",
                        help="Run every available recon module")

    # Verbosity for the logging requirement.
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output while running")

    return parser.parse_args()


def main():
    args = parse_arguments()

    # If a target was given but no module chosen, warn instead of doing nothing.
    any_module = (args.ports or args.banner or args.tech or args.all)
    if not any_module:
        print("[!] No recon module selected. Use --ports, --banner, --tech, or --all.")
        print("    Run 'python3 recon.py -h' to see all options.")
        sys.exit(1)

    print(f"[*] Starting recon on target: {args.target}\n")

    all_results = {}   # collects every module's dict (for the report later)

    # --- Dispatch section ---
    if args.ports or args.all:
        from modules import port_scan
        all_results["ports"] = port_scan.run(args.target, args.verbose)

    # (banner and tech modules will be added here as we build them)
    if args.banner or args.all:
        from modules import banner_grab
        all_results["banner"] = banner_grab.run(args.target, args.verbose)

    if args.tech or args.all:
        from modules import tech_detect
        all_results["tech"] = tech_detect.run(args.target, args.verbose)
    
    if args.report and all_results:
        from utils import reporter
        txt_path, html_path = reporter.generate_report(args.target, all_results)
        print(f"\n[*] Report saved:")
        print(f"    {txt_path}")
        print(f"    {html_path}")
    
        print("\n[*] Recon complete.")


if __name__ == "__main__":
    main()

