# LambdaEye

**A lightweight, modular reconnaissance tool for authorized penetration-testing engagements.**

LambdaEye automates the initial information-gathering phase of a security assessment. It bundles several recon functions into one command-line tool, each built as an independent module that returns structured data and can be run on its own or together.

> Built as part of the ITSolera Offensive Security internship by **Team Lambda**.
> This repository contains the **active reconnaissance** modules. Passive reconnaissance is maintained by the rest of the team and shares the same modular architecture.

---

## Features

**Active Reconnaissance**

- **Port scanning** — socket-based TCP scanner over a set of common ports, with hostname-to-IP resolution.
- **Banner grabbing** — reads service banners from open ports, including TLS-aware handling for HTTPS (port 443/8443) so encrypted services can be fingerprinted.
- **Technology detection** — fingerprints a website's stack from HTTP response headers, cookie names, HTML body signatures, and a set of well-known probe paths (e.g. `/wp-login.php`, `/robots.txt`). Extracts software version numbers where the target discloses them.

**Reporting**

- Generates a report in both **`.txt`** and **`.html`** formats.
- Every report includes a **timestamp** and the **resolved target IP**.
- Reports are saved to the `reports/` directory, uniquely named per scan.

**Design**

- Fully **modular** — each capability is a separate file in `modules/` exposing a `run(target, verbose=False)` function that returns a dictionary.
- **Verbosity levels** via the `-v` flag for detailed output.
- Individual modules can be run standalone for testing.

---

## Requirements

- Python 3.8 or newer
- Linux, macOS, or Windows (developed and tested on Linux)

Python dependencies are listed in `requirements.txt`:

- `requests`

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/lambdaeye.git
cd lambdaeye

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```
python3 recon.py <target> [flags]
```

### Flags

| Flag          | Description                                        |
|---------------|----------------------------------------------------|
| `--ports`     | Scan for open ports                                |
| `--banner`    | Grab service banners from open ports               |
| `--tech`      | Detect web technologies in use                     |
| `--all`       | Run every available module                         |
| `--report`    | Save results to `reports/` as `.txt` and `.html`   |
| `-v`, `--verbose` | Show detailed output while running             |
| `-h`, `--help`    | Show the help menu                             |

### Examples

```bash
# Scan a target for open ports
python3 recon.py scanme.nmap.org --ports

# Detect web technologies, with detailed output
python3 recon.py example.com --tech -v

# Run everything and save a report
python3 recon.py example.com --all --report

# Grab banners only
python3 recon.py scanme.nmap.org --banner
```

Each module can also be run on its own for testing:

```bash
python3 modules/port_scan.py scanme.nmap.org
python3 modules/tech_detect.py example.com
```

---

## Sample Output

```
[*] Starting recon on target: example.com

[PORTS] Port 80    OPEN   (HTTP)
[PORTS] Port 443   OPEN   (HTTPS)
[BANNER] Port 443  -> nginx/1.24.0
[TECH]   URL: https://example.com  (HTTP 200)
[TECH]   Detected -> nginx 1.24.0
[TECH]   Detected -> WordPress
[TECH]   Detected -> jQuery

[*] Report saved:
    reports/example.com_20260704_153644.txt
    reports/example.com_20260704_153644.html

[*] Recon complete.
```

A sample report is included in the `sample_report/` directory.

---

## Project Structure

```
lambdaeye/
├── recon.py              # CLI entry point / control panel
├── modules/              # Recon modules (each returns a result dict)
│   ├── port_scan.py      # Socket-based port scanner
│   ├── banner_grab.py    # TLS-aware banner grabbing
│   └── tech_detect.py    # Web technology fingerprinting
├── utils/
│   └── reporter.py       # Builds .txt and .html reports
├── reports/              # Generated reports (git-ignored)
├── requirements.txt
└── README.md
```

---

## Known Limitations

- **Hidden server details.** Many well-configured servers and CDNs intentionally strip identifying headers (e.g. `server_tokens off`). When a target hides this information, no banner grabber can recover it — this is expected behaviour and is itself a useful finding (good security posture on the target's part).
- **JavaScript-rendered content.** Technology detection reads the raw HTML response. Sites that build their content client-side with heavy JavaScript (some React/Vue/Angular apps) may expose fewer signatures, since the tool does not run a headless browser.
- **Common-port scanning.** The port scanner checks a curated list of common ports rather than the full 65,535 range, favouring speed and readability.

---

## Future Enhancements

- Load technology signatures from an external `signatures.json` file for easier extension.
- Add confidence levels to technology detections.
- Optional full-range and threaded/async port scanning for speed.
- Version-to-CVE lookups to flag known-vulnerable software versions.
- Protocol-specific banner handlers (SSH, FTP, SMTP) for richer service detection.

---

## Legal & Responsible Use

LambdaEye is intended **only** for use against systems you own or are explicitly authorized to test. Active reconnaissance — including port scanning, banner grabbing, and path probing — sends requests directly to the target and may be illegal without permission.

Before scanning any target, ensure that **at least one** of the following is true:

- You own or control the system, **or**
- You have explicit written authorization from the owner, **or**
- The target is a designated public practice host (e.g. `scanme.nmap.org`) or an intentionally-vulnerable lab (e.g. DVWA, OWASP Juice Shop, TryHackMe, HackTheBox).

The authors accept no responsibility for misuse. Use this tool ethically and legally.

---

## License

Released for educational use as part of the ITSolera internship program.
