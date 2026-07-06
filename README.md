# LambdaEye

**A lightweight, modular reconnaissance tool for authorized penetration-testing engagements.**

LambdaEye automates the initial information-gathering phase of a security assessment. It combines passive and active reconnaissance into a single command-line tool, where each capability is an independent module that returns structured data and can be run on its own or together.

> Built as part of the ITSolera Offensive Security internship by **Team Lambda**.

---

## Features

### Passive Reconnaissance
- **WHOIS lookup** — retrieves domain registration details (registrar, creation/expiration dates, name servers, status).
- **DNS enumeration** — queries A, MX, TXT, and NS records and resolves the target's primary IP.
- **Subdomain enumeration** — passive subdomain discovery from public OSINT sources (crt.sh, AlienVault OTX, HackerTarget, Anubis). No brute forcing.

### Active Reconnaissance
- **Port scanning** — socket-based TCP scanner over common ports, with hostname-to-IP resolution.
- **Banner grabbing** — reads service banners from open ports, with TLS-aware handling for HTTPS so encrypted services can be fingerprinted.
- **Technology detection** — fingerprints a website's stack from HTTP headers, cookies, HTML body signatures, and well-known probe paths (e.g. `/wp-login.php`, `/robots.txt`). Extracts version numbers where disclosed.

### Reporting
- Generates reports in both **`.txt`** and **`.html`** formats.
- Every report includes a **timestamp** and the **resolved target IP**.
- Reports are saved to the `reports/` directory, uniquely named per scan.

### Design
- Fully **modular** — each capability is a separate file in `modules/` exposing a `run(target, verbose=False)` function that returns a dictionary.
- **Verbosity** via the `-v` flag.
- Individual modules can be run standalone for testing.

---

## Requirements

- Python 3.8 or newer
- Linux, macOS, or Windows (developed and tested on Linux)

Python dependencies (see `requirements.txt`):

- `requests`
- `dnspython`
- `python-whois`

Alternatively, use **Docker** (see below) and skip the Python setup entirely.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/sirajhussain347/lambdaeye.git
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

| Flag            | Description                                        |
|-----------------|----------------------------------------------------|
| `--whois`       | Run a WHOIS lookup                                  |
| `--dns`         | Enumerate DNS records (A, MX, TXT, NS)             |
| `--subdomains`  | Passive subdomain enumeration                      |
| `--ports`       | Scan for open ports                                |
| `--banner`      | Grab service banners from open ports               |
| `--tech`        | Detect web technologies in use                     |
| `--all`         | Run every available module                         |
| `--report`      | Save results to `reports/` as `.txt` and `.html`   |
| `-v`, `--verbose` | Show detailed output while running               |
| `-h`, `--help`  | Show the help menu                                 |

### Examples

```bash
# Full recon on a target, saving a report
python3 recon.py example.com --all --report

# Passive recon only
python3 recon.py example.com --whois --dns --subdomains

# Active recon with detailed output
python3 recon.py example.com --ports --banner --tech -v

# A single module
python3 recon.py example.com --subdomains
```

Each module can also be run on its own for testing:

```bash
python3 modules/port_scan.py example.com
python3 modules/dns_enum.py example.com
```

---

## Running with Docker

A `Dockerfile` is included, so you can run LambdaEye without installing Python or any dependencies on your host machine.

### Build the image

From the project root (where the `Dockerfile` lives):

```bash
docker build -t lambdaeye .
```

### Run it

The image's entrypoint is `python3 recon.py`, so anything you'd normally pass to `recon.py` goes after the image name.

```bash
# Show the help menu (default if no target is given)
docker run --rm lambdaeye

# Passive + active recon on a target
docker run --rm lambdaeye example.com --all -v

# A single module
docker run --rm lambdaeye scanme.nmap.org --ports
```

### Saving reports to your host machine

The container writes reports to `/app/reports`. To keep them after the container exits, mount a local `reports/` folder as a volume:

```bash
mkdir -p reports
chmod 777 reports   # ensures the container's non-root user can write to it

docker run --rm -v "$PWD/reports:/app/reports" lambdaeye example.com --all --report
```

> **Permission errors?** The container runs as a non-root user for security. If Docker auto-creates the `reports/` folder on your host (owned by root), the container won't be able to write to it. Either run `chmod 777 reports` on the host folder first, or run the container with your own user ID instead:
>
> ```bash
> docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/reports:/app/reports" lambdaeye example.com --all --report
> ```

### Docker one-liners cheat sheet

```bash
# Build
docker build -t lambdaeye .

# Help menu
docker run --rm lambdaeye

# Full recon with report saved locally
docker run --rm -v "$PWD/reports:/app/reports" lambdaeye example.com --all --report

# Active recon only, verbose
docker run --rm lambdaeye example.com --ports --banner --tech -v
```

---

## Sample Output

```
[*] Starting recon on target: example.com

[PORTS] Port 80    OPEN   (HTTP)
[PORTS] Port 443   OPEN   (HTTPS)
[BANNER] Port 443  -> openresty
[TECH]   Detected -> OpenResty (nginx + Lua)
[TECH]   Detected -> WordPress
[WHOIS]  Registrar     : Example Registrar Inc
[DNS]    A    93.184.216.34
[SUBDOM] Found 12 unique subdomain(s).

[*] Report saved:
    reports/example.com_20260704_233700.txt
    reports/example.com_20260704_233700.html

[*] Recon complete.
```

A sample report is included in the `sample_report/` directory.

---

## Project Structure

```
lambdaeye/
├── recon.py              # CLI entry point / control panel
├── modules/              # Recon modules (each returns a result dict)
│   ├── whois_lookup.py   # WHOIS lookup
│   ├── dns_enum.py       # DNS record enumeration
│   ├── subdomain_enum.py # Passive subdomain discovery
│   ├── port_scan.py      # Socket-based port scanner
│   ├── banner_grab.py    # TLS-aware banner grabbing
│   └── tech_detect.py    # Web technology fingerprinting
├── utils/
│   └── reporter.py       # Builds .txt and .html reports
├── reports/              # Generated reports (git-ignored)
├── Dockerfile             # Container build for running LambdaEye without local Python setup
├── requirements.txt
└── README.md
```

---

## Known Limitations

- **Hidden server details.** Many well-configured servers and CDNs intentionally strip identifying headers. When a target hides this information, it cannot be recovered — this is expected and is itself a useful finding.
- **Subdomain sources.** Subdomain enumeration relies on free third-party OSINT APIs, which may occasionally rate-limit or return errors. The tool queries multiple sources and degrades gracefully, using whatever responds.

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
