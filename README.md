# CGRecon

A full-featured network reconnaissance CLI tool built on top of Nmap, designed for fast, repeatable recon during security assessments and lab work.

> **Renamed from NetRecon.** The original `netrecon.py` (v1) remains in this repo for reference but is superseded by `cgrecon.py` (v2), which fixes a real false-positive issue found during live testing (see "Why the rewrite" below) and adds several new features.

## Features

- **8 scan profiles** — from lightweight host discovery to full OS fingerprinting and vulnerability scanning
- **Multi-probe host discovery** — combines ICMP echo, TCP SYN, and TCP ACK probes instead of a plain ARP/ICMP sweep, so networks with proxy ARP or "answer everything" firewalls don't get reported as 100% live
- **Automatic proxy-ARP sanity check** — warns if an implausible fraction of a subnet reports "up"
- **Optional TCP re-verification** — a fast, independent second opinion on which discovered hosts are actually reachable
- **MAC address + vendor lookup** — identifies device manufacturers during discovery
- **Risk-rated findings** — open ports/services are labeled Critical/High/Medium/Low (CVSS-style) with concrete remediation guidance, not just listed flatly
- **Auto-escalation** — optionally run a Quick Port Scan automatically against every host found during discovery
- **Report comparison** — diff two JSON reports to see what changed between scans of the same target
- **Formal assessment reports** — generates a professional Markdown + HTML report structured around NIST SP 800-115 and PTES methodology (scope, methodology, executive summary, severity-ranked findings), separate from the raw data export
- **Authorization gate** — the tool will not run any scan until a tester name, an authorizing party, and explicit confirmation of permission to test are provided
- **Interactive menu + CLI flag support** — run guided or fully scriptable
- **Multi-host support** — scan single IPs, ranges, or full CIDR subnets in one run

## Why the rewrite

Running v1's Host Discovery against a real office subnet returned 256 "live" hosts on a single `/24` - clearly wrong. The cause was proxy ARP: the network was answering ARP requests on behalf of every address in the range, and v1's discovery relied purely on a `-sn` ARP/ICMP sweep, which is exactly the kind of scan that fools. v2 fixes this at the root by requiring a host to answer at least one of several independent probe types, and flags the situation automatically if it happens again.

## Scan Profiles

| # | Profile | Description | Requires sudo |
|---|---------|-------------|----------------|
| 1 | Host Discovery | Multi-probe live host detection (ARP-quirk aware) | No |
| 2 | Quick Port Scan | Top 1000 ports, fast | No |
| 3 | Service & Version Detection | Open ports + service banners | No |
| 4 | Full TCP Scan + Version | All 65535 ports + service version | No |
| 5 | UDP Top Ports Scan | Top 100 UDP ports (often skipped, worth checking) | Yes |
| 6 | OS Detection | Fingerprint operating system | Yes |
| 7 | Vulnerability Scan | Run Nmap vuln scripts | Yes |
| 8 | Full Recon | OS + version + vuln scripts — comprehensive | Yes |

## Installation

```bash
git clone https://github.com/thecybergaffer/netrecon.git
cd netrecon
sudo pip3 install python-nmap --break-system-packages
```

Requires `nmap` to be installed on the system (pre-installed on Kali Linux; on other distros: `sudo apt install nmap`).

## Usage

### Interactive mode

```bash
sudo python3 cgrecon.py
```

Before anything else, you'll be asked to confirm who's testing and who authorized it:

```
AUTHORIZATION REQUIRED
--------------------------------------------------------------------
Assessment title [Network Reconnaissance & Vulnerability Assessment]:
Tester / analyst name (required):
Authorized by - name/role (required):
Confirm you have explicit permission to test this target network [y/N]:
```

Tester name and authorization are required, and the confirmation must be `y` — otherwise the tool exits without running anything. Once confirmed, follow the on-screen menu to pick a scan profile, enter a target (single IP, range, or CIDR), and optionally save reports.

### Scriptable / CLI mode

```bash
sudo python3 cgrecon.py --profile 4 --target 192.168.1.0/24 \
  --tester "Your Name" --authorized-by "IT Manager" \
  --confirm-authorized --save --report
```

| Flag | Purpose |
|---|---|
| `--profile`, `-p` | Scan profile number (1-8) |
| `--target`, `-t` | Target IP / range / CIDR |
| `--tester` | Tester/analyst name (**required**) |
| `--authorized-by` | Who authorized the test (**required**) |
| `--confirm-authorized` | Explicit permission confirmation (**required**) |
| `--save` | Write raw JSON/TXT/HTML reports |
| `--verify` | Re-verify discovery results with TCP connects |
| `--escalate` | Auto-run a Quick Port Scan on discovered live hosts |
| `--report` | Generate the formal assessment report (exec summary, methodology, remediation) |
| `--title` | Assessment title for the formal report |
| `--compare A B` | Diff two prior JSON reports |

### Comparing two reports

```bash
python3 cgrecon.py --compare old_scan.json new_scan.json
```

## Reports

When saving is enabled, CGRecon writes reports to the output directory (default `./reports`):

- `cgrecon_<kind>_<target>_<timestamp>.json` — structured data for further processing
- `cgrecon_<kind>_<target>_<timestamp>.txt` — plain-text summary
- `cgrecon_<kind>_<target>_<timestamp>.html` — dark-themed, self-contained report for easy viewing/sharing

If `--report` (or the interactive equivalent) is used, a separate formal assessment report is also generated:

- `cgrecon_assessment_<target>_<timestamp>.md`
- `cgrecon_assessment_<target>_<timestamp>.html`

These include a scope/authorization section, methodology notes referencing NIST SP 800-115 and PTES, an executive summary, and findings ranked by severity with remediation guidance — meant to be handed to a non-technical stakeholder, not just read by the person running the scan.

> Severity labels (Critical/High/Medium/Low) follow the CVSS v3.1 qualitative scale but are heuristic, keyword-based triage ratings, not calculated CVSS scores. Verify any CVE surfaced by vulnerability scripts against the National Vulnerability Database (nvd.nist.gov) before citing it externally.

## Example Output

```
Port       Proto   State     Service            Version                      Risk
------------------------------------------------------------------------------------
21         tcp     open      ftp                vsftpd 2.3.4                 HIGH
22         tcp     open      ssh                OpenSSH 4.7p1 Debian 8ubuntu1 LOW
80         tcp     open      http               Apache httpd 2.2.8 (Ubuntu)  LOW
3306       tcp     open      mysql              MySQL 5.0.51a-3ubuntu5       MEDIUM
```

## Tested Against

- Live LAN environments (home and office networks)
- A real proxy-ARP network scenario that produced 256 false "live" hosts under v1 — resolved under v2's multi-probe discovery
- Metasploitable 2 (single host and multi-host subnet scans)

## Roadmap

- [x] Auto deep-scan (escalate profile based on initial findings)
- [x] Scan comparison (diff between two reports)
- [x] MAC vendor lookup
- [x] Formal, presentation-ready assessment reports
- [x] Pre-scan authorization gate
- [ ] Export findings directly to a SIEM-friendly format (e.g. CEF or a Wazuh-compatible log format)
- [ ] Scheduled/cron-friendly non-interactive scan mode with report diffing against the last run

## Disclaimer

CGRecon is intended for authorized security testing and network administration only. Only scan systems and networks you own or have explicit permission to test. The tool enforces this at runtime via a mandatory authorization gate before any scan is executed.

## Author

Built by [The Cyber Gaffer](https://github.com/thecybergaffer) — MDR/SOC operator and security tooling.
