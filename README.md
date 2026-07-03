# NetRecon

A full-featured network reconnaissance CLI tool built on top of Nmap, designed for fast, repeatable recon during security assessments and lab work.

## Features

- **7 scan profiles** — from lightweight host discovery to full OS fingerprinting and vulnerability scanning
- **Interactive menu + CLI flag support** — run guided or scriptable
- **Multi-format reporting** — JSON, TXT, and self-contained dark-themed HTML exports
- **Multi-host support** — scan single IPs, ranges, or full CIDR subnets in one run

## Scan Profiles

| # | Profile | Description | Requires sudo |
|---|---------|-------------|----------------|
| 1 | Host Discovery | Detect live hosts on a subnet (no port scan) | No |
| 2 | Quick Port Scan | Top 1000 ports, fast | No |
| 3 | Service & Version Detection | Open ports + service banners | No |
| 4 | Full TCP Scan + Version | All 65535 ports + service version | No |
| 5 | OS Detection | Fingerprint operating system | Yes |
| 6 | Vulnerability Scan | Run Nmap vuln scripts | Yes |
| 7 | Full Recon | OS + version + vuln scripts, comprehensive | Yes |

## Installation

    git clone https://github.com/thecybergaffer/netrecon.git
    cd netrecon
    sudo pip3 install python-nmap --break-system-packages

Requires nmap to be installed on the system (pre-installed on Kali Linux; on other distros: sudo apt install nmap).

## Usage

### Interactive mode

    sudo python3 netrecon.py

Follow the on-screen menu to select a scan profile, enter a target (single IP, range, or CIDR), and optionally save the report.

### Reports

When saving is enabled, NetRecon writes three report formats to the output directory (default ./reports):

- netrecon_<target>_<timestamp>.json — structured data for further processing
- netrecon_<target>_<timestamp>.txt — plain-text summary
- netrecon_<target>_<timestamp>.html — dark-themed, self-contained report for easy viewing/sharing

## Example Output

    Port       State        Service            Version
    ----------------------------------------------------------
    21         open         ftp                vsftpd 2.3.4
    22         open         ssh                OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0
    80         open         http               Apache httpd 2.2.8 (Ubuntu) DAV/2
    3306       open         mysql              MySQL 5.0.51a-3ubuntu5

## Tested Against

- Live LAN environments
- Metasploitable 2 (single host and multi-host subnet scans)

## Roadmap

- [ ] Auto deep-scan (escalate profile based on initial findings)
- [ ] Scan comparison (diff between two reports)
- [ ] MAC vendor lookup

## Disclaimer

NetRecon is intended for authorized security testing and network administration only. Only scan systems and networks you own or have explicit permission to test.

## Author

Built by [The Cyber Gaffer](https://github.com/thecybergaffer) — MDR/SOC operator and security tooling.
