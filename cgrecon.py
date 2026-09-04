#!/usr/bin/env python3
"""
CGRecon v2.0 - CyberG Network Reconnaissance Tool
Built on top of Nmap. Adds reliability fixes and features on top of v1:

  - Multi-probe host discovery (ICMP + TCP SYN + TCP ACK) instead of a
    plain ARP/ICMP sweep, so networks with proxy ARP or "answer everything"
    firewalls don't get reported as 100% live.
  - Automatic sanity-check warning if an implausibly high fraction of a
    subnet reports "up" (a strong signal of proxy ARP / promiscuous
    network behaviour).
  - Optional lightweight socket-level re-verification of "up" hosts.
  - MAC address + vendor lookup on local-subnet discovery (nmap already
    knows this when scanning a directly-attached network).
  - Risk-rated port/service table (flags things like telnet, exposed
    databases, RDP, VNC etc. instead of just listing them flatly).
  - Optional auto-escalation: after host discovery, offer to run a quick
    port scan against every live host automatically.
  - JSON / TXT / HTML report export (dark-themed, self-contained HTML).
  - Report comparison: diff two JSON reports to see what changed between
    scans of the same target.
  - Both an interactive menu (like v1) and scriptable CLI flags.

Only scan systems and networks you own or have explicit permission to test.
"""

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
from datetime import datetime

try:
    import nmap
except ImportError:
    print("[!] Missing dependency: python-nmap")
    print("    Install with: sudo pip3 install python-nmap --break-system-packages")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
   ____ ____  ____                       
  / ___/ ___||  _ \ ___  ___ ___  _ __  
 | |  | |  _ | |_) / _ \/ __/ _ \| '_ \ 
 | |__| |_| ||  _ <  __/ (_| (_) | | | |
  \____\____||_| \_\___|\___\___/|_| |_|

   CyberG Network Reconnaissance Tool  |  v2.0
   ---------------------------------------------
"""

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_GREY = "\033[90m"

RISK_COLOR = {
    "CRITICAL": C_RED,
    "HIGH": C_RED,
    "MEDIUM": C_YELLOW,
    "LOW": C_GREEN,
    "INFO": C_GREY,
}

# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------
# Host discovery deliberately doesn't rely on a single probe type. Some
# networks will make a plain "-sn" ARP/ICMP sweep report every address as
# "up" (proxy ARP, overly helpful firewalls, etc). Combining ICMP echo with
# a few TCP SYN probes and a TCP ACK probe means a host has to answer at
# least one of several different probe types to be counted as live.

HOST_DISCOVERY_ARGS = "-sn -PE -PS22,80,443,3389 -PA80 -PP"

SCAN_PROFILES = {
    "1": {
        "name": "Host Discovery",
        "desc": "Detect live hosts on a subnet (multi-probe, ARP-quirk aware)",
        "args": HOST_DISCOVERY_ARGS,
        "sudo": False,
        "discovery": True,
    },
    "2": {
        "name": "Quick Port Scan",
        "desc": "Top 1000 ports, fast",
        "args": "-T4 -F",
        "sudo": False,
    },
    "3": {
        "name": "Service & Version Detection",
        "desc": "Open ports + service banners",
        "args": "-sV -T4",
        "sudo": False,
    },
    "4": {
        "name": "Full TCP Scan + Version",
        "desc": "All 65535 ports + service version",
        "args": "-p- -sV -T4",
        "sudo": False,
    },
    "5": {
        "name": "UDP Top Ports Scan",
        "desc": "Top 100 UDP ports (often skipped, worth checking)",
        "args": "-sU --top-ports 100 -T4",
        "sudo": True,
    },
    "6": {
        "name": "OS Detection",
        "desc": "Fingerprint operating system",
        "args": "-O",
        "sudo": True,
    },
    "7": {
        "name": "Vulnerability Scan",
        "desc": "Run Nmap vuln scripts",
        "args": "-sV --script vuln",
        "sudo": True,
    },
    "8": {
        "name": "Full Recon",
        "desc": "OS + version + vuln scripts - comprehensive",
        "args": "-sV -O --script vuln",
        "sudo": True,
    },
}

# Rough, opinionated risk ratings for common services. Not exhaustive -
# meant to draw the eye to things worth checking first, not to be a
# definitive vulnerability assessment.
RISK_KEYWORDS = {
    "telnet": "CRITICAL",
    "rlogin": "CRITICAL",
    "rsh": "CRITICAL",
    "vnc": "HIGH",
    "rdp": "HIGH",
    "ms-wbt-server": "HIGH",
    "microsoft-ds": "HIGH",
    "smb": "HIGH",
    "netbios-ssn": "MEDIUM",
    "ftp": "HIGH",
    "redis": "HIGH",
    "mongodb": "HIGH",
    "elasticsearch": "HIGH",
    "mysql": "MEDIUM",
    "mssql": "MEDIUM",
    "postgresql": "MEDIUM",
    "ssh": "LOW",
    "http": "LOW",
    "https": "LOW",
}


def get_risk(service_name):
    service_name = (service_name or "").lower()
    for keyword, rating in RISK_KEYWORDS.items():
        if keyword in service_name:
            return rating
    return "LOW"


# Short, generic remediation guidance keyed the same way as RISK_KEYWORDS.
# Intentionally generic - a real fix depends on the specific host/version,
# but this gives a report reader a concrete first action instead of just
# a severity label.
REMEDIATIONS = {
    "telnet": "Disable Telnet; replace with SSH (encrypted, key-based auth).",
    "rlogin": "Disable rlogin/rsh; these transmit credentials in cleartext.",
    "rsh": "Disable rlogin/rsh; these transmit credentials in cleartext.",
    "vnc": "Restrict VNC to a VPN/jump host, enforce strong auth, or disable if unused.",
    "rdp": "Restrict RDP to VPN access only; enforce NLA and strong passwords/MFA.",
    "ms-wbt-server": "Restrict RDP to VPN access only; enforce NLA and strong passwords/MFA.",
    "microsoft-ds": "Restrict SMB to trusted internal hosts; disable SMBv1; patch regularly.",
    "smb": "Restrict SMB to trusted internal hosts; disable SMBv1; patch regularly.",
    "netbios-ssn": "Disable NetBIOS if not required; segment legacy Windows services.",
    "ftp": "Replace with SFTP/FTPS; disable anonymous login if enabled.",
    "redis": "Bind to localhost or internal-only interface; require authentication.",
    "mongodb": "Bind to localhost or internal-only interface; require authentication.",
    "elasticsearch": "Do not expose to the internet; require authentication and TLS.",
    "mysql": "Restrict to application servers only; avoid exposing to the wider network.",
    "mssql": "Restrict to application servers only; avoid exposing to the wider network.",
    "postgresql": "Restrict to application servers only; avoid exposing to the wider network.",
    "ssh": "Keep patched; disable password auth in favour of keys where possible.",
    "http": "Confirm this is intended to be reachable; enforce HTTPS where possible.",
    "https": "Confirm certificate validity and TLS configuration are current.",
}


def get_remediation(service_name):
    service_name = (service_name or "").lower()
    for keyword, advice in REMEDIATIONS.items():
        if keyword in service_name:
            return advice
    return "Review whether this service needs to be exposed; apply vendor patches."


RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def require_authorization():
    """Gate: no scan runs until tester identity and explicit authorization are
    confirmed. This mirrors the 'rules of engagement' step every recognized
    testing methodology (NIST SP 800-115, PTES) requires before Discovery
    begins - authorization is captured before, not after, scanning starts."""
    print(BANNER)
    print("AUTHORIZATION REQUIRED")
    print("-" * 78)
    print("Before any scan runs, confirm who is testing and who authorized it.")
    print("Only scan systems and networks you own or have explicit permission to test.")
    print("-" * 78)

    title = input("\nAssessment title [Network Reconnaissance & Vulnerability Assessment]: ").strip() or None

    tester = ""
    while not tester:
        tester = input("Tester / analyst name (required): ").strip()
        if not tester:
            print(f"{C_RED}This field is required - enter a name to continue.{C_RESET}")

    authorized_by = ""
    while not authorized_by:
        authorized_by = input("Authorized by - name/role (required): ").strip()
        if not authorized_by:
            print(f"{C_RED}This field is required - enter who authorized this test.{C_RESET}")

    confirmed = ""
    while confirmed not in ("y", "n"):
        confirmed = input(
            "Confirm you have explicit permission to test this target network [y/N]: "
        ).strip().lower() or "n"

    if confirmed != "y":
        print(f"\n{C_RED}Authorization not confirmed - exiting without running any scan.{C_RESET}")
        sys.exit(1)

    meta = build_report_metadata("(not yet set)", tester=tester, authorized_by=authorized_by, title=title)
    print(f"\n{C_GREEN}[+] Authorization recorded:{C_RESET}")
    print(f"    Tester       : {meta['tester']}")
    print(f"    Authorized by: {meta['authorized_by']}")
    print(f"    Title        : {meta['title']}")
    print("-" * 78)
    return meta


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def run_host_discovery(nm, target):
    print(f"\n{C_CYAN}[*]{C_RESET} Target     : {C_BOLD}{target}{C_RESET}")
    print(f"{C_CYAN}[*]{C_RESET} Nmap args  : {HOST_DISCOVERY_ARGS}")
    print(f"{C_CYAN}[*]{C_RESET} Started    : {datetime.now()}\n")
    print("Scanning... (multi-probe discovery, may take a little longer than a plain ping sweep)\n")

    nm.scan(hosts=target, arguments=HOST_DISCOVERY_ARGS)

    hosts = []
    for host in nm.all_hosts():
        info = nm[host]
        mac = info["addresses"].get("mac")
        vendor = info["vendor"].get(mac, "") if mac else ""
        hostname = ""
        if info.hostnames():
            hostname = info.hostnames()[0].get("name", "") or ""
        hosts.append(
            {
                "ip": host,
                "hostname": hostname or "N/A",
                "state": info.state(),
                "mac": mac or "N/A",
                "vendor": vendor or "N/A",
            }
        )

    hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".")))
    return hosts


def proxy_arp_sanity_check(target, hosts):
    """Warn if an implausible fraction of the target range reports 'up'."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        total_addresses = network.num_addresses
    except ValueError:
        return  # single IP or range syntax we can't easily size - skip check

    if total_addresses < 8:
        return  # too small a range for this heuristic to mean much

    up_count = sum(1 for h in hosts if h["state"] == "up")
    fraction_up = up_count / total_addresses

    if fraction_up >= 0.9:
        print(
            f"\n{C_YELLOW}[!] WARNING:{C_RESET} {up_count}/{total_addresses} "
            f"addresses ({fraction_up:.0%}) reported UP on {target}."
        )
        print(
            f"{C_YELLOW}    This is unusual for a real network and often means proxy ARP,\n"
            f"    an overly helpful firewall, or another device answering on behalf\n"
            f"    of the whole range. Treat these results with caution - consider\n"
            f"    re-running with --verify, or spot-checking a few addresses by hand\n"
            f"    (e.g. ping / connect to a specific service) before trusting this list."
            f"{C_RESET}\n"
        )


def verify_hosts(hosts, ports=(80, 443, 22, 3389), timeout=0.6):
    """Lightweight socket-level re-check of 'up' hosts, independent of nmap.

    Not a replacement for the nmap probes above - just a fast second
    opinion using raw TCP connects, useful for flagging results that came
    only from a single (possibly unreliable) probe type.
    """
    print(f"\n{C_CYAN}[*]{C_RESET} Re-verifying {len(hosts)} host(s) with direct TCP connects...")
    for h in hosts:
        if h["state"] != "up":
            h["verified"] = False
            continue
        confirmed = False
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((h["ip"], port))
                    if result == 0:
                        confirmed = True
                        break
            except (socket.gaierror, OSError):
                continue
        h["verified"] = confirmed
    return hosts


def print_discovery_results(hosts, verified_included=False):
    print(f"\n{C_GREEN}[+] Discovery complete - {len(hosts)} host(s) found{C_RESET}")
    print("-" * 78)
    header = f"{'IP':<16}{'Hostname':<20}{'MAC':<19}{'Vendor':<18}"
    if verified_included:
        header += "Verified"
    print(header)
    print("-" * 78)
    for h in hosts:
        line = f"{h['ip']:<16}{h['hostname']:<20}{h['mac']:<19}{h['vendor']:<18}"
        if verified_included:
            mark = f"{C_GREEN}yes{C_RESET}" if h.get("verified") else f"{C_YELLOW}no{C_RESET}"
            line += mark
        print(line)
    print("-" * 78)


# ---------------------------------------------------------------------------
# Port / service scans
# ---------------------------------------------------------------------------

def run_port_scan(nm, target, profile):
    print(f"\n{C_CYAN}[*]{C_RESET} Target     : {C_BOLD}{target}{C_RESET}")
    print(f"{C_CYAN}[*]{C_RESET} Profile    : {profile['name']}")
    print(f"{C_CYAN}[*]{C_RESET} Nmap args  : {profile['args']}")
    print(f"{C_CYAN}[*]{C_RESET} Started    : {datetime.now()}\n")
    print("Scanning... (this may take a while for full/vuln scans)\n")

    nm.scan(hosts=target, arguments=profile["args"], sudo=profile.get("sudo", False))

    results = {}
    for host in nm.all_hosts():
        info = nm[host]
        entry = {
            "hostname": info.hostname() or "N/A",
            "state": info.state(),
            "os": [],
            "ports": [],
            "vuln_findings": [],
        }

        if "osmatch" in info and info["osmatch"]:
            entry["os"] = [m["name"] for m in info["osmatch"][:3]]

        for proto in info.all_protocols():
            for port in sorted(info[proto].keys()):
                pinfo = info[proto][port]
                service = pinfo.get("name", "")
                product = pinfo.get("product", "")
                version = pinfo.get("version", "")
                version_str = f"{product} {version}".strip()
                risk = get_risk(service)
                entry["ports"].append(
                    {
                        "port": port,
                        "protocol": proto,
                        "state": pinfo.get("state", ""),
                        "service": service,
                        "version": version_str or "N/A",
                        "risk": risk,
                    }
                )
                script_output = pinfo.get("script", {})
                for script_name, output in script_output.items():
                    if "vuln" in script_name or "VULNERABLE" in output:
                        entry["vuln_findings"].append(
                            {"script": script_name, "output": output.strip()}
                        )

        results[host] = entry

    return results


def print_port_results(results):
    for host, data in results.items():
        print(f"\n{C_BOLD}Host: {host}{C_RESET}  ({data['hostname']})  state: {data['state']}")
        if data["os"]:
            print(f"  OS guess: {', '.join(data['os'])}")
        if not data["ports"]:
            print(f"  {C_GREY}No open ports found.{C_RESET}")
            continue
        print(f"  {'Port':<10}{'Proto':<8}{'State':<10}{'Service':<20}{'Version':<28}{'Risk'}")
        print("  " + "-" * 90)
        for p in data["ports"]:
            color = RISK_COLOR.get(p["risk"], C_RESET)
            print(
                f"  {p['port']:<10}{p['protocol']:<8}{p['state']:<10}"
                f"{p['service']:<20}{p['version']:<28}{color}{p['risk']}{C_RESET}"
            )
        if data["vuln_findings"]:
            print(f"\n  {C_RED}Vulnerability script findings:{C_RESET}")
            for finding in data["vuln_findings"]:
                print(f"   [{finding['script']}]")
                for line in finding["output"].splitlines():
                    print(f"     {line}")


# ---------------------------------------------------------------------------
# Auto-escalation
# ---------------------------------------------------------------------------

def auto_escalate(nm, hosts):
    live_ips = [h["ip"] for h in hosts if h["state"] == "up"]
    if not live_ips:
        print(f"{C_YELLOW}[!] No live hosts to escalate to a port scan.{C_RESET}")
        return None
    target_list = ",".join(live_ips)
    print(f"\n{C_CYAN}[*]{C_RESET} Auto-escalating to Quick Port Scan against {len(live_ips)} host(s)...")
    profile = SCAN_PROFILES["2"]
    return run_port_scan(nm, target_list, profile)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def safe_filename(target):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in target)


def save_reports(kind, target, payload, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"cgrecon_{kind}_{safe_filename(target)}_{timestamp}"

    json_path = os.path.join(output_dir, base + ".json")
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    txt_path = os.path.join(output_dir, base + ".txt")
    with open(txt_path, "w") as f:
        f.write(json.dumps(payload, indent=2, default=str))

    html_path = os.path.join(output_dir, base + ".html")
    with open(html_path, "w") as f:
        f.write(render_html_report(kind, target, payload))

    print(f"\n{C_GREEN}[+] Reports saved:{C_RESET}")
    print(f"    {json_path}")
    print(f"    {txt_path}")
    print(f"    {html_path}")


def render_html_report(kind, target, payload):
    rows = ""
    if kind == "discovery":
        for h in payload:
            verified = h.get("verified")
            v_cell = "" if verified is None else ("yes" if verified else "no")
            rows += (
                f"<tr><td>{h['ip']}</td><td>{h['hostname']}</td>"
                f"<td>{h['mac']}</td><td>{h['vendor']}</td><td>{v_cell}</td></tr>"
            )
        table_header = "<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Verified</th></tr>"
    else:
        for host, data in payload.items():
            if not data["ports"]:
                rows += f"<tr><td>{host}</td><td colspan='5'>No open ports</td></tr>"
                continue
            for p in data["ports"]:
                rows += (
                    f"<tr><td>{host}</td><td>{p['port']}/{p['protocol']}</td>"
                    f"<td>{p['state']}</td><td>{p['service']}</td>"
                    f"<td>{p['version']}</td><td class='risk-{p['risk'].lower()}'>{p['risk']}</td></tr>"
                )
        table_header = "<tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Risk</th></tr>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CGRecon Report - {target}</title>
<style>
  body {{ background:#101418; color:#e6e6e6; font-family: -apple-system, Segoe UI, sans-serif; padding: 2rem; }}
  h1 {{ color:#5ec8f2; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #2a2f36; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background:#1b2028; color:#9fd3ea; }}
  tr:nth-child(even) {{ background:#161a20; }}
  .risk-critical {{ color:#ff5c5c; font-weight:bold; }}
  .risk-high {{ color:#ff8a5c; font-weight:bold; }}
  .risk-medium {{ color:#f4d35e; }}
  .risk-low {{ color:#7ed07e; }}
  .meta {{ color:#8a93a1; font-size: 13px; }}
</style></head>
<body>
  <h1>CGRecon Report</h1>
  <p class="meta">Target: {target} &nbsp;|&nbsp; Scan type: {kind} &nbsp;|&nbsp; Generated: {datetime.now()}</p>
  <table>{table_header}{rows}</table>
</body></html>"""


# ---------------------------------------------------------------------------
# Professional / executive report
# ---------------------------------------------------------------------------
# Structured to match how technical security assessments are conventionally
# presented: scope & authorization, methodology, executive summary, detailed
# findings with CVSS-style severity labels, and remediation guidance. This
# mirrors the shape described in NIST SP 800-115 (Technical Guide to
# Information Security Testing and Assessment) and the Penetration Testing
# Execution Standard (PTES) - scope, discovery, analysis/attack, reporting.
#
# Severity labels (Critical/High/Medium/Low) match the CVSS v3.1 qualitative
# rating scale. They are heuristic, keyword-based ratings for triage, not
# calculated CVSS scores - the report says this explicitly so it isn't
# mistaken for more precision than it has. Specific CVEs surfaced by Nmap's
# vuln scripts should be checked against the National Vulnerability Database
# (nvd.nist.gov) for an authoritative score before being cited externally.

def build_report_metadata(target, tester=None, authorized_by=None, title=None):
    return {
        "title": title or "Network Reconnaissance & Vulnerability Assessment",
        "target": target,
        "tester": tester or "N/A",
        "authorized_by": authorized_by or "N/A",
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "CGRecon v2.0 (built on Nmap)",
    }


def compute_summary_stats(discovery_hosts, port_results):
    hosts_up = 0
    if discovery_hosts is not None:
        hosts_up = sum(1 for h in discovery_hosts if h["state"] == "up")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    open_ports_total = 0
    hosts_with_findings = set()

    if port_results:
        for host, data in port_results.items():
            for p in data["ports"]:
                if p["state"] != "open":
                    continue
                open_ports_total += 1
                severity_counts[p["risk"]] = severity_counts.get(p["risk"], 0) + 1
                if p["risk"] in ("CRITICAL", "HIGH"):
                    hosts_with_findings.add(host)

    return {
        "hosts_up": hosts_up,
        "open_ports_total": open_ports_total,
        "severity_counts": severity_counts,
        "hosts_with_high_or_critical": len(hosts_with_findings),
    }


def build_findings_list(port_results):
    """Flatten per-host port results into a single, severity-sorted findings
    list - the shape a reader expects from a vulnerability assessment report
    (worst issues first, not grouped arbitrarily by host)."""
    findings = []
    if not port_results:
        return findings

    for host, data in port_results.items():
        for p in data["ports"]:
            if p["state"] != "open":
                continue
            findings.append(
                {
                    "host": host,
                    "hostname": data.get("hostname", "N/A"),
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "version": p["version"],
                    "severity": p["risk"],
                    "remediation": get_remediation(p["service"]),
                }
            )
        for vf in data.get("vuln_findings", []):
            findings.append(
                {
                    "host": host,
                    "hostname": data.get("hostname", "N/A"),
                    "port": "N/A",
                    "protocol": "N/A",
                    "service": f"script: {vf['script']}",
                    "version": vf["output"][:200],
                    "severity": "HIGH",
                    "remediation": "Review Nmap script output; cross-reference any CVEs against nvd.nist.gov.",
                }
            )

    findings.sort(key=lambda f: RISK_ORDER.get(f["severity"], 0), reverse=True)
    return findings


def render_executive_report_md(meta, discovery_hosts, port_results):
    stats = compute_summary_stats(discovery_hosts, port_results)
    findings = build_findings_list(port_results)

    lines = []
    lines.append(f"# {meta['title']}")
    lines.append("")
    lines.append("## Scope & Authorization")
    lines.append(f"- **Target:** {meta['target']}")
    lines.append(f"- **Tester:** {meta['tester']}")
    lines.append(f"- **Authorized by:** {meta['authorized_by']}")
    lines.append(f"- **Date:** {meta['generated']}")
    lines.append(f"- **Tool:** {meta['tool']}")
    lines.append(
        "- This assessment was performed only against systems the tester "
        "owns or has explicit permission to test."
    )
    lines.append("")
    lines.append("## Methodology")
    lines.append(
        "Testing followed the general phases described in NIST SP 800-115 "
        "(Technical Guide to Information Security Testing and Assessment) "
        "and the Penetration Testing Execution Standard (PTES):"
    )
    lines.append("1. **Discovery** - multi-probe host enumeration (ICMP echo, TCP SYN, TCP ACK)")
    lines.append("   to identify live hosts, including a sanity check for proxy-ARP or")
    lines.append("   overly permissive network behaviour that can produce false positives.")
    lines.append("2. **Enumeration** - port and service/version scanning of live hosts.")
    lines.append("3. **Vulnerability analysis** - Nmap NSE vulnerability scripts where authorized.")
    lines.append("4. **Reporting** - findings below, ranked by severity, with remediation guidance.")
    lines.append("")
    lines.append(
        "> Severity labels (Critical/High/Medium/Low) follow the CVSS v3.1 qualitative "
        "rating scale but are heuristic, keyword-based triage ratings - not calculated "
        "CVSS scores. Any CVE identified by vulnerability scripts should be verified "
        "against the National Vulnerability Database (nvd.nist.gov) before being cited "
        "in a formal record."
    )
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- **Live hosts identified:** {stats['hosts_up']}")
    lines.append(f"- **Open ports/services identified:** {stats['open_ports_total']}")
    lines.append(
        f"- **Findings by severity:** "
        f"Critical: {stats['severity_counts'].get('CRITICAL', 0)}, "
        f"High: {stats['severity_counts'].get('HIGH', 0)}, "
        f"Medium: {stats['severity_counts'].get('MEDIUM', 0)}, "
        f"Low: {stats['severity_counts'].get('LOW', 0)}"
    )
    lines.append(
        f"- **Hosts with at least one High/Critical finding:** "
        f"{stats['hosts_with_high_or_critical']}"
    )
    lines.append("")

    if discovery_hosts is not None:
        lines.append("## Host Inventory")
        lines.append("")
        lines.append("| IP | Hostname | MAC | Vendor | State |")
        lines.append("|---|---|---|---|---|")
        for h in discovery_hosts:
            lines.append(f"| {h['ip']} | {h['hostname']} | {h['mac']} | {h['vendor']} | {h['state']} |")
        lines.append("")

    lines.append("## Detailed Findings (ranked by severity)")
    lines.append("")
    if not findings:
        lines.append("No open ports or vulnerability script findings were recorded in this run.")
    else:
        lines.append("| Severity | Host | Port | Service | Version | Remediation |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            port_str = f["port"] if f["port"] == "N/A" else f"{f['port']}/{f['protocol']}"
            lines.append(
                f"| {f['severity']} | {f['host']} ({f['hostname']}) | {port_str} | "
                f"{f['service']} | {f['version']} | {f['remediation']} |"
            )
    lines.append("")
    lines.append("## Disclaimer")
    lines.append(
        "This report reflects automated scan results at a point in time and is not "
        "a substitute for manual validation or a full penetration test. Findings "
        "should be independently verified before remediation work is prioritized."
    )

    return "\n".join(lines)


def render_executive_report_html(meta, discovery_hosts, port_results):
    stats = compute_summary_stats(discovery_hosts, port_results)
    findings = build_findings_list(port_results)

    host_rows = ""
    if discovery_hosts is not None:
        for h in discovery_hosts:
            host_rows += (
                f"<tr><td>{h['ip']}</td><td>{h['hostname']}</td>"
                f"<td>{h['mac']}</td><td>{h['vendor']}</td><td>{h['state']}</td></tr>"
            )

    finding_rows = ""
    for f in findings:
        port_str = f["port"] if f["port"] == "N/A" else f"{f['port']}/{f['protocol']}"
        finding_rows += (
            f"<tr><td class='sev-{f['severity'].lower()}'>{f['severity']}</td>"
            f"<td>{f['host']} ({f['hostname']})</td><td>{port_str}</td>"
            f"<td>{f['service']}</td><td>{f['version']}</td><td>{f['remediation']}</td></tr>"
        )
    if not finding_rows:
        finding_rows = "<tr><td colspan='6'>No open ports or vulnerability findings recorded.</td></tr>"

    host_section = ""
    if discovery_hosts is not None:
        host_section = f"""
        <h2>Host Inventory</h2>
        <table>
          <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>State</th></tr>
          {host_rows}
        </table>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{meta['title']} - {meta['target']}</title>
<style>
  body {{ background:#0d1117; color:#e6edf3; font-family: -apple-system, Segoe UI, sans-serif;
          padding: 2.5rem; max-width: 1000px; margin: 0 auto; line-height: 1.5; }}
  h1 {{ color:#58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
  h2 {{ color:#79c0ff; margin-top: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; font-size: 13.5px; vertical-align: top; }}
  th {{ background:#161b22; color:#9fd3ea; }}
  tr:nth-child(even) {{ background:#11161d; }}
  .meta-box {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem 1.5rem; }}
  .meta-box p {{ margin: 0.25rem 0; color:#c9d1d9; }}
  .callout {{ background:#1c2128; border-left: 3px solid #58a6ff; padding: 0.75rem 1rem; margin: 1rem 0; color:#c9d1d9; font-size: 13.5px; }}
  .sev-critical {{ color:#ff6b6b; font-weight:bold; }}
  .sev-high {{ color:#ff9b6b; font-weight:bold; }}
  .sev-medium {{ color:#f4d35e; }}
  .sev-low {{ color:#7ee07e; }}
  .disclaimer {{ color:#8b949e; font-size: 12.5px; margin-top: 2.5rem; border-top: 1px solid #30363d; padding-top: 1rem; }}
</style></head>
<body>
  <h1>{meta['title']}</h1>
  <div class="meta-box">
    <p><strong>Target:</strong> {meta['target']}</p>
    <p><strong>Tester:</strong> {meta['tester']}</p>
    <p><strong>Authorized by:</strong> {meta['authorized_by']}</p>
    <p><strong>Date:</strong> {meta['generated']}</p>
    <p><strong>Tool:</strong> {meta['tool']}</p>
  </div>

  <h2>Methodology</h2>
  <p>Testing followed the general phases described in NIST SP 800-115 (Technical Guide to
     Information Security Testing and Assessment) and the Penetration Testing Execution
     Standard (PTES): discovery, enumeration, vulnerability analysis, and reporting.</p>
  <div class="callout">
    Severity labels follow the CVSS v3.1 qualitative rating scale (Critical/High/Medium/Low)
    but are heuristic, keyword-based triage ratings - not calculated CVSS scores. Verify any
    CVE identified by vulnerability scripts against the National Vulnerability Database
    (nvd.nist.gov) before citing it externally.
  </div>

  <h2>Executive Summary</h2>
  <table>
    <tr><th>Live hosts</th><th>Open ports/services</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
    <tr>
      <td>{stats['hosts_up']}</td>
      <td>{stats['open_ports_total']}</td>
      <td class="sev-critical">{stats['severity_counts'].get('CRITICAL', 0)}</td>
      <td class="sev-high">{stats['severity_counts'].get('HIGH', 0)}</td>
      <td class="sev-medium">{stats['severity_counts'].get('MEDIUM', 0)}</td>
      <td class="sev-low">{stats['severity_counts'].get('LOW', 0)}</td>
    </tr>
  </table>

  {host_section}

  <h2>Detailed Findings (ranked by severity)</h2>
  <table>
    <tr><th>Severity</th><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Remediation</th></tr>
    {finding_rows}
  </table>

  <p class="disclaimer">
    This report reflects automated scan results at a point in time and is not a substitute
    for manual validation or a full penetration test. Findings should be independently
    verified before remediation work is prioritized.
  </p>
</body></html>"""


def save_executive_report(meta, discovery_hosts, port_results, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"cgrecon_assessment_{safe_filename(meta['target'])}_{timestamp}"

    md_path = os.path.join(output_dir, base + ".md")
    with open(md_path, "w") as f:
        f.write(render_executive_report_md(meta, discovery_hosts, port_results))

    html_path = os.path.join(output_dir, base + ".html")
    with open(html_path, "w") as f:
        f.write(render_executive_report_html(meta, discovery_hosts, port_results))

    print(f"\n{C_GREEN}[+] Executive assessment report saved:{C_RESET}")
    print(f"    {md_path}")
    print(f"    {html_path}")


# ---------------------------------------------------------------------------
# Report comparison
# ---------------------------------------------------------------------------

def compare_reports(file_a, file_b):
    with open(file_a) as f:
        a = json.load(f)
    with open(file_b) as f:
        b = json.load(f)

    print(f"\n{C_BOLD}Comparing:{C_RESET}\n  A: {file_a}\n  B: {file_b}\n")

    if isinstance(a, list) and isinstance(b, list):
        ips_a = {h["ip"] for h in a}
        ips_b = {h["ip"] for h in b}
        added = ips_b - ips_a
        removed = ips_a - ips_b
        print(f"{C_GREEN}New hosts in B:{C_RESET} {', '.join(sorted(added)) or 'none'}")
        print(f"{C_RED}Hosts missing in B:{C_RESET} {', '.join(sorted(removed)) or 'none'}")
        return

    if isinstance(a, dict) and isinstance(b, dict):
        hosts = set(a) | set(b)
        for host in sorted(hosts):
            ports_a = {(p["port"], p["protocol"]) for p in a.get(host, {}).get("ports", [])}
            ports_b = {(p["port"], p["protocol"]) for p in b.get(host, {}).get("ports", [])}
            opened = ports_b - ports_a
            closed = ports_a - ports_b
            if not opened and not closed:
                continue
            print(f"{C_BOLD}{host}{C_RESET}")
            if opened:
                print(f"  {C_YELLOW}Newly open:{C_RESET} {sorted(opened)}")
            if closed:
                print(f"  {C_GREEN}No longer open:{C_RESET} {sorted(closed)}")
        return

    print(f"{C_YELLOW}[!] Reports are not the same kind (discovery vs port scan) - can't compare directly.{C_RESET}")


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def print_menu():
    print(BANNER)
    print("SELECT SCAN PROFILE\n" + "-" * 78)
    for key, profile in SCAN_PROFILES.items():
        sudo_tag = f" {C_RED}[sudo]{C_RESET}" if profile.get("sudo") else ""
        print(f"{key}) {C_BOLD}{profile['name']}{C_RESET}{sudo_tag}")
        print(f"   {profile['desc']}")
    print("-" * 78)


def interactive_mode():
    meta = require_authorization()
    print_menu()
    choice = input("\nProfile [1-8]: ").strip()
    profile = SCAN_PROFILES.get(choice)
    if not profile:
        print(f"{C_RED}Invalid profile.{C_RESET}")
        return

    target = input("Target (IP / range / CIDR): ").strip()
    meta["target"] = target
    verify = False
    if profile.get("discovery"):
        verify = input("Re-verify live hosts with TCP connects? [y/N]: ").strip().lower() == "y"
    save = input("Save report to file? [y/N]: ").strip().lower() == "y"
    professional = False
    if save:
        professional = input("Also generate the formal assessment report (exec summary + remediation)? [y/N]: ").strip().lower() == "y"

    nm = nmap.PortScanner()
    discovery_hosts = None
    port_results = None

    if profile.get("discovery"):
        discovery_hosts = run_host_discovery(nm, target)
        proxy_arp_sanity_check(target, discovery_hosts)
        if verify:
            discovery_hosts = verify_hosts(discovery_hosts)
        print_discovery_results(discovery_hosts, verified_included=verify)

        if input("\nAuto-escalate: run Quick Port Scan on all live hosts? [y/N]: ").strip().lower() == "y":
            escalation_results = auto_escalate(nm, discovery_hosts)
            if escalation_results:
                print_port_results(escalation_results)
                port_results = escalation_results
                if save:
                    save_reports("discovery", target, discovery_hosts)
                    save_reports("portscan", target, escalation_results)
        else:
            if save:
                save_reports("discovery", target, discovery_hosts)
    else:
        port_results = run_port_scan(nm, target, profile)
        print_port_results(port_results)
        if save:
            save_reports("portscan", target, port_results)

    if professional:
        save_executive_report(meta, discovery_hosts, port_results)

    print(f"\nFinished: {datetime.now()}")


# ---------------------------------------------------------------------------
# CLI mode
# ---------------------------------------------------------------------------

def cli_mode(args):
    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    if not (args.tester and args.authorized_by and args.confirm_authorized):
        print(f"{C_RED}Authorization required before scanning.{C_RESET}")
        print("  Missing one or more required flags: --tester, --authorized-by, --confirm-authorized")
        print("  Example:")
        print(
            "    sudo python3 cgrecon.py --profile 4 --target 192.168.1.0/24 "
            "--tester 'Your Name' --authorized-by 'IT Manager' --confirm-authorized --report"
        )
        sys.exit(1)

    profile = SCAN_PROFILES.get(str(args.profile))
    if not profile:
        print(f"{C_RED}Invalid profile: {args.profile}{C_RESET}")
        sys.exit(1)

    nm = nmap.PortScanner()
    discovery_hosts = None
    port_results = None

    if profile.get("discovery"):
        discovery_hosts = run_host_discovery(nm, args.target)
        proxy_arp_sanity_check(args.target, discovery_hosts)
        if args.verify:
            discovery_hosts = verify_hosts(discovery_hosts)
        print_discovery_results(discovery_hosts, verified_included=args.verify)
        if args.escalate:
            escalation_results = auto_escalate(nm, discovery_hosts)
            if escalation_results:
                print_port_results(escalation_results)
                port_results = escalation_results
                if args.save:
                    save_reports("portscan", args.target, escalation_results)
        if args.save:
            save_reports("discovery", args.target, discovery_hosts)
    else:
        port_results = run_port_scan(nm, args.target, profile)
        print_port_results(port_results)
        if args.save:
            save_reports("portscan", args.target, port_results)

    if args.report:
        meta = build_report_metadata(
            args.target, tester=args.tester, authorized_by=args.authorized_by, title=args.title
        )
        save_executive_report(meta, discovery_hosts, port_results)


def build_arg_parser():
    parser = argparse.ArgumentParser(description="CGRecon v2.0 - CyberG Network Reconnaissance Tool")
    parser.add_argument("--profile", "-p", help="Scan profile number (1-8)")
    parser.add_argument("--target", "-t", help="Target IP / range / CIDR")
    parser.add_argument("--save", action="store_true", help="Save JSON/TXT/HTML reports")
    parser.add_argument("--verify", action="store_true", help="Re-verify discovery results with TCP connects")
    parser.add_argument("--escalate", action="store_true", help="Auto-run a Quick Port Scan on discovered live hosts")
    parser.add_argument("--compare", nargs=2, metavar=("REPORT_A", "REPORT_B"), help="Diff two JSON reports")
    parser.add_argument("--report", action="store_true", help="Generate a formal assessment report (exec summary, methodology, remediation)")
    parser.add_argument("--title", help="Assessment title for the formal report")
    parser.add_argument("--tester", help="Tester / analyst name (required to run any scan)")
    parser.add_argument("--authorized-by", dest="authorized_by", help="Who authorized this assessment (required to run any scan)")
    parser.add_argument("--confirm-authorized", action="store_true", help="Explicit confirmation you have permission to test this target (required to run any scan)")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.compare:
        cli_mode(args)
        return

    if args.profile and args.target:
        print(BANNER)
        cli_mode(args)
        return

    interactive_mode()


if __name__ == "__main__":
    main()
