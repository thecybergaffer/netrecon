#!/usr/bin/env python3
"""
NetRecon - Full Network Reconnaissance Tool
Standalone CLI | python-nmap backend
"""

import nmap
import argparse
import json
import sys
import os
import datetime
from typing import Optional

# ─── ANSI Colors ────────────────────────────────────────────────────────────────
R  = "\033[0m"       # Reset
B  = "\033[1m"       # Bold
CY = "\033[96m"      # Cyan
GR = "\033[92m"      # Green
YE = "\033[93m"      # Yellow
RD = "\033[91m"      # Red
BL = "\033[94m"      # Blue
DM = "\033[2m"       # Dim
WH = "\033[97m"      # White

# ─── Banner ─────────────────────────────────────────────────────────────────────
BANNER = f"""
{CY}{B}
  _   _      _   ____
 | \\ | | ___| |_|  _ \\ ___  ___ ___  _ __
 |  \\| |/ _ \\ __| |_) / _ \\/ __/ _ \\| '_ \\
 | |\\  |  __/ |_|  _ <  __/ (_| (_) | | | |
 |_| \\_|\\___|\\__|_| \\_\\___|\\___\\___/|_| |_|
{R}{DM}  Full Network Reconnaissance Tool  |  v1.0{R}
{DM}  ─────────────────────────────────────────────{R}
"""

SCAN_PROFILES = {
    "1": {
        "name": "Host Discovery",
        "desc": "Detect live hosts on a subnet (no port scan)",
        "args": "-sn",
        "sudo": False,
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
        "args": "-sV -p- -T4",
        "sudo": False,
    },
    "5": {
        "name": "OS Detection",
        "desc": "Fingerprint operating system (requires sudo)",
        "args": "-O -sV -T4",
        "sudo": True,
    },
    "6": {
        "name": "Vulnerability Scan",
        "desc": "Run Nmap vuln scripts (requires sudo)",
        "args": "-sV --script=vuln -T4",
        "sudo": True,
    },
    "7": {
        "name": "Full Recon (All of the above)",
        "desc": "OS + version + vuln scripts — comprehensive (requires sudo)",
        "args": "-A --script=vuln -T4",
        "sudo": True,
    },
}


# ─── Utility ─────────────────────────────────────────────────────────────────────

def print_separator(char="─", width=60, color=DM):
    print(f"{color}{char * width}{R}")


def check_sudo(required: bool) -> bool:
    if required and os.geteuid() != 0:
        print(f"\n{YE}[!] This scan profile requires sudo/root privileges.{R}")
        print(f"{DM}    Re-run with: sudo python3 netrecon.py{R}")
        return False
    return True


def get_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_filename_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# ─── Scan Engine ─────────────────────────────────────────────────────────────────

def run_scan(target: str, scan_args: str) -> Optional[nmap.PortScanner]:
    nm = nmap.PortScanner()
    print(f"\n{BL}[*]{R} Target   : {B}{target}{R}")
    print(f"{BL}[*]{R} Nmap args: {DM}{scan_args}{R}")
    print(f"{BL}[*]{R} Started  : {DM}{get_timestamp()}{R}")
    print_separator()
    print(f"{DM}Scanning... (this may take a while for large scans){R}\n")

    try:
        nm.scan(hosts=target, arguments=scan_args)
    except nmap.PortScannerError as e:
        print(f"{RD}[!] Nmap error: {e}{R}")
        return None
    except KeyboardInterrupt:
        print(f"\n{YE}[!] Scan interrupted by user.{R}")
        return None

    return nm


# ─── Output Formatting ────────────────────────────────────────────────────────────

def display_results(nm: nmap.PortScanner):
    hosts = nm.all_hosts()

    if not hosts:
        print(f"{YE}[!] No hosts found / all hosts down.{R}")
        return

    print(f"\n{GR}{B}[+] Scan complete — {len(hosts)} host(s) found{R}")
    print_separator("═", 60, CY)

    for host in hosts:
        state = nm[host].state()
        state_color = GR if state == "up" else RD
        hostname = nm[host].hostname() or "N/A"

        print(f"\n{B}{WH}Host:{R}     {CY}{host}{R}  ({DM}{hostname}{R})")
        print(f"  State:  {state_color}{state.upper()}{R}")

        # OS detection
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            top_os = nm[host]["osmatch"][0]
            print(f"  OS:     {YE}{top_os.get('name', 'Unknown')}{R}  "
                  f"{DM}(accuracy: {top_os.get('accuracy', '?')}%){R}")

        # Protocols / Ports
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            if not ports:
                continue

            print(f"\n  {BL}Protocol: {proto.upper()}{R}")
            print(f"  {'Port':<10} {'State':<12} {'Service':<18} {'Version'}")
            print_separator("-", 58, DM)

            for port in ports:
                pdata    = nm[host][proto][port]
                pstate   = pdata.get("state", "?")
                service  = pdata.get("name", "unknown")
                version  = pdata.get("version", "")
                product  = pdata.get("product", "")
                extra    = pdata.get("extrainfo", "")

                version_str = " ".join(filter(None, [product, version, extra])).strip()
                port_color  = GR if pstate == "open" else (YE if pstate == "filtered" else DM)

                print(f"  {port_color}{port:<10}{R} {pstate:<12} {service:<18} {DM}{version_str}{R}")

            # Script output (vuln scan results)
            for port in ports:
                script_out = nm[host][proto][port].get("script", {})
                if script_out:
                    print(f"\n  {RD}[!] Script output for port {port}:{R}")
                    for script_name, output in script_out.items():
                        print(f"    {YE}{script_name}:{R}")
                        for line in output.strip().splitlines():
                            print(f"      {DM}{line}{R}")

        print_separator("─", 60, DM)

    print(f"\n{DM}Finished: {get_timestamp()}{R}\n")


# ─── Export ───────────────────────────────────────────────────────────────────────

def build_report_data(nm: nmap.PortScanner, target: str, scan_args: str) -> dict:
    report = {
        "meta": {
            "target": target,
            "scan_args": scan_args,
            "timestamp": get_timestamp(),
            "nmap_version": nm.nmap_version(),
            "command_line": nm.command_line(),
        },
        "hosts": []
    }

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "os": [],
            "protocols": {}
        }

        if "osmatch" in nm[host]:
            host_data["os"] = [
                {"name": o.get("name"), "accuracy": o.get("accuracy")}
                for o in nm[host]["osmatch"]
            ]

        for proto in nm[host].all_protocols():
            host_data["protocols"][proto] = {}
            for port in sorted(nm[host][proto].keys()):
                pdata = nm[host][proto][port]
                host_data["protocols"][proto][str(port)] = {
                    "state": pdata.get("state"),
                    "name": pdata.get("name"),
                    "product": pdata.get("product"),
                    "version": pdata.get("version"),
                    "extrainfo": pdata.get("extrainfo"),
                    "scripts": pdata.get("script", {}),
                }

        report["hosts"].append(host_data)

    return report


def export_json(report_data: dict, outfile: str):
    with open(outfile, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"{GR}[+]{R} JSON report saved: {B}{outfile}{R}")


def export_txt(report_data: dict, outfile: str):
    lines = []
    meta = report_data["meta"]
    lines.append("=" * 60)
    lines.append("NETRECON SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Target    : {meta['target']}")
    lines.append(f"Timestamp : {meta['timestamp']}")
    lines.append(f"Command   : {meta['command_line']}")
    lines.append("=" * 60)

    for host in report_data["hosts"]:
        lines.append(f"\nHost: {host['ip']}  ({host['hostname'] or 'N/A'})")
        lines.append(f"State: {host['state'].upper()}")

        if host["os"]:
            top_os = host["os"][0]
            lines.append(f"OS: {top_os['name']} (accuracy: {top_os['accuracy']}%)")

        for proto, ports in host["protocols"].items():
            lines.append(f"\n  Protocol: {proto.upper()}")
            lines.append(f"  {'Port':<10} {'State':<12} {'Service':<18} Version")
            lines.append("  " + "-" * 56)
            for port, pdata in ports.items():
                ver = " ".join(filter(None, [
                    pdata.get("product", ""),
                    pdata.get("version", ""),
                    pdata.get("extrainfo", ""),
                ])).strip()
                lines.append(f"  {port:<10} {pdata['state']:<12} {pdata['name']:<18} {ver}")

                for script_name, output in pdata.get("scripts", {}).items():
                    lines.append(f"\n    [Script] {script_name}:")
                    for l in output.strip().splitlines():
                        lines.append(f"      {l}")

        lines.append("-" * 60)

    with open(outfile, "w") as f:
        f.write("\n".join(lines))
    print(f"{GR}[+]{R} TXT report saved:  {B}{outfile}{R}")


def export_html(report_data: dict, outfile: str):
    import html as _html
    meta = report_data["meta"]

    css = """
    <style>
        body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',Consolas,monospace; margin:0; padding:2rem; }
        h1 { color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:0.5rem; }
        .meta { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:1rem; margin-bottom:1.5rem; }
        .meta div { margin:0.25rem 0; }
        .meta span.label { color:#8b949e; display:inline-block; width:120px; }
        .host { background:#161b22; border:1px solid #30363d; border-radius:6px; margin-bottom:1.5rem; padding:1rem; }
        .host h2 { color:#3fb950; margin-top:0; }
        .state-up { color:#3fb950; font-weight:bold; }
        .state-down { color:#f85149; font-weight:bold; }
        table { width:100%; border-collapse:collapse; margin-top:0.75rem; }
        th, td { text-align:left; padding:6px 10px; border-bottom:1px solid #30363d; }
        th { color:#8b949e; text-transform:uppercase; font-size:0.8rem; }
        tr:hover { background:#1c2128; }
        .port { color:#58a6ff; font-weight:bold; }
        .service { color:#d2a8ff; }
        .version { color:#c9d1d9; }
        .script-block { background:#0d1117; border-left:3px solid #58a6ff; margin:0.5rem 0; padding:0.5rem 0.75rem; font-size:0.85rem; white-space:pre-wrap; }
        .script-name { color:#f0883e; font-weight:bold; }
        footer { margin-top:2rem; color:#8b949e; font-size:0.8rem; text-align:center; }
    </style>
    """

    parts = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>NetRecon Report - {_html.escape(meta['target'])}</title>")
    parts.append(css)
    parts.append("</head><body>")
    parts.append("<h1>NetRecon Scan Report</h1>")
    parts.append("<div class='meta'>")
    parts.append(f"<div><span class='label'>Target</span>{_html.escape(meta['target'])}</div>")
    parts.append(f"<div><span class='label'>Timestamp</span>{_html.escape(meta['timestamp'])}</div>")
    parts.append(f"<div><span class='label'>Nmap Version</span>{_html.escape(str(meta['nmap_version']))}</div>")
    parts.append(f"<div><span class='label'>Command</span>{_html.escape(meta['command_line'])}</div>")
    parts.append("</div>")

    for host in report_data["hosts"]:
        state_class = "state-up" if host["state"] == "up" else "state-down"
        parts.append("<div class='host'>")
        parts.append(f"<h2>{_html.escape(host['ip'])} <small>({_html.escape(host['hostname'] or 'N/A')})</small></h2>")
        parts.append(f"<div>State: <span class='{state_class}'>{_html.escape(host['state'].upper())}</span></div>")

        if host["os"]:
            top_os = host["os"][0]
            parts.append(f"<div>OS: {_html.escape(str(top_os.get('name')))} (accuracy: {_html.escape(str(top_os.get('accuracy')))}%)</div>")

        for proto, ports in host["protocols"].items():
            parts.append(f"<h3>{_html.escape(proto.upper())}</h3>")
            parts.append("<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>")
            for port, pdata in ports.items():
                ver = " ".join(filter(None, [
                    pdata.get("product") or "",
                    pdata.get("version") or "",
                    pdata.get("extrainfo") or "",
                ])).strip()
                parts.append("<tr>")
                parts.append(f"<td class='port'>{_html.escape(str(port))}</td>")
                parts.append(f"<td>{_html.escape(str(pdata.get('state','')))}</td>")
                parts.append(f"<td class='service'>{_html.escape(str(pdata.get('name','')))}</td>")
                parts.append(f"<td class='version'>{_html.escape(ver)}</td>")
                parts.append("</tr>")

                scripts = pdata.get("scripts") or {}
                if scripts:
                    parts.append("<tr><td colspan='4'>")
                    for script_name, output in scripts.items():
                        parts.append(f"<div class='script-block'><span class='script-name'>[{_html.escape(script_name)}]</span>\n{_html.escape(output.strip())}</div>")
                    parts.append("</td></tr>")
            parts.append("</table>")

        parts.append("</div>")

    parts.append(f"<footer>Generated by NetRecon &middot; {_html.escape(meta['timestamp'])}</footer>")
    parts.append("</body></html>")

    with open(outfile, "w") as f:
        f.write("\n".join(parts))
    print(f"{GR}[+]{R} HTML report saved: {B}{outfile}{R}")


def save_reports(nm: nmap.PortScanner, target: str, scan_args: str, output_dir: str = "."):
    ts = get_filename_timestamp()
    safe_target = target.replace("/", "_").replace(".", "_")
    report_data = build_report_data(nm, target, scan_args)

    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, f"netrecon_{safe_target}_{ts}.json")
    txt_path  = os.path.join(output_dir, f"netrecon_{safe_target}_{ts}.txt")
    html_path = os.path.join(output_dir, f"netrecon_{safe_target}_{ts}.html")

    export_json(report_data, json_path)
    export_txt(report_data, txt_path)
    export_html(report_data, html_path)


# ─── Interactive Menu ─────────────────────────────────────────────────────────────

def interactive_menu():
    print(BANNER)
    print(f"{B}SELECT SCAN PROFILE{R}")
    print_separator()

    for key, profile in SCAN_PROFILES.items():
        sudo_tag = f" {RD}[sudo]{R}" if profile["sudo"] else ""
        print(f"  {CY}{key}{R}) {B}{profile['name']}{R}{sudo_tag}")
        print(f"     {DM}{profile['desc']}{R}")

    print_separator()
    choice = input(f"\n{B}Profile [1-7]: {R}").strip()

    if choice not in SCAN_PROFILES:
        print(f"{RD}[!] Invalid choice.{R}")
        sys.exit(1)

    profile = SCAN_PROFILES[choice]

    if not check_sudo(profile["sudo"]):
        sys.exit(1)

    target = input(f"{B}Target (IP / range / CIDR): {R}").strip()
    if not target:
        print(f"{RD}[!] No target specified.{R}")
        sys.exit(1)

    save = input(f"{B}Save report to file? [y/N]: {R}").strip().lower()
    output_dir = None
    if save == "y":
        output_dir = input(f"{B}Output directory [./reports]: {R}").strip() or "./reports"

    nm = run_scan(target, profile["args"])
    if nm is None:
        sys.exit(1)

    display_results(nm)

    if output_dir:
        save_reports(nm, target, profile["args"], output_dir)


# ─── CLI Mode ────────────────────────────────────────────────────────────────────

def cli_mode():
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon — Full Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Profiles:
  1  Host Discovery         -sn
  2  Quick Port Scan        -T4 -F
  3  Service & Version      -sV -T4
  4  Full TCP + Version     -sV -p- -T4
  5  OS Detection           -O -sV -T4          [sudo]
  6  Vulnerability Scan     -sV --script=vuln   [sudo]
  7  Full Recon             -A --script=vuln    [sudo]

Examples:
  python3 netrecon.py -t 192.168.1.0/24 -p 1
  sudo python3 netrecon.py -t 192.168.1.10 -p 7 -o ./reports
  python3 netrecon.py -t 10.0.0.5 --custom "-sV -p 22,80,443"
        """
    )

    parser.add_argument("-t", "--target",  required=True, help="Target IP, range, or CIDR")
    parser.add_argument("-p", "--profile", choices=[k for k in SCAN_PROFILES], help="Scan profile (1-7)")
    parser.add_argument("--custom",        help="Custom Nmap arguments (overrides profile)")
    parser.add_argument("-o", "--output",  help="Directory to save reports (JSON + TXT)")
    parser.add_argument("--no-display",    action="store_true", help="Suppress terminal output")

    args = parser.parse_args()

    print(BANNER)

    if args.custom:
        scan_args = args.custom
    elif args.profile:
        profile = SCAN_PROFILES[args.profile]
        if not check_sudo(profile["sudo"]):
            sys.exit(1)
        scan_args = profile["args"]
        print(f"{BL}[*]{R} Profile: {B}{profile['name']}{R}")
    else:
        print(f"{RD}[!] Specify a profile (-p 1-7) or custom args (--custom).{R}")
        sys.exit(1)

    nm = run_scan(args.target, scan_args)
    if nm is None:
        sys.exit(1)

    if not args.no_display:
        display_results(nm)

    if args.output:
        save_reports(nm, args.target, scan_args, args.output)


# ─── Entry Point ──────────────────────────────────────────────────────────────────

def main():
    # No args → interactive menu
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        cli_mode()


if __name__ == "__main__":
    main()
