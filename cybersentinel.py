#!/usr/bin/env python3
"""
CyberSentinel - Network Vulnerability Scanner
================================================
A multi-threaded network port scanner with a built-in vulnerability
advisory engine, TLS/SSL configuration checker, and automatic report
generation (HTML / JSON / CSV).

Author : Hamza (github.com/senpaihamza26-lab)
License: MIT

LEGAL NOTICE
------------
This tool is intended ONLY for scanning systems you own, or for which
you have explicit written authorization to test. Unauthorized scanning
of networks/hosts you do not control may be illegal in your jurisdiction.
The author assumes no liability for misuse of this tool.
"""

import argparse
import csv
import json
import os
import socket
import ssl
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
except ImportError:
    print("Missing dependency 'rich'. Install it with:\n    pip install rich")
    sys.exit(1)

console = Console()

# --------------------------------------------------------------------------
# Vulnerability advisory database
# Maps well-known ports to service name, risk level, and a short advisory.
# --------------------------------------------------------------------------
VULN_DB = {
    21:    {"service": "FTP",          "risk": "High",     "desc": "FTP often transmits credentials in plaintext and may allow anonymous login."},
    22:    {"service": "SSH",          "risk": "Low",      "desc": "Ensure key-based authentication, disable root login, and rate-limit auth attempts."},
    23:    {"service": "Telnet",       "risk": "Critical", "desc": "Telnet sends all traffic, including passwords, unencrypted. Disable and use SSH instead."},
    25:    {"service": "SMTP",         "risk": "Medium",   "desc": "Check for open mail relay misconfiguration and enforce authentication."},
    53:    {"service": "DNS",         "risk": "Medium",   "desc": "Verify zone transfers (AXFR) are restricted to authorized secondary servers."},
    80:    {"service": "HTTP",         "risk": "Low",      "desc": "Unencrypted web service. Check for outdated software, default admin panels, and directory listing."},
    110:   {"service": "POP3",         "risk": "Medium",   "desc": "Legacy mail retrieval protocol; prefer POP3S (995) with TLS."},
    111:   {"service": "RPCbind",      "risk": "Medium",   "desc": "Exposes RPC services; often abused for reflection/amplification attacks."},
    135:   {"service": "MS RPC",       "risk": "Medium",   "desc": "Windows RPC endpoint mapper, historically targeted by worms (e.g. Blaster)."},
    139:   {"service": "NetBIOS",      "risk": "Medium",   "desc": "Legacy SMB transport; can leak host/user information."},
    143:   {"service": "IMAP",         "risk": "Medium",   "desc": "Legacy mail retrieval protocol; prefer IMAPS (993) with TLS."},
    443:   {"service": "HTTPS",        "risk": "Low",      "desc": "Verify certificate validity, TLS version, and cipher strength."},
    445:   {"service": "SMB",          "risk": "Critical", "desc": "SMB is a top ransomware entry vector (e.g. EternalBlue) if unpatched or exposed to the internet."},
    465:   {"service": "SMTPS",        "risk": "Low",      "desc": "Encrypted SMTP submission; verify TLS configuration."},
    993:   {"service": "IMAPS",        "risk": "Low",      "desc": "Encrypted IMAP; verify TLS configuration."},
    995:   {"service": "POP3S",        "risk": "Low",      "desc": "Encrypted POP3; verify TLS configuration."},
    1433:  {"service": "MSSQL",        "risk": "High",     "desc": "Exposed database port; common brute-force and credential-stuffing target."},
    3306:  {"service": "MySQL",        "risk": "High",     "desc": "Exposed database port; should not be reachable from the public internet."},
    3389:  {"service": "RDP",          "risk": "Critical", "desc": "RDP exposed to the internet is one of the top ransomware entry vectors. Restrict via VPN/firewall."},
    5432:  {"service": "PostgreSQL",   "risk": "High",     "desc": "Exposed database port; restrict access and enforce strong auth."},
    5900:  {"service": "VNC",          "risk": "High",     "desc": "Remote desktop protocol, frequently found with weak or no authentication."},
    6379:  {"service": "Redis",        "risk": "Critical", "desc": "Redis without authentication allows full data access and, in some configs, remote code execution."},
    8080:  {"service": "HTTP-Alt",     "risk": "Medium",   "desc": "Alternate web/admin service; check for exposed dashboards or dev environments."},
    8443:  {"service": "HTTPS-Alt",    "risk": "Low",      "desc": "Alternate HTTPS service; verify certificate and TLS configuration."},
    9200:  {"service": "Elasticsearch","risk": "High",     "desc": "Often exposed without authentication, leading to large-scale data leaks."},
    27017: {"service": "MongoDB",      "risk": "Critical", "desc": "Default no-auth MongoDB instances are one of the most commonly breached databases."},
}

COMMON_PORTS = sorted(set(VULN_DB.keys()) | {8000, 8888, 20})

RISK_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
RISK_COLOR = {"Critical": "bold white on red", "High": "red", "Medium": "yellow", "Low": "green", "Info": "cyan"}


def print_banner():
    banner = r"""
   _____      _               _____             _   _            _
  / ____|    | |             / ____|           | | (_)          | |
 | |    _   _| |__   ___ _ _| (___   ___ _ __ | |_ _ _ __   ___| |
 | |   | | | | '_ \ / _ \ '__\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |___| |_| | |_) |  __/ |  ____) |  __/ | | | |_| | | | |  __/ |
  \_____\__, |_.__/ \___|_| |_____/ \___|_| |_|\__|_|_| |_|\___|_|
         __/ |            Network Vulnerability Scanner  v1.0
        |___/
"""
    console.print(f"[bold red]{banner}[/bold red]")


def parse_ports(port_arg):
    """Parse a port spec like '22,80,443' or '1-1024' into a sorted list."""
    if not port_arg:
        return COMMON_PORTS
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def grab_http_banner(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = s.recv(1024).decode(errors="ignore").strip()
            first_line = data.splitlines()[0] if data else ""
            return first_line
    except Exception:
        return ""


def scan_port(ip, port, timeout):
    """Attempt a TCP connect to a single port and grab a banner if possible."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = ""
            if port in (80, 8080, 8000, 8888, 8443):
                banner = grab_http_banner(ip, port, timeout)
            else:
                try:
                    s.settimeout(timeout)
                    banner = s.recv(256).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
            return port, True, banner
    except Exception:
        return port, False, ""


def check_tls(ip, port, timeout=3):
    """Connect via TLS and report negotiated protocol/cipher, flagging weak configs."""
    result = {}
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                result["tls_version"] = version
                result["cipher"] = cipher[0] if cipher else "Unknown"
                result["weak"] = version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
    except Exception as e:
        result["error"] = str(e)
    return result


def run_scan(ip, ports, threads, timeout):
    results = []
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, complete_style="red", finished_style="green"),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold red]Scanning ports...", total=len(ports))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    results.append({"port": port, "banner": banner})
                progress.advance(task)

    results.sort(key=lambda r: r["port"])
    for r in results:
        vuln = VULN_DB.get(
            r["port"],
            {"service": "Unknown", "risk": "Info", "desc": "No specific advisory for this port. Verify the running service and its necessity manually."},
        )
        r.update(vuln)
        if r["port"] in (443, 8443, 993, 995, 465):
            r["tls"] = check_tls(ip, r["port"], timeout)
    return results


def display_results(target, ip, results, elapsed):
    console.print()
    if not results:
        console.print(Panel("[bold green]No open ports found in the scanned range.[/bold green]", border_style="green"))
        return

    table = Table(title=f"Scan Results for {target} ({ip})", box=box.ROUNDED, show_lines=False, header_style="bold white on red")
    table.add_column("Port", justify="right", style="bold")
    table.add_column("Service")
    table.add_column("Risk", justify="center")
    table.add_column("Advisory")
    table.add_column("Banner", overflow="fold")

    for r in results:
        color = RISK_COLOR.get(r["risk"], "white")
        banner_txt = r["banner"][:40] + ("..." if len(r["banner"]) > 40 else "") if r["banner"] else "-"
        table.add_row(
            str(r["port"]),
            r["service"],
            f"[{color}]{r['risk']}[/{color}]",
            r["desc"],
            banner_txt,
        )
    console.print(table)

    counts = Counter(r["risk"] for r in results)
    summary = "   ".join(f"[{RISK_COLOR.get(k,'white')}]{k}: {v}[/{RISK_COLOR.get(k,'white')}]" for k, v in counts.items())
    console.print(Panel(f"{summary}\n\n[bold]Open ports:[/bold] {len(results)}   [bold]Scan time:[/bold] {elapsed:.2f}s", title="Summary", border_style="red"))


def risk_score(results):
    if not results:
        return 0, "Clean"
    score = sum(RISK_WEIGHT.get(r["risk"], 0) for r in results)
    if any(r["risk"] == "Critical" for r in results):
        rating = "Critical"
    elif any(r["risk"] == "High" for r in results):
        rating = "High"
    elif any(r["risk"] == "Medium" for r in results):
        rating = "Medium"
    else:
        rating = "Low"
    return score, rating


def save_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def save_csv(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "service", "risk", "desc", "banner"])
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in ["port", "service", "risk", "desc", "banner"]})


def save_html(path, target, ip, results, elapsed, timestamp):
    score, rating = risk_score(results)
    counts = Counter(r["risk"] for r in results)
    rows = ""
    for r in results:
        tls_info = ""
        if "tls" in r:
            t = r["tls"]
            if "error" in t:
                tls_info = f"<span class='tls-error'>TLS check failed</span>"
            else:
                weak_tag = " <span class='weak'>WEAK</span>" if t.get("weak") else ""
                tls_info = f"{t.get('tls_version','?')} / {t.get('cipher','?')}{weak_tag}"
        rows += f"""
        <tr class="risk-{r['risk'].lower()}">
            <td>{r['port']}</td>
            <td>{r['service']}</td>
            <td><span class="badge badge-{r['risk'].lower()}">{r['risk']}</span></td>
            <td>{r['desc']}</td>
            <td>{r['banner'] or '-'}</td>
            <td>{tls_info or '-'}</td>
        </tr>"""

    cards = ""
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        c = counts.get(level, 0)
        cards += f"""<div class="card card-{level.lower()}"><div class="card-num">{c}</div><div class="card-label">{level}</div></div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberSentinel Report — {target}</title>
<style>
    :root {{
        --bg: #0d0508; --panel: #1a0d10; --crimson: #a3123a; --crimson-bright: #e11d48;
        --text: #f1e9ea; --muted: #a08088; --border: #33161f;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        background: radial-gradient(circle at top, #1a0308 0%, #0d0508 70%);
        color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
        margin: 0; padding: 40px;
    }}
    .header {{ border-bottom: 2px solid var(--crimson); padding-bottom: 20px; margin-bottom: 30px; }}
    .header h1 {{ margin: 0; font-size: 28px; letter-spacing: 1px; color: var(--crimson-bright); }}
    .header p {{ color: var(--muted); margin: 6px 0 0; }}
    .cards {{ display: flex; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 22px; min-width: 100px; text-align: center; }}
    .card-num {{ font-size: 28px; font-weight: 700; }}
    .card-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
    .card-critical .card-num {{ color: #ff2d55; }}
    .card-high .card-num {{ color: #ff6b3d; }}
    .card-medium .card-num {{ color: #f0c419; }}
    .card-low .card-num {{ color: #2ecc71; }}
    .card-info .card-num {{ color: #4dd0e1; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 10px; overflow: hidden; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }}
    th {{ background: #240b12; color: var(--crimson-bright); text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
    tr:hover {{ background: #241014; }}
    .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    .badge-critical {{ background: #ff2d55; color: #fff; }}
    .badge-high {{ background: #ff6b3d; color: #1a0308; }}
    .badge-medium {{ background: #f0c419; color: #1a0308; }}
    .badge-low {{ background: #2ecc71; color: #1a0308; }}
    .badge-info {{ background: #4dd0e1; color: #1a0308; }}
    .weak {{ color: #ff2d55; font-weight: 700; }}
    .tls-error {{ color: var(--muted); }}
    .footer {{ margin-top: 30px; color: var(--muted); font-size: 12px; text-align: center; }}
</style>
</head>
<body>
    <div class="header">
        <h1>⚔ CyberSentinel — Vulnerability Scan Report</h1>
        <p>Target: <strong>{target}</strong> ({ip}) &nbsp;|&nbsp; Scanned: {timestamp} &nbsp;|&nbsp; Duration: {elapsed:.2f}s &nbsp;|&nbsp; Overall Risk: <strong>{rating}</strong></p>
    </div>
    <div class="cards">{cards}</div>
    <table>
        <tr><th>Port</th><th>Service</th><th>Risk</th><th>Advisory</th><th>Banner</th><th>TLS Info</th></tr>
        {rows if rows else '<tr><td colspan="6">No open ports detected.</td></tr>'}
    </table>
    <div class="footer">Generated by CyberSentinel · For authorized security testing only</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def save_reports(target, ip, results, elapsed, fmt, outdir):
    os.makedirs(outdir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_name = target.replace(".", "_").replace(":", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(outdir, f"{safe_name}_{stamp}")

    payload = {
        "target": target,
        "ip": ip,
        "timestamp": timestamp,
        "duration_seconds": round(elapsed, 2),
        "open_ports": len(results),
        "risk_score": risk_score(results)[0],
        "overall_rating": risk_score(results)[1],
        "findings": results,
    }

    saved = []
    if fmt in ("json", "all"):
        p = f"{base}.json"
        save_json(p, payload)
        saved.append(p)
    if fmt in ("csv", "all"):
        p = f"{base}.csv"
        save_csv(p, results)
        saved.append(p)
    if fmt in ("html", "all"):
        p = f"{base}.html"
        save_html(p, target, ip, results, elapsed, timestamp)
        saved.append(p)

    console.print("\n[bold green]Report(s) saved:[/bold green]")
    for p in saved:
        console.print(f"  → {p}")


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel - Network Vulnerability Scanner")
    parser.add_argument("target", help="Target IP address or hostname (must be authorized for testing)")
    parser.add_argument("-p", "--ports", help="Ports: '22,80,443' or '1-1024' or 'all'. Default: common ports")
    parser.add_argument("-t", "--threads", type=int, default=150, help="Number of concurrent threads (default: 150)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connection timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", choices=["json", "csv", "html", "all"], default="html", help="Report format (default: html)")
    parser.add_argument("--outdir", default="scan_reports", help="Directory to save reports (default: scan_reports)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        console.print(f"[bold red]Error:[/bold red] Could not resolve host '{args.target}'.")
        sys.exit(1)

    ports = list(range(1, 65536)) if args.ports == "all" else parse_ports(args.ports)

    print_banner()
    console.print(Panel(
        f"[bold]Target:[/bold] {args.target} ({ip})\n"
        f"[bold]Ports to scan:[/bold] {len(ports)}\n"
        f"[bold]Threads:[/bold] {args.threads}",
        title="Scan Configuration", border_style="red",
    ))
    console.print("[yellow]⚠ Only scan systems you own or are explicitly authorized to test.[/yellow]\n")

    start_time = datetime.now()
    results = run_scan(ip, ports, args.threads, args.timeout)
    elapsed = (datetime.now() - start_time).total_seconds()

    display_results(args.target, ip, results, elapsed)
    save_reports(args.target, ip, results, elapsed, args.output, args.outdir)


if __name__ == "__main__":
    main()