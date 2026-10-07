#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_hunter.py - Web server log attack analyzer.

Author: USER-Bi
Version: 1.0.0

A modular SOC-style log triage tool. Detection rules live in signatures.py;
this file contains the parsing, detection engine, and terminal dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

# Windows UTF-8 console fix
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLACK_EX = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = ""
        LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = NORMAL = ""

import signatures as sigs

__author__ = "USER-Bi"
__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def _map_color(name: str) -> str:
    """Map a colorama-style color name to Fore/Style attrs."""
    COLOR_MAP = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.BLUE, "magenta": Fore.MAGENTA, "cyan": Fore.CYAN,
        "white": Fore.WHITE, "bright_black": Fore.LIGHTBLACK_EX,
        "bright_red": Fore.LIGHTRED_EX, "bright_green": Fore.LIGHTGREEN_EX,
        "bright_yellow": Fore.LIGHTYELLOW_EX, "bright_blue": Fore.LIGHTBLUE_EX,
        "bright_magenta": Fore.LIGHTMAGENTA_EX, "bright_cyan": Fore.LIGHTCYAN_EX,
        "bright_white": Fore.LIGHTWHITE_EX,
    }
    return COLOR_MAP.get(name.lower(), "")


def colorize(text: str, color_spec: str) -> str:
    """Apply a color spec like 'cyan' or 'bright_white on red' to text."""
    if not HAS_COLORAMA:
        return text
    parts = color_spec.lower().split(" on ")
    fg = _map_color(parts[0].strip())
    result = f"{fg}{text}{Style.RESET_ALL}"
    return result


def severity_color(severity: str) -> str:
    """Return the theme color for a severity tag."""
    spec = sigs.THEME.get(severity.upper(), "white")
    return spec


# ---------------------------------------------------------------------------
# SECTION 1: Log parser
# ---------------------------------------------------------------------------

class LogEntry:
    """Parsed representation of a single access-log line."""
    def __init__(
        self,
        ip: str,
        timestamp: Optional[datetime],
        method: str,
        path: str,
        protocol: str,
        status: int,
        size: str,
        referer: str,
        user_agent: str,
        raw_request: str,
    ):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.protocol = protocol
        self.status = status
        self.size = size
        self.referer = referer
        self.user_agent = user_agent
        self.raw_request = raw_request

    def decoded_target(self) -> str:
        """Return URL-decoded path+query for signature matching."""
        try:
            return unquote_plus(self.path)
        except Exception:
            return self.path

    def is_static(self) -> bool:
        """Check if the request is for a static asset (by extension)."""
        for ext in sigs.STATIC_EXTENSIONS:
            if self.path.lower().endswith(ext):
                return True
        return False


def parse_log_line(line: str) -> Optional[LogEntry]:
    """
    Parse one line from an Apache/Nginx access log.
    Tries each regex in sigs.LOG_FORMATS until one matches.
    Returns None if the line is malformed.
    """
    for fmt_name, pattern in sigs.LOG_FORMATS.items():
        match = re.match(pattern, line)
        if match:
            groups = match.groupdict()
            ip = groups.get("ip", "-")
            time_str = groups.get("time", "")
            request_line = groups.get("request", "")
            status_str = groups.get("status", "0")
            size = groups.get("size", "-")
            referer = groups.get("referer", "-")
            agent = groups.get("agent", "-")

            # Parse request line: "GET /path HTTP/1.1"
            method, path, protocol = "", "", ""
            req_parts = request_line.split()
            if len(req_parts) >= 2:
                method = req_parts[0]
                path = req_parts[1]
                protocol = req_parts[2] if len(req_parts) >= 3 else ""

            # Parse timestamp
            ts = parse_timestamp(time_str)

            try:
                status = int(status_str)
            except ValueError:
                status = 0

            return LogEntry(
                ip=ip,
                timestamp=ts,
                method=method,
                path=path,
                protocol=protocol,
                status=status,
                size=size,
                referer=referer,
                user_agent=agent,
                raw_request=request_line,
            )
    return None


def parse_timestamp(time_str: str) -> Optional[datetime]:
    """Try parsing the bracketed timestamp against known formats."""
    for fmt in sigs.TIME_FORMATS:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# SECTION 2: Detection engine
# ---------------------------------------------------------------------------

class Finding:
    """A single security finding."""
    def __init__(
        self,
        severity: str,
        finding_type: str,
        ip: str,
        timestamp: Optional[datetime],
        request: str,
        rule_id: Optional[str] = None,
        description: str = "",
    ):
        self.severity = severity
        self.finding_type = finding_type
        self.ip = ip
        self.timestamp = timestamp
        self.request = request
        self.rule_id = rule_id
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "type": self.finding_type,
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "request": self.request,
            "rule_id": self.rule_id,
            "description": self.description,
        }


def is_benign_crawler(user_agent: str) -> Optional[str]:
    """Check if the UA matches a known benign bot. Return bot name or None."""
    ua_lower = user_agent.lower()
    for crawler in sigs.BENIGN_CRAWLERS:
        if re.search(crawler["pattern"], ua_lower, re.IGNORECASE):
            return crawler["name"]
    return None


def detect_scanner_ua(user_agent: str) -> Optional[str]:
    """Check if the UA matches a scanner fingerprint. Return tool name or None."""
    ua_lower = user_agent.lower()
    for scanner in sigs.SCANNER_USER_AGENTS:
        if re.search(scanner["pattern"], ua_lower, re.IGNORECASE):
            return scanner["tool"]
    return None


def match_attack_signatures(entry: LogEntry) -> List[Finding]:
    """
    Run all ATTACK_SIGNATURES rules against this entry.
    Returns a list of findings (one per fired rule).
    """
    findings: List[Finding] = []

    # Skip static resources and benign crawlers
    if entry.is_static():
        return findings
    if is_benign_crawler(entry.user_agent):
        return findings

    decoded = entry.decoded_target().lower()

    for rule in sigs.ATTACK_SIGNATURES:
        patterns = rule["patterns"]
        min_matches = rule.get("min_matches", 1)
        hits = 0
        for pat in patterns:
            if re.search(pat, decoded, re.IGNORECASE):
                hits += 1
        if hits >= min_matches:
            findings.append(
                Finding(
                    severity=rule["severity"],
                    finding_type=rule["type"],
                    ip=entry.ip,
                    timestamp=entry.timestamp,
                    request=entry.raw_request,
                    rule_id=rule["rule_id"],
                    description=rule["description"],
                )
            )

    # Scanner UA fingerprint (separate from path-based rules)
    scanner_tool = detect_scanner_ua(entry.user_agent)
    if scanner_tool:
        findings.append(
            Finding(
                severity="MEDIUM",
                finding_type="Scanner Probe",
                ip=entry.ip,
                timestamp=entry.timestamp,
                request=entry.raw_request,
                rule_id="scanner_ua",
                description=f"Scanner user-agent detected: {scanner_tool}",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# SECTION 3: Brute-force and 404-scan burst detection
# ---------------------------------------------------------------------------

def detect_brute_force(entries: List[LogEntry]) -> List[Finding]:
    """
    Sliding-window brute-force detection on login endpoints.
    Returns findings for IPs that exceed the failure threshold.
    """
    findings: List[Finding] = []
    login_patterns = [re.compile(p, re.IGNORECASE) for p in sigs.BRUTE_FORCE["login_path_patterns"]]
    failure_codes = sigs.BRUTE_FORCE["failure_status_codes"]
    window_sec = sigs.BRUTE_FORCE["window_seconds"]
    min_failures = sigs.BRUTE_FORCE["min_failures"]
    critical_after = sigs.BRUTE_FORCE["critical_after_failures"]

    # Group login failures by IP
    ip_failures: Dict[str, List[datetime]] = defaultdict(list)

    for entry in entries:
        # Check if path is a login endpoint
        is_login = any(pat.search(entry.path) for pat in login_patterns)
        if not is_login:
            continue
        # Check if status indicates failure
        if entry.status in failure_codes and entry.timestamp:
            ip_failures[entry.ip].append(entry.timestamp)

    # Analyze each IP's failure timeline
    for ip, timestamps in ip_failures.items():
        timestamps.sort()
        for i, ts in enumerate(timestamps):
            window_start = ts - timedelta(seconds=window_sec)
            count = sum(1 for t in timestamps if window_start <= t <= ts)
            if count >= min_failures:
                severity = "CRITICAL" if count >= critical_after else "HIGH"
                findings.append(
                    Finding(
                        severity=severity,
                        finding_type="Brute Force",
                        ip=ip,
                        timestamp=ts,
                        request=f"{count} failed login attempts in {window_sec}s",
                        rule_id="brute_force",
                        description=f"Brute-force burst: {count} failures from {ip}",
                    )
                )
                break  # One finding per IP

    return findings


def detect_404_scan(entries: List[LogEntry]) -> List[Finding]:
    """
    Rate-based 404 scanning detection.
    Returns findings for IPs that trigger excessive unique 404s.
    """
    findings: List[Finding] = []
    window_sec = sigs.NOT_FOUND_SCAN["window_seconds"]
    min_unique = sigs.NOT_FOUND_SCAN["min_unique_404s"]
    critical_after = sigs.NOT_FOUND_SCAN["critical_after_unique_404s"]

    # Group 404s by IP
    ip_404s: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)

    for entry in entries:
        if entry.status == 404 and entry.timestamp:
            ip_404s[entry.ip].append((entry.timestamp, entry.path))

    # Sliding window analysis
    for ip, items in ip_404s.items():
        items.sort(key=lambda x: x[0])
        for i, (ts, _) in enumerate(items):
            window_start = ts - timedelta(seconds=window_sec)
            window_paths = [p for t, p in items if window_start <= t <= ts]
            unique_paths = len(set(window_paths))
            if unique_paths >= min_unique:
                severity = "CRITICAL" if unique_paths >= critical_after else "HIGH"
                findings.append(
                    Finding(
                        severity=severity,
                        finding_type="404 Scanning",
                        ip=ip,
                        timestamp=ts,
                        request=f"{unique_paths} unique 404s in {window_sec}s",
                        rule_id="404_scan",
                        description=f"404 scan burst: {unique_paths} paths from {ip}",
                    )
                )
                break

    return findings


# ---------------------------------------------------------------------------
# SECTION 4: Terminal dashboard / reporter
# ---------------------------------------------------------------------------

def draw_banner():
    """Print the LOG-HUNTER ASCII banner."""
    banner_art = r"""
 _     ___   ____       _   _ _   _ _   _ _____ _____ ____  
| |   / _ \ / ___|     | | | | | | | \ | |_   _| ____|  _ \ 
| |  | | | | |  _ _____| |_| | | | |  \| | | | |  _| | |_) |
| |__| |_| | |_| |_____|  _  | |_| | |\  | | | | |___|  _ < 
|_____\___/ \____|     |_| |_|\___/|_| \_| |_| |_____|_| \_\

"""
    print(colorize(banner_art, sigs.THEME["banner"]))
    print(colorize("LOG-Hunter - SOC Log Triage Tool | v1.0.0 | Author: USER-Bi", sigs.THEME["title"]))
    print(colorize("Fast web log attack analysis with low false-positive detection", sigs.THEME["tagline"]))
    print()


def draw_box(title: str, lines: List[str], border_color: str):
    """Draw a colored box with title and content lines."""
    width = max(len(line.replace(Fore.RESET, "").replace(Style.RESET_ALL, "")) for line in lines) + 4
    width = max(width, len(title) + 4)

    top = f"+{'-' * (width - 2)}+"
    bottom = f"+{'-' * (width - 2)}+"
    title_line = f"| {title.ljust(width - 4)} |"

    print(colorize(top, border_color))
    print(colorize(title_line, border_color))
    print(colorize(f"|{'-' * (width - 2)}|", border_color))

    for line in lines:
        # Strip color codes for length calculation
        plain = re.sub(r'\x1b\[[0-9;]+m', '', line)
        pad_needed = width - 4 - len(plain)
        padded = line + " " * pad_needed
        print(colorize("|", border_color) + f" {padded} " + colorize("|", border_color))

    print(colorize(bottom, border_color))
    print()


def summary_stats(
    entries: List[LogEntry],
    findings: List[Finding],
    parse_errors: int,
    duration: float,
) -> Dict[str, Any]:
    """Compute summary statistics for the dashboard."""
    unique_ips = len(set(e.ip for e in entries))

    # Top attackers
    ip_finding_count: Dict[str, int] = defaultdict(int)
    for f in findings:
        if f.severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            ip_finding_count[f.ip] += 1
    top_attackers = sorted(ip_finding_count.items(), key=lambda x: x[1], reverse=True)[:5]

    # Top attacked paths
    path_count: Dict[str, int] = defaultdict(int)
    for e in entries:
        path_count[e.path] += 1
    top_paths = sorted(path_count.items(), key=lambda x: x[1], reverse=True)[:5]

    # Findings by severity
    sev_count = {s: 0 for s in sigs.SEVERITY_ORDER}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    return {
        "total_entries": len(entries),
        "unique_ips": unique_ips,
        "parse_errors": parse_errors,
        "duration": duration,
        "severity_counts": sev_count,
        "top_attackers": top_attackers,
        "top_paths": top_paths,
    }


def display_dashboard(stats: Dict[str, Any], findings: List[Finding]):
    """Print the terminal dashboard."""
    # Detection Summary panel
    duration_str = str(round(stats['duration'], 2)) + 's'
    summary_lines = [
        f"{colorize('Lines parsed:', sigs.THEME['label'])}  {colorize(str(stats['total_entries']), sigs.THEME['value'])}",
        f"{colorize('Unique IPs:', sigs.THEME['label'])}    {colorize(str(stats['unique_ips']), sigs.THEME['value'])}",
        f"{colorize('Parse errors:', sigs.THEME['label'])} {colorize(str(stats['parse_errors']), sigs.THEME['value'])}",
        f"{colorize('Duration:', sigs.THEME['label'])}     {colorize(duration_str, sigs.THEME['value'])}",
    ]
    draw_box("Detection Summary", summary_lines, sigs.THEME["panel_border"])

    # Executive Summary Dashboard panel
    sev_counts = stats["severity_counts"]
    sev_line = " | ".join(
        colorize(f"{sev}: {sev_counts[sev]}", severity_color(sev))
        for sev in sigs.SEVERITY_ORDER
    )

    top_attackers_str = "\n".join(
        f"  {colorize(ip, sigs.THEME['value'])} ({colorize(str(count), 'green')} findings)"
        for ip, count in stats["top_attackers"]
    ) or "  None"

    top_paths_str = "\n".join(
        f"  {colorize(path[:50], sigs.THEME['value'])} ({colorize(str(count), 'green')} hits)"
        for path, count in stats["top_paths"]
    ) or "  None"

    exec_lines = [
        colorize("Findings by Severity:", sigs.THEME["label"]),
        f"  {sev_line}",
        "",
        colorize("Top 5 Attacker IPs:", sigs.THEME["label"]),
        top_attackers_str,
        "",
        colorize("Top 5 Attacked Paths:", sigs.THEME["label"]),
        top_paths_str,
    ]
    draw_box("Executive Summary Dashboard", exec_lines, sigs.THEME["panel_border"])

    # Findings table
    if not findings:
        print(colorize("No security findings detected.", "green"))
        print()
        return

    # Sort findings by severity, then timestamp
    findings.sort(key=lambda f: (sigs.severity_rank(f.severity), f.timestamp or datetime.min))

    w = sigs.TABLE_WIDTHS
    header = (
        f"{'TIME'.ljust(w['time'])} | "
        f"{'SRC IP'.ljust(w['ip'])} | "
        f"{'SEVERITY'.ljust(w['severity'])} | "
        f"{'TYPE'.ljust(w['type'])} | "
        f"{'REQUEST'.ljust(w['request'])}"
    )
    sep = "-" * len(header)

    table_lines = [colorize(header, "bright_white"), colorize(sep, sigs.THEME["table_border"])]

    for f in findings[:50]:  # Limit to 50 rows for terminal display
        ts_str = f.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.timestamp else "N/A"
        ts_str = ts_str.ljust(w["time"])[:w["time"]]
        ip_str = f.ip.ljust(w["ip"])[:w["ip"]]
        sev_tag = colorize(f.severity.center(w["severity"]), severity_color(f.severity))
        type_str = f.finding_type.ljust(w["type"])[:w["type"]]

        # Decode and truncate request
        try:
            decoded_req = unquote_plus(f.request)
        except Exception:
            decoded_req = f.request
        req_str = decoded_req.ljust(w["request"])[:w["request"]]

        row = f"{ts_str} | {ip_str} | {sev_tag} | {type_str} | {req_str}"
        table_lines.append(row)

    # Box the table
    border_color = sigs.THEME["table_border"]
    plain_header = re.sub(r'\x1b\[[0-9;]+m', '', header)
    max_width = len(plain_header)
    top = colorize(f"+{'-' * max_width}+", border_color)
    bottom = colorize(f"+{'-' * max_width}+", border_color)

    print(top)
    for line in table_lines:
        print(colorize("|", border_color) + line + colorize("|", border_color))
    print(bottom)
    print()


# ---------------------------------------------------------------------------
# SECTION 5: JSON report writer
# ---------------------------------------------------------------------------

def write_json_report(
    log_path: str,
    stats: Dict[str, Any],
    findings: List[Finding],
    output_path: str,
):
    """Write a machine-readable JSON report."""
    report = {
        "log_file": log_path,
        "timestamp": datetime.now().isoformat(),
        "summary": stats,
        "findings": [f.to_dict() for f in findings],
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# SECTION 6: CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LOG-Hunter - Web server log attack analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Author: USER-Bi | For authorized testing only.",
    )
    parser.add_argument(
        "-f", "--file",
        dest="log_file",
        help="Path to the Apache/Nginx access log file.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        help="Custom path for JSON report output.",
    )
    parser.add_argument(
        "--whitelist",
        dest="whitelist",
        help="Comma-separated list of IPs to exclude from findings.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"LOG-Hunter v{__version__} by USER-Bi",
    )

    args = parser.parse_args()

    draw_banner()

    # Prompt for log file if not provided
    log_file = args.log_file
    if not log_file:
        log_file = input(colorize("Enter path to log file: ", sigs.THEME["prompt"]))

    if not log_file or not os.path.isfile(log_file):
        print(colorize(f"Error: Log file not found: {log_file}", "red"))
        sys.exit(1)

    whitelist = set()
    if args.whitelist:
        whitelist = set(ip.strip() for ip in args.whitelist.split(","))

    # Parse log
    print(colorize("Parsing log file...", "cyan"))
    start_time = datetime.now()

    entries: List[LogEntry] = []
    parse_errors = 0

    with open(log_file, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
            else:
                parse_errors += 1

    # Run detections
    print(colorize("Running attack signature matching...", "cyan"))
    all_findings: List[Finding] = []

    for entry in entries:
        if entry.ip in whitelist:
            continue
        sig_findings = match_attack_signatures(entry)
        all_findings.extend(sig_findings)

    print(colorize("Detecting brute-force and 404 scans...", "cyan"))
    bf_findings = detect_brute_force(entries)
    scan_findings = detect_404_scan(entries)
    all_findings.extend(bf_findings)
    all_findings.extend(scan_findings)

    duration = (datetime.now() - start_time).total_seconds()

    # Compute stats
    stats = summary_stats(entries, all_findings, parse_errors, duration)

    # Display dashboard
    display_dashboard(stats, all_findings)

    # Write JSON report
    log_name = Path(log_file).stem
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_json = f"reports/loghunter_report_{log_name}_{timestamp_str}.json"
    json_path = args.json_output or default_json

    write_json_report(log_file, stats, all_findings, json_path)
    print(colorize(f"JSON report written to: {json_path}", "green"))


if __name__ == "__main__":
    main()