#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signatures.py - LOG-Hunter detection rule table.

Author: USER-Bi

---------------------------------------------------------------------------
THIS IS THE ONLY FILE YOU NEED TO EDIT TO ADD / REMOVE / TUNE DETECTIONS.
---------------------------------------------------------------------------

Nothing here imports anything from log_hunter.py, and log_hunter.py never
hardcodes a payload string. The engine walks the tables below, so adding a
rule is a data edit, not a code change.

How a rule is matched
---------------------
1. The request target (path + query) is **URL-decoded** (once) and compared
   case-insensitively against each pattern. So ``%3Cscript`` and ``..%2f..``
   are normalised before the regex ever runs.
2. Regexes are intentionally anchored on *payload shapes* (``UNION SELECT``,
   ``' OR 1=1``, ``../etc/passwd``), never on bare English words. A URL like
   ``/search?q=selecting+a+product`` therefore does not fire SQLi.
3. Per-rule ``min_matches`` skips noise: a rule may require several matching
   patterns in the same request before it emits a finding.

Field reference for an ATTACK_SIGNATURES entry
----------------------------------------------
    rule_id     : short stable id (used in JSON reports and --rules output)
    severity    : one of CRITICAL / HIGH / MEDIUM / LOW / INFO
    type        : human label shown in the findings table
    patterns    : list of raw regex strings (applied to the decoded target)
    min_matches : how many patterns must hit before a finding is emitted
    description : one-line explanation, printed by --rules
    dedupe_key  : optional, groups several rules into one finding type
                  (e.g. every 404-scan rule reports as "404 Scanning")
"""

from __future__ import annotations

__author__ = "USER-Bi"
__version__ = "1.0.0"

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Severity levels, ordered most severe first. Used for sorting and colouring.
# ---------------------------------------------------------------------------

SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ---------------------------------------------------------------------------
# SECTION 1 - ATTACK SIGNATURES (payload matching on the decoded request)
# ---------------------------------------------------------------------------
#
# Keep patterns as raw strings (r"..."). Prefer explicit multi-token shapes
# over single keywords to keep the false-positive rate down.
#

ATTACK_SIGNATURES: List[Dict[str, Any]] = [
    # -----------------------------------------------------------------
    # SQL injection
    # Requires a real payload shape: an injection keyword *plus* SQL
    # syntax, or a tautology. Bare "select" in a query string is ignored.
    # -----------------------------------------------------------------
    {
        "rule_id": "sqli_union_select",
        "severity": "CRITICAL",
        "type": "SQL Injection",
        "patterns": [
            r"union[\s/*]*(?:all[\s/*]*)?select\b",
            r"union\s+select\s+.{0,40}\b(?:from|into)\b",
        ],
        "min_matches": 1,
        "description": "UNION SELECT based SQL injection attempt",
    },
    {
        "rule_id": "sqli_tautology",
        "severity": "HIGH",
        "type": "SQL Injection",
        "patterns": [
            r"'\s*(?:or|and)\s+(?:'?[\w\"']+'?\s*=\s*'?[\w\"']+'?|\d+\s*=\s*\d+)",
            r"\b(?:or|and)\b\s+1\s*=\s*1\b",
            r"'\s*or\s+'[^']*'\s*=\s*'",
        ],
        "min_matches": 1,
        "description": "SQL tautology such as ' OR 1=1",
    },
    {
        "rule_id": "sqli_stacked_blind",
        "severity": "HIGH",
        "type": "SQL Injection",
        "patterns": [
            r";\s*(?:drop|alter|create|truncate|insert|update|delete)\s+table\b",
            r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
            r"\bselect\b.{0,40}\b(?:from|where)\b",
            r"\binformation_schema\b",
        ],
        "min_matches": 2,
        "description": "Stacked query / blind SQLi (time-based, schema probing)",
    },
    {
        "rule_id": "sqli_comment_terminator",
        "severity": "MEDIUM",
        "type": "SQL Injection",
        "patterns": [
            r"'\s*(?:--|#|/\*)",
            r"/\*!\d{5}",
            r"\bconvert\s*\(\s*int\b",
        ],
        "min_matches": 2,
        "description": "SQL comment terminator / inline comment obfuscation",
    },

    # -----------------------------------------------------------------
    # Cross-site scripting
    # -----------------------------------------------------------------
    {
        "rule_id": "xss_script_tag",
        "severity": "HIGH",
        "type": "XSS",
        "patterns": [
            r"<\s*script\b",
            r"<\s*/\s*script\s*>",
            r"<\s*(?:iframe|svg|object|embed|body|img)\b[^>]*(?:src|on\w+)\s*=",
        ],
        "min_matches": 1,
        "description": "Injected script / markup tag in request",
    },
    {
        "rule_id": "xss_event_handler",
        "severity": "HIGH",
        "type": "XSS",
        "patterns": [
            r"\bon(?:error|load|mouseover|click|focus|submit|animationstart)\s*=",
            r"javascript\s*:",
            r"\bdata\s*:\s*text/html",
        ],
        "min_matches": 1,
        "description": "Event-handler / javascript: URI XSS payload",
    },
    {
        "rule_id": "xss_probe",
        "severity": "MEDIUM",
        "type": "XSS",
        "patterns": [
            r"\b(?:alert|prompt|confirm)\s*\(\s*(?:\"|'|\d|document|window)",
            r"document\s*\.\s*(?:cookie|domain|write)",
            r"<[a-z]+\s+[^>]*\bon\w+\s*=",
        ],
        "min_matches": 2,
        "description": "Reflected-XSS probe (alert()/document.cookie)",
    },

    # -----------------------------------------------------------------
    # Path traversal / local file inclusion
    # Requires traversal depth *plus* a sensitive target, or a known
    # wrapper scheme, so "/api/v1/../users" style noise stays quiet.
    # -----------------------------------------------------------------
    {
        "rule_id": "lfi_traversal",
        "severity": "HIGH",
        "type": "Path Traversal / LFI",
        "patterns": [
            r"(?:\.\./){2,}",
            r"%2e%2e(?:%2f|/|\\)",
            r"\.\.(?:/|\\|%2f|%5c)",
        ],
        "min_matches": 1,
        "description": "Directory traversal sequence",
    },
    {
        "rule_id": "lfi_sensitive_file",
        "severity": "CRITICAL",
        "type": "Path Traversal / LFI",
        "patterns": [
            r"/etc/(?:passwd|shadow|hosts|group)\b",
            r"\b(?:boot\.ini|win\.ini|sam\b|system32[/\\]config)",
            r"(?:proc/self/environ|\.\./\.\./\.\./)",
            r"/var/log/(?:auth|secure|messages)",
        ],
        "min_matches": 1,
        "description": "Traversal aimed at a sensitive system file",
    },
    {
        "rule_id": "lfi_wrapper",
        "severity": "HIGH",
        "type": "Path Traversal / LFI",
        "patterns": [
            r"\bphp://(?:filter|input|data)\b",
            r"\b(?:data|expect|zip|phar|glob)://",
            r"\bphp://filter/.*(?:convert|base64)",
        ],
        "min_matches": 1,
        "description": "PHP stream-wrapper abuse (filter/input/data)",
    },

    # -----------------------------------------------------------------
    # Web-shell probes
    # -----------------------------------------------------------------
    {
        "rule_id": "webshell_known",
        "severity": "CRITICAL",
        "type": "Web Shell Probe",
        "patterns": [
            r"/(?:c99|r57|b374k|wso|alfa|indoxploit|g00nshell|webshell)(?:\.\w+)?(?:\?|$)",
            r"/(?:shell|cmd|c99|up|upload)\.(?:php|asp|aspx|jsp)(?:\?|$)",
            r"/(?:mysql|symlink|mass|zone-h)\.php(?:\?|$)",
        ],
        "min_matches": 1,
        "description": "Request for a well-known public web shell",
    },
    {
        "rule_id": "webshell_functions",
        "severity": "HIGH",
        "type": "Web Shell Probe",
        "patterns": [
            r"\b(?:eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(",
            r"\b(?:base64_decode|gzinflate|str_rot13)\s*\(",
            r"\bcmd\s*=|c99shell|FilesMan",
        ],
        "min_matches": 2,
        "description": "Remote-code-execution function used as a parameter",
    },

    # -----------------------------------------------------------------
    # Scanner / tooling fingerprints in the request target
    # (User-agent fingerprints live in SCANNER_USER_AGENTS below.)
    # -----------------------------------------------------------------
    {
        "rule_id": "scanner_paths",
        "severity": "MEDIUM",
        "type": "Scanner Probe",
        "patterns": [
            r"/(?:phpmyadmin|pma|adminer|dbadmin)(?:/|\?|$)",
            r"/(?:\.git|\.svn|\.env|\.aws|\.ssh)(?:/|\?|$)",
            r"/(?:wp-config\.php\.bak|backup\.(?:sql|zip|tar\.gz)|\.DS_Store)",
            r"/(?:actuator|swagger-ui|api-docs|\.well-known/security\.txt)",
        ],
        "min_matches": 1,
        "description": "Exposed administrative / configuration path probe",
    },
]

# ---------------------------------------------------------------------------
# SECTION 2 - SCANNER USER-AGENT FINGERPRINTS
# ---------------------------------------------------------------------------
# Matched against the User-Agent header (case-insensitive substring OR regex).
#

SCANNER_USER_AGENTS: List[Dict[str, str]] = [
    {"pattern": r"sqlmap", "tool": "sqlmap"},
    {"pattern": r"nikto", "tool": "Nikto"},
    {"pattern": r"masscan", "tool": "masscan"},
    {"pattern": r"(?:acunetix|wvs)", "tool": "Acunetix"},
    {"pattern": r"nmap\s+scripting\s+engine|nmap", "tool": "Nmap NSE"},
    {"pattern": r"(?:nessus|openvas)", "tool": "Nessus/OpenVAS"},
    {"pattern": r"(?:dirbuster|gobuster|dirb|wfuzz|ffuf)", "tool": "Content fuzzer"},
    {"pattern": r"(?:nuclei|zgrab|zgrab2)", "tool": "Nuclei/ZGrab"},
    {"pattern": r"(?:hydra|patator|medusa)", "tool": "Brute forcer"},
    {"pattern": r"(?:python-requests|curl/|wget/|libwww-perl|go-http-client)", "tool": "Scripted client"},
    {"pattern": r"(?:havij|pangolin|jsql|sqlninja)", "tool": "SQLi tool"},
]

# ---------------------------------------------------------------------------
# SECTION 3 - BENIGN CRAWLERS (counted as INFO, excluded from signature hits)
# ---------------------------------------------------------------------------

BENIGN_CRAWLERS: List[Dict[str, str]] = [
    {"pattern": r"googlebot", "name": "Googlebot"},
    {"pattern": r"bingbot|msnbot", "name": "Bingbot"},
    {"pattern": r"duckduckbot", "name": "DuckDuckBot"},
    {"pattern": r"yandexbot", "name": "YandexBot"},
    {"pattern": r"baiduspider", "name": "BaiduSpider"},
    {"pattern": r"applebot", "name": "Applebot"},
    {"pattern": r"ahrefsbot|semrushbot|mj12bot|dotbot|petalbot", "name": "SEO crawler"},
    {"pattern": r"facebookexternalhit|twitterbot|slackbot|telegrambot", "name": "Social preview bot"},
    {"pattern": r"uptimerobot|pingdom|statuscake", "name": "Uptime monitor"},
]

# ---------------------------------------------------------------------------
# SECTION 4 - LOGIN / BRUTE-FORCE TUNING
# ---------------------------------------------------------------------------

BRUTE_FORCE: Dict[str, Any] = {
    # Any request whose path matches one of these is a "login request".
    "login_path_patterns": [
        r"/(?:wp-login\.php|wp-admin|xmlrpc\.php)",
        r"/(?:login|log-in|signin|sign-in|auth|authenticate)(?:/|\?|$|\.)",
        r"(?:/admin|/administrator|/manage|/panel|/cpanel)(?:/|\?|$)",
        r"/(?:user|account|session)s?/(?:login|signin)",
        r"/(?:api|v\d+)/(?:login|token|oauth)",
        r"(?:phpmyadmin|pma|webmail|roundcube|owa)(?:/|\?|$)",
    ],
    # HTTP status codes that mean "the credential was rejected".
    "failure_status_codes": [401, 403],
    # ...or a POST to a login path answered with 200 + failure keyword.
    "failure_body_keywords": [
        "invalid password", "incorrect password", "login failed",
        "authentication failed", "invalid credentials", "wrong password",
        "access denied", "too many failed",
    ],
    # Threshold: this many failures from ONE ip inside the window.
    "min_failures": 10,
    # Sliding window length, in seconds.
    "window_seconds": 300,
    # Escalate the whole burst to CRITICAL past this many failures.
    "critical_after_failures": 40,
}

# ---------------------------------------------------------------------------
# SECTION 5 - 404 SCANNING BURST TUNING
# ---------------------------------------------------------------------------
# Rate-based, not request-based: a single 404 is never a finding.
#

NOT_FOUND_SCAN: Dict[str, Any] = {
    # Consecutive-window length for counting 404s, in seconds.
    "window_seconds": 120,
    # Distinct 404 paths from one IP inside the window before we care.
    "min_unique_404s": 30,
    # Alternatively: this many distinct 404s overall (set lower), provided
    # they are also at least `min_distinct_ratio` of that IP's traffic.
    "min_404_ratio": 0.60,
    "min_requests_for_ratio_rule": 25,
    # Escalate past this many unique 404s.
    "critical_after_unique_404s": 150,
}

# ---------------------------------------------------------------------------
# SECTION 6 - REQUEST-RATE / FLOOD TUNING (optional INFO-level signal)
# ---------------------------------------------------------------------------

RATE_FLOOD: Dict[str, Any] = {
    "enabled": True,
    "window_seconds": 60,
    "min_requests": 300,
}

# ---------------------------------------------------------------------------
# SECTION 7 - FILES THE PARSER TREATS AS STATIC (ignored for signature hits)
# ---------------------------------------------------------------------------

STATIC_EXTENSIONS: List[str] = [
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
    ".pdf", ".zip", ".gz", ".mp3",
]

# ---------------------------------------------------------------------------
# SECTION 8 - PARSER SUPPORT: log formats + timestamp formats
# ---------------------------------------------------------------------------

LOG_FORMATS: Dict[str, str] = {
    # Apache / Nginx "combined" plus the common "-" variant.
    "combined": (
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) '
        r'\[(?P<time>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    ),
    # "common": no referer/agent.
    "common": (
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) '
        r'\[(?P<time>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    ),
    # Nginx error-tolerance: some collectors omit the ident/user pair.
    "combined_short": (
        r'(?P<ip>\S+) - (?P<user>\S+) '
        r'\[(?P<time>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    ),
}

# Tried in order against the bracketed timestamp field.
TIME_FORMATS: List[str] = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M",
]

# ---------------------------------------------------------------------------
# SECTION 9 - UI THEME (bullet-proof: mirrors the AutoSecurityPro palette)
# ---------------------------------------------------------------------------

THEME: Dict[str, str] = {
    "banner": "cyan",
    "title": "cyan",
    "tagline": "green",
    "prompt": "yellow",
    "panel_border": "magenta",
    "table_border": "green",
    "label": "white",
    "value": "cyan",
    "dim": "bright_black",
    "CRITICAL": "bright_white on red",
    "HIGH": "bright_white on red",
    "MEDIUM": "black on yellow",
    "LOW": "black on cyan",
    "INFO": "black on green",
}

# Column widths for the findings table (content is truncated to fit).
TABLE_WIDTHS: Dict[str, int] = {
    "time": 19,
    "ip": 15,
    "severity": 8,
    "type": 22,
    "request": 52,
}

# ---------------------------------------------------------------------------
# Helpers - the engine calls these; you normally do not need to edit them.
# ---------------------------------------------------------------------------


def severity_rank(severity: str) -> int:
    """Return the sort index of ``severity`` (0 = most severe)."""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


def all_rules() -> List[Dict[str, Any]]:
    """Return every attack signature rule, for --rules listings."""
    return list(ATTACK_SIGNATURES)


def find_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    """Look up a single rule by ``rule_id`` (or return ``None``)."""
    for rule in ATTACK_SIGNATURES:
        if rule["rule_id"] == rule_id:
            return rule
    return None