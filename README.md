# LOG-Hunter

**Web Server Log Attack Analyzer for SOC-Style Log Triage**

LOG-Hunter is a professional Python CLI tool that parses Apache and Nginx access logs, detects attack patterns with low false-positive rates, and outputs a beautiful terminal dashboard plus machine-readable JSON reports.

Author: **USER-Bi**

---

## Features

- **Modular architecture**: Detection rules live in `signatures.py` — add/tune rules without touching the engine
- **URL-decoding aware**: Matches payloads like `%3Cscript`, `..%2f..`, and `%27+OR+1=1` correctly
- **Low false-positive design**:
  - Payload-shape matching (e.g., `UNION SELECT`, not just "select")
  - Threshold-based brute-force detection (>10 failures in a window)
  - Rate-based 404 scanning (>30 unique 404s, not single requests)
  - Excludes benign crawlers (Googlebot, Bingbot, etc.) and static assets
- **Attack coverage**:
  - SQL injection (UNION, tautology, blind/time-based, comment obfuscation)
  - Cross-site scripting (script tags, event handlers, javascript: URIs)
  - Path traversal / LFI (traversal sequences, sensitive files, PHP wrappers)
  - Web-shell probes (c99, r57, wso, cmd.php, etc.)
  - Scanner fingerprints (sqlmap, Nikto, Acunetix, masscan, etc.)
  - Brute-force login attacks
  - 404 scanning bursts
- **Severity levels**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Beautiful terminal UI**: Pentest-suite styling with colored panels, ASCII banner, findings table
- **JSON reports**: Full machine-readable output with timestamps, rule IDs, descriptions
- **Whitelist support**: `--whitelist` to exclude trusted IPs
- **Graceful error handling**: Malformed log lines are counted, never crash the tool

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/LOG-Hunter.git
cd LOG-Hunter
pip install -r requirements.txt
```

**Requirements**: Python 3.7+ and `colorama` (automatically installed).

---

## Usage

### Interactive mode (prompt for log file):

```bash
python log_hunter.py
```

### Direct invocation:

```bash
python log_hunter.py -f /var/log/nginx/access.log
```

### Custom JSON output path:

```bash
python log_hunter.py -f access.log --json /tmp/my_report.json
```

### Whitelist trusted IPs:

```bash
python log_hunter.py -f access.log --whitelist 192.168.1.1,10.0.0.5
```

### Version info:

```bash
python log_hunter.py --version
```

---

## Sample Output

On startup, LOG-Hunter displays a cyan ASCII banner:

```
 ██╗      ██████╗  ██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ██║     ██╔═══██╗██╔════╝       ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║     ██║   ██║██║  ███╗█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║     ██║   ██║██║   ██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ███████╗╚██████╔╝╚██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══════╝ ╚═════╝  ╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

LOG-Hunter - SOC Log Triage Tool | v1.0.0 | Author: USER-Bi
Fast web log attack analysis with low false-positive detection
```

Then it displays:

1. **Detection Summary** panel (magenta border): lines parsed, unique IPs, parse errors, duration
2. **Executive Summary Dashboard** panel: severity counts (color-coded), top 5 attacker IPs, top 5 attacked paths
3. **Findings table** (green border): TIME | SRC IP | SEVERITY (colored tag) | TYPE | REQUEST (URL-decoded)

Finally, it writes a JSON report: `reports/loghunter_report_<logfile>_<YYYYMMDD_HHMMSS>.json`

---

## False-Positive Prevention Notes

- **SQLi/XSS/LFI regexes** require payload shapes (e.g., `UNION SELECT`, `' OR 1=1`, `<script`, `../etc/passwd`), not bare keywords.
- **Brute-force** is threshold-based: >10 failed login attempts from one IP in a 5-minute window. A single failed login is ignored.
- **404 scanning** is rate-based: >30 unique 404 paths from one IP in a 2-minute window. Single 404s are normal traffic.
- **Benign crawlers** (Googlebot, Bingbot, etc.) are excluded from signature matching but counted separately as INFO.
- **Static assets** (.css, .js, .png, etc.) are never scanned for attack signatures.
- Use `--whitelist` to exclude internal monitoring IPs, load balancers, or trusted scanners.

**Known limitations**:
- The tool cannot parse response bodies (only status codes), so POST-based attacks without status-code failures may be under-reported.
- Compressed logs (`.gz`) must be decompressed first (`gunzip`).
- Time-window detections assume chronological log order. If logs are shuffled, results may vary.

---

## Adding New Detection Rules

All detection rules live in **`signatures.py`**. To add a new rule:

1. Open `signatures.py`
2. Add a new dict to `ATTACK_SIGNATURES`:

```python
{
    "rule_id": "my_new_rule",
    "severity": "HIGH",
    "type": "My Attack Type",
    "patterns": [
        r"pattern1",
        r"pattern2",
    ],
    "min_matches": 1,
    "description": "Human-readable description",
}
```

3. Run `log_hunter.py` — no changes to the engine required.

The engine automatically URL-decodes requests, matches patterns case-insensitively, and applies the `min_matches` threshold.

---

## Testing

A sanitized `sample_access.log` is included. Run:

```bash
python log_hunter.py -f sample_access.log
```

You should see:
- Googlebot requests excluded from attack findings
- SQL injection detected (`' OR '1'='1`, `UNION SELECT`)
- XSS detected (`<script>alert(1)</script>`)
- Path traversal detected (`../../../../etc/passwd`, `php://filter`)
- Web-shell probes detected (`/shell.php`, `/c99.php`)
- Brute-force burst detected (11 failed WordPress login attempts from one IP)
- Scanner UA detected (sqlmap user-agent)
- Static assets (.css, .js) ignored

---

## Disclaimer

**For authorized security testing and log analysis only.**

Unauthorized access to computer systems is illegal. Always obtain proper authorization before analyzing logs or testing systems you do not own.

---

## Author

**USER-Bi**

---

## License

This project is provided as-is for educational and professional SOC/incident-response use. No warranty is provided.