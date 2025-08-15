# Cross-Platform Network Vulnerability Scanner (Polyglot)

This example demonstrates a decoupled, cross-platform network vulnerability scanner and reporter:

- Python (Flask): Core scanning API for TCP port scanning, service enumeration, and simple vulnerability checks.
- Perl (Mojolicious): Report generation and filtering from scan logs or posted results.
- JavaScript (vanilla): Interactive UI to configure scans and display dynamic vulnerability reports.

## Components

1. **Python Scanning API (`app.py`)**
   - `POST /scan` accepts JSON: `{ target, ports, service_enumeration, vulnerability_checks }`
   - Performs async TCP scan, optional banner grabbing and heuristic vuln checks.
   - Persists JSON logs under `example_project/logs/scan-<id>.json`.
   - Also retains the sample DNS capture endpoint `GET /analyze` from the original sample.

2. **Perl Report Service (`parser_app.pl`)**
   - `POST /report?severity=<level>` accepts `{ scan }` (the JSON returned by Python) or `{ log_path }` to a file.
   - Aggregates open ports and groups vulnerabilities by severity with filter (info|low|medium|high|critical).
   - `GET /report/latest` returns the most recent scan JSON from the logs directory.

3. **Frontend (`index.html`)**
   - Form to set target, ports (comma and dash ranges), and toggles for enumeration/vuln checks.
   - Calls Python `/scan`, then Perl `/report` to render a dynamic report and the raw JSON.

## Run Instructions

1) Create and activate Python venv (recommended) and install deps:

```bash
cd example_project
python3 -m venv ../venv
source ../venv/bin/activate
pip install Flask Flask-Cors
```

2) Start the Python API (port 5000):

```bash
python app.py
```

3) Install Perl dependencies and start report service (port 3000):

```bash
cpan Mojolicious
morbo parser_app.pl
```

4) Open the UI:

- Open `example_project/index.html` in a browser.
- Enter a target (e.g., `127.0.0.1`) and ports (e.g., `22,80,443,8000-8100`).
- Click "Run Scan" to see open ports and grouped vulnerabilities. Use the severity filter to refine.

## Notes

- Scanning and banner grabbing operate over TCP without special privileges. Some services may throttle or block banners.
- Vulnerability checks are heuristic examples; integrate a real feed (e.g., NVD) for production.
- CORS is enabled on both services to allow the static UI to communicate with Python (5000) and Perl (3000).
- Logs write to `example_project/logs/` for reproducible reporting and automation.
