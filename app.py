from flask import Flask, jsonify, request
from flask_cors import CORS # Import CORS
try:
    from scapy.all import sniff, DNS, DNSQR
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

app = Flask(__name__)
# IMPORTANT: Enable CORS to allow the JavaScript on port 8000
# to make requests to this server on port 5000.
CORS(app)

captured_queries = []

def process_dns_packet(packet):
    """Callback function for scapy to extract DNS query names."""
    if _SCAPY_AVAILABLE and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode('utf-8')
        print(f"Captured DNS Query: {query_name}")
        captured_queries.append(query_name)

@app.route('/analyze')
def analyze_network():
    """API endpoint to trigger packet capture and return raw data."""
    if not _SCAPY_AVAILABLE:
        return jsonify({"error": "scapy is not installed; /analyze is unavailable"}), 501
    global captured_queries
    captured_queries = []

    print("Starting packet capture for 5 seconds...")
    # Note: Requires root/administrator privileges.
    sniff(filter="udp port 53", prn=process_dns_packet, count=15, timeout=5)
    print("Packet capture finished. Sending raw data to client.")

    # Just return the raw list of queries as JSON
    return jsonify({"captured_data": captured_queries})

# --- Vulnerability Scanner additions ---
import asyncio
import json as _json
import os as _os
import re as _re
from datetime import datetime as _dt, timezone as _tz
from typing import List as _List, Dict as _Dict, Any as _Any, Optional as _Optional

_LOG_DIR = _os.path.join(_os.path.dirname(__file__), 'logs')
_os.makedirs(_LOG_DIR, exist_ok=True)

_SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']

async def _probe_port(host: str, port: int, timeout_seconds: float = 1.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
        try:
            writer.close()
            if hasattr(writer, 'wait_closed'):
                await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def _recv_banner(host: str, port: int, to_send: bytes = b'', read_bytes: int = 1024, timeout_seconds: float = 1.5) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
        try:
            if to_send:
                writer.write(to_send)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout_seconds)
            banner = data.decode('utf-8', errors='ignore')
        finally:
            try:
                writer.close()
                if hasattr(writer, 'wait_closed'):
                    await writer.wait_closed()
            except Exception:
                pass
        return banner
    except Exception:
        return ''

async def _enumerate_service(host: str, port: int) -> _Dict[str, _Any]:
    service_guess = None
    banner = ''

    if port in (80, 8080, 8000, 8888, 443):
        payload = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
        banner = await _recv_banner(host, port, payload, 2048)
        service_guess = 'https' if port == 443 else 'http'
    elif port == 22:
        banner = await _recv_banner(host, port, b'', 512)
        service_guess = 'ssh'
    elif port == 21:
        banner = await _recv_banner(host, port, b'', 512)
        service_guess = 'ftp'
    elif port == 25:
        banner = await _recv_banner(host, port, b'EHLO scanner\r\n', 512)
        service_guess = 'smtp'
    elif port == 110:
        banner = await _recv_banner(host, port, b'', 512)
        service_guess = 'pop3'
    elif port == 143:
        banner = await _recv_banner(host, port, b'A001 CAPABILITY\r\n', 1024)
        service_guess = 'imap'
    else:
        # Generic attempt: connect, send nothing, read something
        banner = await _recv_banner(host, port, b'', 512)

    # Refine guess from banner content
    if not service_guess:
        if 'SSH-' in banner:
            service_guess = 'ssh'
        elif 'SMTP' in banner or banner.startswith('220 '):
            service_guess = 'smtp'
        elif 'FTP' in banner:
            service_guess = 'ftp'
        elif 'HTTP/' in banner or 'Server:' in banner:
            service_guess = 'http'

    return { 'service': service_guess, 'banner': banner.strip() or None }

def _evaluate_vulnerabilities(service: _Optional[str], banner: _Optional[str], port: int) -> _List[_Dict[str, _Any]]:
    findings: _List[_Dict[str, _Any]] = []
    text = f"{service or ''} {banner or ''}"

    rules = [
        # HTTP servers
        {
            'id': 'HTTP-Apache-2.4.49-traversal',
            'severity': 'critical',
            'pattern': r'Apache\/2\.4\.49',
            'description': 'Vulnerable Apache 2.4.49 susceptible to path traversal (CVE-2021-41773).',
            'when_port_in': [80, 8080, 8000, 8888, 443]
        },
        {
            'id': 'HTTP-Apache-2.2-EOL',
            'severity': 'high',
            'pattern': r'Apache\/2\.2(\.|\s|$)',
            'description': 'Apache 2.2 is end-of-life; multiple known vulnerabilities.',
            'when_port_in': [80, 8080, 8000, 8888, 443]
        },
        {
            'id': 'HTTP-PHP-5-EOL',
            'severity': 'high',
            'pattern': r'PHP\/5\.',
            'description': 'Outdated PHP 5 detected (end-of-life).',
            'when_port_in': [80, 8080, 8000, 8888, 443]
        },
        # SSH
        {
            'id': 'SSH-OpenSSH-legacy',
            'severity': 'high',
            'pattern': r'OpenSSH\_([0-6]\.\d+|7\.[0-3])',
            'description': 'Legacy OpenSSH version; upgrade recommended due to multiple CVEs.',
            'when_port_in': [22]
        },
        # FTP
        {
            'id': 'FTP-vsftpd-2.3.4-backdoor',
            'severity': 'critical',
            'pattern': r'vsFTPd 2\.3\.4',
            'description': 'vsFTPd 2.3.4 backdoor vulnerability.',
            'when_port_in': [21]
        },
        # SMTP
        {
            'id': 'SMTP-OpenRelay-suspected',
            'severity': 'medium',
            'pattern': r'ESMTP|SMTP',
            'description': 'SMTP detected; verify relay restrictions to prevent open relay.',
            'when_port_in': [25]
        },
    ]

    for rule in rules:
        if port in rule.get('when_port_in', []):
            if _re.search(rule['pattern'], text or '', flags=_re.IGNORECASE):
                findings.append({
                    'id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'evidence': (banner or '').strip()[:300] or None
                })

    return findings

def _parse_ports(ports_value: _Any) -> _List[int]:
    ports: _List[int] = []
    if isinstance(ports_value, list):
        for p in ports_value:
            try:
                ports.append(int(p))
            except Exception:
                continue
    elif isinstance(ports_value, str):
        for token in ports_value.split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                try:
                    start_s, end_s = token.split('-', 1)
                    start, end = int(start_s), int(end_s)
                    if start <= end:
                        ports.extend(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    ports.append(int(token))
                except Exception:
                    continue
    else:
        # Default top common ports if unspecified
        ports = [22, 21, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443]
    # Deduplicate and bounds check
    ports = sorted({p for p in ports if 1 <= p <= 65535})
    return ports

async def _run_scan(host: str, ports: _List[int], do_enum: bool, do_vuln: bool) -> _List[_Dict[str, _Any]]:
    results: _List[_Dict[str, _Any]] = []

    async def scan_one(port: int) -> None:
        is_open = await _probe_port(host, port)
        entry: _Dict[str, _Any] = {
            'port': port,
            'protocol': 'tcp',
            'status': 'open' if is_open else 'closed'
        }
        if is_open and do_enum:
            enum = await _enumerate_service(host, port)
            entry.update(enum)
            if do_vuln:
                entry['vulnerabilities'] = _evaluate_vulnerabilities(enum.get('service'), enum.get('banner'), port)
        results.append(entry)

    await asyncio.gather(*(scan_one(p) for p in ports))
    # Sort by port number
    results.sort(key=lambda x: x.get('port', 0))
    return results

@app.route('/scan', methods=['POST'])
def start_scan():
    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400

    target = payload.get('target')
    ports = _parse_ports(payload.get('ports'))
    do_enum = bool(payload.get('service_enumeration', True))
    do_vuln = bool(payload.get('vulnerability_checks', True))

    if not target:
        return jsonify({'error': 'Missing required field: target'}), 400

    scan_id = payload.get('scan_id') or _dt.now(tz=_tz.utc).strftime('%Y%m%dT%H%M%SZ')
    started_at = _dt.now(tz=_tz.utc).isoformat()

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(_run_scan(target, ports, do_enum, do_vuln))
    finally:
        loop.close()

    ended_at = _dt.now(tz=_tz.utc).isoformat()

    output = {
        'scan_id': scan_id,
        'target': target,
        'started_at': started_at,
        'ended_at': ended_at,
        'results': results,
        'errors': []
    }

    # Persist log for the Perl report service
    log_path = _os.path.join(_LOG_DIR, f'scan-{scan_id}.json')
    try:
        with open(log_path, 'w', encoding='utf-8') as f:
            _json.dump(output, f, ensure_ascii=False, indent=2)
        output['log_path'] = log_path
    except Exception as e:
        output['errors'].append(f'Failed to write log: {e}')

    return jsonify(output), 200

# Re-declare the app runner to remain at the end of file
if __name__ == '__main__':
    app.run(debug=True, port=5000)