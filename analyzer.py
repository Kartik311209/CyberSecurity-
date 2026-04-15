"""
CFIP – Cyber Forensic Intelligence Platform
Real Log Analysis Engine  |  analyzer.py

Supported formats:
  - Linux  : auth.log, syslog, /var/log/*
  - Windows: .evtx (via wevtutil), plain event-log text
  - Cloud  : AWS CloudTrail (JSON), Azure Monitor (JSON)
  - Web    : Apache / Nginx access logs
  - Generic: CSV, JSON, plain text
"""
from __future__ import annotations

import re, json, csv, io, os, datetime, ipaddress, subprocess
import hashlib
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Tuple

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

# ════════════════════════════════════════════════════════
#  CONSTANTS & THRESHOLDS
# ════════════════════════════════════════════════════════
MAX_EVENTS_PER_FILE = 50_000
BRUTE_THRESHOLD     = 5      # failed logins → brute-force
BRUTE_WINDOW_SEC    = 600    # 10-minute window
SCAN_PORT_THRESHOLD = 10     # distinct dst ports → portscan

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]
SUSPICIOUS_COUNTRIES = {'RU', 'CN', 'KP', 'IR', 'SY', 'BY', 'CU', 'VE'}

# ── Windows Event IDs → (description, severity, type) ───
WIN_EVENT_MAP: Dict[int, Tuple[str,str,str]] = {
    4625: ('Failed Logon',                  'critical', 'failed_login'),
    4624: ('Successful Logon',              'info',     'login_ok'),
    4740: ('Account Locked Out',            'critical', 'lockout'),
    4720: ('User Account Created',          'warning',  'account_create'),
    4726: ('User Account Deleted',          'warning',  'account_delete'),
    4732: ('User Added to Admins Group',    'critical', 'privesc'),
    4728: ('User Added to Global Group',    'warning',  'privesc'),
    4756: ('User Added to Universal Group', 'warning',  'privesc'),
    4648: ('Logon Using Explicit Creds',    'warning',  'credential'),
    4771: ('Kerberos Pre-Auth Failure',     'warning',  'failed_login'),
    4768: ('Kerberos TGT Requested',        'info',     None),
    1102: ('Audit Log Cleared',             'critical', 'tamper'),
    7045: ('New Service Installed',         'warning',  'persistence'),
    4697: ('Service Installed',             'warning',  'persistence'),
    4688: ('Process Created',               'info',     'process'),
    4698: ('Scheduled Task Created',        'warning',  'persistence'),
    4663: ('Object Access Attempt',         'info',     None),
    5156: ('Network Connection Allowed',    'info',     None),
    5157: ('Network Connection Blocked',    'warning',  'scan'),
}

# ════════════════════════════════════════════════════════
#  REGEX LIBRARY
# ════════════════════════════════════════════════════════
# --- Linux SSH / auth.log ---
_SSH_FAIL    = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+')
_SSH_OK      = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)')
_SSH_INVALID = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)')
_SUDO        = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?sudo.*?USER=(?P<to_user>\S+).*?COMMAND=(?P<cmd>.+)')
_NEW_USER    = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?new user: name=(?P<user>\S+)')
_UFW_BLOCK   = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?UFW BLOCK.*?SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+).*?PROTO=(?P<proto>\S+)')
_IPTABLES    = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?iptables.*?SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+)')
_SU_OPEN     = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?su.*?session opened for user (?P<user>\S+)')
_CRON_FAIL   = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?cron.*?ERROR')
_LOGIN_FAIL  = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?login.*?FAILED.*?(?P<user>\S+)', re.I)
_PAM_FAIL    = re.compile(r'(?P<ts>\w{3}\s+\d+\s+[\d:]+).*?pam_unix.*?authentication failure.*?user=(?P<user>\S+)')

# --- Apache / Nginx access log ---
_APACHE_CLF  = re.compile(r'^(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>[^"]+) HTTP/[\d.]+" (?P<status>\d{3}) (?P<bytes>\d+|-)')

# --- Generic patterns ---
_ISO_TS      = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
_IP_ANY      = re.compile(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_FAIL_KW     = re.compile(r'\b(fail|failed|failure|error|denied|reject|invalid|unauthorized|blocked|attack|brute|scan|exploit|malware|ransomware|suspicious|anomaly|intrusion)\b', re.I)
_OK_KW       = re.compile(r'\b(success|accept|authorized|establish|complet|granted|logged in)\b', re.I)

# --- Windows XML (wevtutil / evtx) ---
_WIN_EVID    = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
_WIN_TIME    = re.compile(r'SystemTime=.([0-9T:\.\-Z+]+)')
_WIN_IP      = re.compile(r'<Data Name=.IpAddress.>([^<]+)</Data>')
_WIN_USER    = re.compile(r'<Data Name=.(?:TargetUserName|SubjectUserName).>([^<]+)</Data>')
_WIN_PROC    = re.compile(r'<Data Name=.ProcessName.>([^<]+)</Data>')
_WIN_SVC     = re.compile(r'<Data Name=.ServiceName.>([^<]+)</Data>')

# ════════════════════════════════════════════════════════
#  IP UTILITIES
# ════════════════════════════════════════════════════════
_GEO_CACHE: Dict[str, dict] = {}

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except:
        return False

def geolocate_ip(ip: str) -> dict:
    """Query ipinfo.io (free, ~50k req/month). Returns cached result."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    result = {'country': '?', 'city': '?', 'org': '?', 'loc': ''}
    if is_private_ip(ip):
        result = {'country': 'LOCAL', 'city': 'Internal Network', 'org': 'Private', 'loc': ''}
        _GEO_CACHE[ip] = result
        return result
    if not HAS_REQUESTS:
        return result
    try:
        r = _req.get(f'https://ipinfo.io/{ip}/json', timeout=3)
        if r.ok:
            d = r.json()
            result = {
                'country': d.get('country', '?'),
                'city':    d.get('city', '?'),
                'org':     d.get('org', '?'),
                'loc':     d.get('loc', ''),
            }
    except:
        pass
    _GEO_CACHE[ip] = result
    return result

# ════════════════════════════════════════════════════════
#  TIMESTAMP NORMALIZERS
# ════════════════════════════════════════════════════════
_MONTH = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def _parse_syslog_ts(ts_str: str) -> Optional[datetime.datetime]:
    """Parse 'Apr 15 10:23:45' style timestamps."""
    try:
        parts = ts_str.split()
        if len(parts) >= 3:
            mon = _MONTH.get(parts[0], None)
            if mon:
                day = int(parts[1])
                h, m, s = map(int, parts[2].split(':'))
                year = datetime.datetime.now().year
                return datetime.datetime(year, mon, day, h, m, s)
    except:
        pass
    return None

def _parse_any_ts(text: str) -> Optional[datetime.datetime]:
    """Try to extract any timestamp from a string."""
    m = _ISO_TS.search(text)
    if m:
        try:
            return datetime.datetime.fromisoformat(m.group(1).replace('T', ' '))
        except:
            pass
    return None

def _fmt(dt: Optional[datetime.datetime]) -> str:
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ════════════════════════════════════════════════════════
#  EVENT NORMALIZER
# ════════════════════════════════════════════════════════
def _event(ts, src, dst, user, event_desc, proto, status, ev_type, raw='', fname='') -> dict:
    return {
        'ts':    _fmt(ts),
        'src':   src or '—',
        'dst':   dst or '—',
        'user':  user or '—',
        'event': event_desc,
        'proto': proto or '—',
        'status':status,
        'type':  ev_type,
        'raw':   raw[:300],
        'file':  fname,
    }

# ════════════════════════════════════════════════════════
#  FORMAT AUTO-DETECTION
# ════════════════════════════════════════════════════════
def detect_format(content: str, filename: str) -> str:
    fn = filename.lower()
    if fn.endswith('.evtx'):       return 'windows_evtx'
    if fn.endswith('.csv'):        return 'csv'
    snippet = content[:4000]
    # CloudTrail: has "Records" array with eventName
    if '"Records"' in snippet and '"eventName"' in snippet:
        return 'cloudtrail'
    # Azure Monitor
    if ('"operationName"' in snippet or '"callerIpAddress"' in snippet) and '"time"' in snippet:
        return 'azure'
    # JSON array/object
    stripped = snippet.lstrip()
    if stripped.startswith('{') or stripped.startswith('['):
        return 'json'
    # Apache / Nginx CLF
    if _APACHE_CLF.search(snippet):
        return 'apache'
    # Auth.log / syslog
    if _SSH_FAIL.search(snippet) or _SSH_OK.search(snippet) or _UFW_BLOCK.search(snippet):
        return 'auth_log'
    if re.search(r'^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+\S+:', snippet, re.M):
        return 'syslog'
    # CSV check
    if ',' in snippet and snippet.count('\n') > 2:
        return 'csv'
    return 'text'

# ════════════════════════════════════════════════════════
#  PARSERS
# ════════════════════════════════════════════════════════
def _parse_auth_log(lines: List[str], fname: str) -> List[dict]:
    events = []
    for raw in lines[:MAX_EVENTS_PER_FILE]:
        raw = raw.rstrip()
        if not raw:
            continue
        # SSH failed
        m = _SSH_FAIL.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, m.group('ip'), None, m.group('user'),
                f"SSH Failed Login for '{m.group('user')}' from {m.group('ip')}",
                'SSH', 'critical', 'failed_login', raw, fname))
            continue
        # SSH success
        m = _SSH_OK.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, m.group('ip'), None, m.group('user'),
                f"SSH Login Success for '{m.group('user')}' from {m.group('ip')}",
                'SSH', 'info', 'login_ok', raw, fname))
            continue
        # Invalid user
        m = _SSH_INVALID.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, m.group('ip'), None, m.group('user'),
                f"SSH Invalid User '{m.group('user')}' from {m.group('ip')}",
                'SSH', 'warning', 'failed_login', raw, fname))
            continue
        # Sudo
        m = _SUDO.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, None, None, m.group('to_user'),
                f"Sudo Execution by '{m.group('to_user')}': {m.group('cmd')[:80]}",
                'SYS', 'warning', 'privesc', raw, fname))
            continue
        # UFW block
        m = _UFW_BLOCK.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, m.group('src'), m.group('dst'), None,
                f"Firewall Blocked {m.group('proto')} from {m.group('src')} to {m.group('dst')}",
                m.group('proto'), 'warning', 'firewall', raw, fname))
            continue
        # New user
        m = _NEW_USER.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, None, None, m.group('user'),
                f"New User Account Created: '{m.group('user')}'",
                'SYS', 'warning', 'account_create', raw, fname))
            continue
        # SU escalation
        m = _SU_OPEN.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, None, None, m.group('user'),
                f"User Escalation via su to '{m.group('user')}'",
                'SYS', 'warning', 'privesc', raw, fname))
            continue
        # PAM failure
        m = _PAM_FAIL.search(raw)
        if m:
            ts = _parse_syslog_ts(m.group('ts'))
            events.append(_event(ts, None, None, m.group('user'),
                f"PAM Authentication Failure for '{m.group('user')}'",
                'SYS', 'warning', 'failed_login', raw, fname))
            continue
    return events


def _parse_apache_log(lines: List[str], fname: str) -> List[dict]:
    events = []
    for raw in lines[:MAX_EVENTS_PER_FILE]:
        m = _APACHE_CLF.match(raw.strip())
        if not m:
            continue
        ip     = m.group('ip')
        status = int(m.group('status'))
        method = m.group('method')
        path   = m.group('path')[:100]
        try:
            ts_str = m.group('ts')  # '15/Apr/2026:10:23:45 +0000'
            ts = datetime.datetime.strptime(ts_str[:20], '%d/%b/%Y:%H:%M:%S')
        except:
            ts = None

        if status >= 500:
            sev, tp = 'critical', 'server_error'
            desc = f"HTTP {status} Server Error: {method} {path} from {ip}"
        elif status == 403:
            sev, tp = 'warning', 'access_denied'
            desc = f"HTTP 403 Forbidden: {method} {path} from {ip}"
        elif status == 401:
            sev, tp = 'warning', 'failed_login'
            desc = f"HTTP 401 Unauthorized: {method} {path} from {ip}"
        elif status == 404 and method in ('POST', 'PUT'):
            sev, tp = 'warning', 'scan'
            desc = f"Potential Scan — POST/PUT to missing resource: {path} from {ip}"
        else:
            sev, tp = 'info', None
            desc = f"HTTP {status}: {method} {path} from {ip}"

        events.append(_event(ts, ip, None, None, desc, 'HTTP', sev, tp, raw.strip(), fname))
    return events


def _parse_cloudtrail(data: Any, fname: str) -> List[dict]:
    events = []
    records = data.get('Records', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    for rec in records[:MAX_EVENTS_PER_FILE]:
        try:
            ts_str    = rec.get('eventTime', '')
            ts        = datetime.datetime.fromisoformat(ts_str.replace('Z','')) if ts_str else None
            ip        = rec.get('sourceIPAddress', '—')
            user_id   = rec.get('userIdentity', {})
            user      = user_id.get('userName') or user_id.get('arn', '—')
            ev_name   = rec.get('eventName', '—')
            region    = rec.get('awsRegion', '')
            error     = rec.get('errorCode')
            error_msg = rec.get('errorMessage', '')

            if error:
                sev, tp = 'critical', 'api_error'
                desc = f"AWS {ev_name} FAILED [{error}] by {user} from {ip}"
            elif ev_name in ('DeleteUser','DeleteRole','DetachUserPolicy','DeleteBucket'):
                sev, tp = 'critical', 'iam_change'
                desc = f"AWS Destructive Action: {ev_name} by {user} from {ip}"
            elif ev_name in ('CreateUser','AttachUserPolicy','PutUserPolicy','CreateAccessKey'):
                sev, tp = 'warning', 'iam_change'
                desc = f"AWS IAM Change: {ev_name} by {user} from {ip}"
            elif ev_name == 'ConsoleLogin':
                result = (rec.get('responseElements') or {}).get('ConsoleLogin','')
                if result == 'Failure':
                    sev, tp = 'critical', 'failed_login'
                    desc = f"AWS Console Login FAILED by {user} from {ip}"
                else:
                    sev, tp = 'info', 'login_ok'
                    desc = f"AWS Console Login by {user} from {ip}"
            elif ev_name.startswith('Describe') or ev_name.startswith('List') or ev_name.startswith('Get'):
                sev, tp = 'info', None
                desc = f"AWS Read Action: {ev_name} by {user}"
            else:
                sev, tp = 'info', None
                desc = f"AWS {ev_name} by {user} from {ip} [{region}]"

            events.append(_event(ts, ip if ip != '—' else None, None, user, desc,
                                 'HTTPS', sev, tp, json.dumps(rec)[:300], fname))
        except Exception:
            continue
    return events


def _parse_azure(data: Any, fname: str) -> List[dict]:
    events = []
    records = data if isinstance(data, list) else data.get('records', data.get('value', []))
    for rec in records[:MAX_EVENTS_PER_FILE]:
        try:
            ts_str  = rec.get('time', rec.get('timestamp', ''))
            ts      = datetime.datetime.fromisoformat(ts_str[:19].replace('T',' ')) if ts_str else None
            ip      = rec.get('callerIpAddress', '—')
            op      = rec.get('operationName', '—')
            result  = rec.get('resultType', rec.get('result', ''))
            ident   = rec.get('identity', {})
            user    = ''
            if isinstance(ident, dict):
                claims = ident.get('claims', {})
                user   = claims.get('name', claims.get('upn', ident.get('displayName', '—')))

            if result in ('Failure','Failed','forbidden','Unauthorized'):
                sev, tp = 'critical', 'api_error'
                desc = f"Azure FAILED: {op} by {user} from {ip}"
            elif 'write' in op.lower() or 'delete' in op.lower():
                sev, tp = 'warning', 'iam_change'
                desc = f"Azure Write/Delete: {op} by {user}"
            elif 'role' in op.lower() or 'policy' in op.lower() or 'permission' in op.lower():
                sev, tp = 'critical', 'privesc'
                desc = f"Azure Permission Change: {op} by {user}"
            else:
                sev, tp = 'info', None
                desc = f"Azure: {op} by {user}"

            events.append(_event(ts, ip if ip!='—' else None, None, user, desc,
                                 'HTTPS', sev, tp, json.dumps(rec)[:300], fname))
        except Exception:
            continue
    return events


def _parse_csv_log(content: str, fname: str) -> List[dict]:
    events = []
    try:
        reader = csv.DictReader(io.StringIO(content))
        # Flexible column mapping
        field_map = {
            'timestamp': ['timestamp','time','ts','datetime','date_time','log_time','event_time'],
            'src':       ['source_ip','src_ip','src','source','ip','sourceip','client_ip','remote_addr','remote_ip'],
            'dst':       ['destination_ip','dst_ip','dst','destination','dest_ip'],
            'user':      ['user','username','user_name','account','identity'],
            'event':     ['event','event_type','message','msg','description','action','log_message','details'],
            'status':    ['status','severity','level','type','result'],
            'proto':     ['protocol','proto','port_protocol'],
        }
        headers  = reader.fieldnames or []
        h_lower  = {h.lower().strip(): h for h in headers}

        def find_col(keys):
            for k in keys:
                if k in h_lower: return h_lower[k]
            return None

        col = {k: find_col(v) for k, v in field_map.items()}

        for i, row in enumerate(reader):
            if i >= MAX_EVENTS_PER_FILE:
                break
            ts_raw = row.get(col['timestamp'], '') if col['timestamp'] else ''
            ts     = _parse_any_ts(ts_raw)
            src    = row.get(col['src'], '').strip()  if col['src']    else ''
            dst    = row.get(col['dst'], '').strip()  if col['dst']    else ''
            user   = row.get(col['user'], '').strip() if col['user']   else ''
            desc   = row.get(col['event'], str(row)).strip()[:200] if col['event'] else str(row)[:200]
            status_raw = (row.get(col['status'], '') if col['status'] else '').lower()
            proto  = row.get(col['proto'], '').strip() if col['proto'] else '—'

            if any(w in status_raw for w in ('critical','crit','high','alert','fatal')):
                sev, tp = 'critical', 'alert'
            elif any(w in status_raw for w in ('warn','medium','suspicious','error','fail')):
                sev, tp = 'warning', 'alert'
            elif _FAIL_KW.search(desc):
                sev, tp = 'warning', None
            else:
                sev, tp = 'info', None

            events.append(_event(ts, src or None, dst or None, user or None,
                                 desc, proto, sev, tp, str(row)[:300], fname))
    except Exception as e:
        print(f'[analyzer] CSV parse error: {e}')
    return events


def _parse_json_log(data: Any, fname: str) -> List[dict]:
    events = []
    entries = data if isinstance(data, list) else [data]
    for i, entry in enumerate(entries[:MAX_EVENTS_PER_FILE]):
        if not isinstance(entry, dict):
            continue
        raw  = json.dumps(entry)
        ts   = _parse_any_ts(raw)
        ips  = _IP_ANY.findall(raw)
        src  = ips[0] if ips else None
        desc = (entry.get('message') or entry.get('msg') or
                entry.get('event') or entry.get('description') or
                entry.get('action') or raw[:120])
        user = entry.get('user') or entry.get('username') or entry.get('identity') or '—'
        sev_raw = str(entry.get('severity') or entry.get('level') or entry.get('status') or '').lower()

        if any(w in sev_raw for w in ('crit','high','fatal','alert')):
            sev, tp = 'critical', 'alert'
        elif any(w in sev_raw for w in ('warn','medium','error','fail')):
            sev, tp = 'warning', None
        elif _FAIL_KW.search(str(desc)):
            sev, tp = 'warning', None
        else:
            sev, tp = 'info', None

        events.append(_event(ts, src, None, str(user),
                             str(desc)[:200], '—', sev, tp, raw[:300], fname))
    return events


def _parse_text_log(lines: List[str], fname: str) -> List[dict]:
    """Heuristic fallback parser for plain text logs."""
    events = []
    for raw in lines[:MAX_EVENTS_PER_FILE]:
        raw = raw.rstrip()
        if not raw or len(raw) < 10:
            continue
        ts   = _parse_any_ts(raw)
        ips  = _IP_ANY.findall(raw)
        src  = ips[0] if ips else None

        # Classify by keywords
        if _FAIL_KW.search(raw) and any(w in raw.lower() for w in ('crit','fatal','attack','exploit','ransomw','malware')):
            sev, tp = 'critical', 'alert'
        elif _FAIL_KW.search(raw):
            sev, tp = 'warning', None
        elif _OK_KW.search(raw):
            sev, tp = 'info', None
        else:
            sev, tp = 'info', None

        events.append(_event(ts, src, None, None, raw[:200], '—', sev, tp, raw, fname))
    return events


def _parse_windows_xml(xml_text: str, fname: str) -> List[dict]:
    """Parse wevtutil-style XML blocks."""
    events = []
    # Split by <Event> tags
    blocks = re.split(r'<Event\s', xml_text)
    for block in blocks[1:MAX_EVENTS_PER_FILE+1]:
        try:
            evid_m = _WIN_EVID.search(block)
            if not evid_m:
                continue
            evid = int(evid_m.group(1))
            ts_m = _WIN_TIME.search(block)
            ts   = None
            if ts_m:
                try:
                    ts = datetime.datetime.fromisoformat(ts_m.group(1)[:19].replace('T',' '))
                except:
                    pass
            ip_m   = _WIN_IP.search(block)
            user_m = _WIN_USER.search(block)
            proc_m = _WIN_PROC.search(block)
            svc_m  = _WIN_SVC.search(block)

            ip   = ip_m.group(1).strip()   if ip_m   else None
            user = user_m.group(1).strip() if user_m else None
            proc = proc_m.group(1).strip() if proc_m else None
            svc  = svc_m.group(1).strip()  if svc_m  else None

            # Filter out system users
            if user in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                user = None

            if ip in ('-', '::1', '0.0.0.0'):
                ip = None

            info = WIN_EVENT_MAP.get(evid, (f'Windows Event {evid}', 'info', None))
            base_desc, sev, tp = info

            extra = ''
            if proc: extra += f' via {os.path.basename(proc)}'
            if svc:  extra += f' service={svc}'

            desc = f"{base_desc}{extra}"
            if user: desc += f" [user: {user}]"
            if ip:   desc += f" from {ip}"

            events.append(_event(ts, ip, None, user, desc, 'WIN', sev, tp,
                                 f'EventID={evid}', fname))
        except Exception:
            continue
    return events


def _read_live_windows_event_log(log_name: str = 'Security', count: int = 200) -> List[dict]:
    """Read live Windows Event Log using wevtutil (Windows only)."""
    try:
        cmd = ['wevtutil', 'qe', log_name, f'/count:{count}', '/rd:true', '/format:xml']
        r   = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout:
            return _parse_windows_xml(r.stdout, f'LiveWinLog:{log_name}')
    except Exception as e:
        print(f'[analyzer] wevtutil error: {e}')
    return []

# ════════════════════════════════════════════════════════
#  MAIN PARSE DISPATCHER
# ════════════════════════════════════════════════════════
def parse_log_file(content: str, filename: str) -> Tuple[List[dict], str]:
    """Detect format and parse. Returns (events, format_name)."""
    fmt = detect_format(content, filename)
    lines = content.splitlines()

    if fmt == 'auth_log':
        return _parse_auth_log(lines, filename), 'Linux auth.log / syslog'
    if fmt == 'syslog':
        return _parse_auth_log(lines, filename), 'Generic syslog'
    if fmt == 'apache':
        return _parse_apache_log(lines, filename), 'Apache / Nginx access log'
    if fmt == 'cloudtrail':
        try:
            data = json.loads(content)
            return _parse_cloudtrail(data, filename), 'AWS CloudTrail'
        except:
            return [], 'AWS CloudTrail (parse failed)'
    if fmt == 'azure':
        try:
            data = json.loads(content)
            return _parse_azure(data, filename), 'Azure Monitor'
        except:
            return [], 'Azure Monitor (parse failed)'
    if fmt == 'json':
        try:
            data = json.loads(content)
            return _parse_json_log(data, filename), 'JSON log'
        except:
            pass
    if fmt == 'csv':
        return _parse_csv_log(content, filename), 'CSV log'
    if fmt == 'windows_evtx':
        # Try using python-evtx if available, else attempt XML parse
        return _parse_windows_xml(content, filename), 'Windows EVTX'

    return _parse_text_log(lines, filename), 'Plain text log'

# ════════════════════════════════════════════════════════
#  REAL THREAT DETECTION ENGINE
# ════════════════════════════════════════════════════════
def detect_threats(events: List[dict]) -> List[dict]:
    """Apply rule-based threat detection to a list of normalized events."""
    alerts = []
    now    = datetime.datetime.now()

    # Group events
    by_src:         defaultdict[str, List[dict]] = defaultdict(list)
    by_type:        defaultdict[str, List[dict]] = defaultdict(list)
    failed_per_src: defaultdict[str, List[datetime.datetime]] = defaultdict(list)
    users_per_src:  defaultdict[str, set] = defaultdict(set)
    dst_per_src:    defaultdict[str, set] = defaultdict(set)

    for ev in events:
        src = ev['src']
        if src and src != '—':
            by_src[src].append(ev)
            if ev['type'] == 'failed_login':
                try:
                    ts = datetime.datetime.strptime(ev['ts'], '%Y-%m-%d %H:%M:%S')
                    failed_per_src[src].append(ts)
                except:
                    pass
                if ev['user'] and ev['user'] != '—':
                    users_per_src[src].add(ev['user'])
            if ev['dst'] and ev['dst'] != '—':
                dst_per_src[src].add(ev['dst'])
        if ev['type']:
            by_type[ev['type']].append(ev)

    # ── Rule 1: Brute-Force Detection ──────────────────
    for src, timestamps in failed_per_src.items():
        timestamps.sort()
        window_count = 0
        for i, ts in enumerate(timestamps):
            window = [t for t in timestamps if (ts - t).total_seconds() <= BRUTE_WINDOW_SEC and t <= ts]
            if len(window) >= BRUTE_THRESHOLD:
                window_count = len(window)
                break
        if window_count >= BRUTE_THRESHOLD:
            geo = geolocate_ip(src) if not is_private_ip(src) else None
            location = f"{geo['city']}, {geo['country']}" if geo else 'unknown'
            alerts.append({
                'rule':     'Brute-Force Attack',
                'mitre':    'T1110 – Brute Force',
                'severity': 'critical',
                'src':      src,
                'detail':   f"{window_count} failed logins from {src} within {BRUTE_WINDOW_SEC//60} min (location: {location})",
                'count':    window_count,
            })

    # ── Rule 2: Credential Stuffing (many users, same IP) ──
    for src, users in users_per_src.items():
        if len(users) >= 3:
            alerts.append({
                'rule':     'Credential Stuffing',
                'mitre':    'T1078 – Valid Accounts',
                'severity': 'critical',
                'src':      src,
                'detail':   f"{src} attempted {len(users)} different usernames: {', '.join(list(users)[:5])}",
                'count':    len(users),
            })

    # ── Rule 3: Privilege Escalation ──────────────────
    privesc_events = by_type.get('privesc', [])
    if privesc_events:
        for ev in privesc_events:
            alerts.append({
                'rule':     'Privilege Escalation',
                'mitre':    'T1548 – Abuse Elevation Control',
                'severity': 'critical',
                'src':      ev['src'],
                'detail':   ev['event'],
                'count':    1,
            })

    # ── Rule 4: Account Manipulation ─────────────────
    for ev in by_type.get('account_create', []):
        alerts.append({
            'rule':     'Suspicious Account Creation',
            'mitre':    'T1136 – Create Account',
            'severity': 'warning',
            'src':      ev['src'],
            'detail':   ev['event'],
            'count':    1,
        })

    # ── Rule 5: Audit Log Tampered ────────────────────
    for ev in by_type.get('tamper', []):
        alerts.append({
            'rule':     'Audit Log Cleared',
            'mitre':    'T1070 – Indicator Removal',
            'severity': 'critical',
            'src':      ev['src'],
            'detail':   ev['event'],
            'count':    1,
        })

    # ── Rule 6: Lateral Movement ─────────────────────
    for src, dsts in dst_per_src.items():
        internal_dsts = [d for d in dsts if is_private_ip(d) if d]
        if len(internal_dsts) >= 4:
            alerts.append({
                'rule':     'Lateral Movement',
                'mitre':    'T1021 – Remote Services',
                'severity': 'critical',
                'src':      src,
                'detail':   f"{src} connected to {len(internal_dsts)} internal hosts",
                'count':    len(internal_dsts),
            })

    # ── Rule 7: HTTP Brute-Force (401/403 flood) ──────
    http_fails = [e for e in events if e['type'] == 'failed_login' and e['proto'] == 'HTTP']
    http_by_ip = Counter(e['src'] for e in http_fails)
    for ip, cnt in http_by_ip.items():
        if cnt >= BRUTE_THRESHOLD:
            alerts.append({
                'rule':     'HTTP Authentication Brute-Force',
                'mitre':    'T1110.001 – Password Guessing',
                'severity': 'critical',
                'src':      ip,
                'detail':   f"{cnt} HTTP auth failures from {ip}",
                'count':    cnt,
            })

    # ── Rule 8: IAM / Permission Changes ─────────────
    iam_events = by_type.get('iam_change', []) + by_type.get('iam_change', [])
    if len(iam_events) >= 3:
        ips = list({e['src'] for e in iam_events if e['src'] != '—'})
        alerts.append({
            'rule':     'Excessive IAM/Permission Changes',
            'mitre':    'T1098 – Account Manipulation',
            'severity': 'warning',
            'src':      ips[0] if ips else '—',
            'detail':   f"{len(iam_events)} IAM/permission changes detected",
            'count':    len(iam_events),
        })

    # ── Rule 9: Persistence (new services/tasks) ──────
    persist_evs = by_type.get('persistence', [])
    for ev in persist_evs:
        alerts.append({
            'rule':     'Persistence Mechanism Detected',
            'mitre':    'T1543 – Create or Modify System Process',
            'severity': 'warning',
            'src':      ev['src'],
            'detail':   ev['event'],
            'count':    1,
        })

    # ── Rule 10: Foreign IP Access ────────────────────
    foreign_ips = set()
    for ev in events:
        src = ev['src']
        if src and src != '—' and not is_private_ip(src):
            foreign_ips.add(src)

    if foreign_ips:
        # Batch geolocate (limit to 10 to avoid rate-limiting)
        suspicious = []
        for ip in list(foreign_ips)[:10]:
            geo = geolocate_ip(ip)
            if geo.get('country') in SUSPICIOUS_COUNTRIES:
                suspicious.append(f"{ip} ({geo['country']}, {geo['city']})")
        if suspicious:
            alerts.append({
                'rule':     'Access from Suspicious Countries',
                'mitre':    'T1133 – External Remote Services',
                'severity': 'critical',
                'src':      suspicious[0].split()[0],
                'detail':   f"Connections from high-risk countries: {'; '.join(suspicious[:5])}",
                'count':    len(suspicious),
            })

    return alerts

# ════════════════════════════════════════════════════════
#  REAL METRICS CALCULATION
# ════════════════════════════════════════════════════════
def calculate_metrics(events: List[dict], alerts: List[dict]) -> dict:
    total    = len(events)
    critical = sum(1 for e in events if e['status'] == 'critical')
    warning  = sum(1 for e in events if e['status'] == 'warning')
    info     = sum(1 for e in events if e['status'] == 'info')

    # Risk score: weighted formula
    risk = min(99, int(
        critical * 3.0 +
        warning  * 1.0 +
        len([a for a in alerts if a['severity'] == 'critical']) * 8 +
        len([a for a in alerts if a['severity'] == 'warning'])  * 3
    ) / max(total, 1) * 60)
    risk = max(risk, min(99, len(alerts) * 4))

    # MTTP: average minutes between consecutive critical events
    crit_ts = []
    for e in events:
        if e['status'] == 'critical':
            try:
                crit_ts.append(datetime.datetime.strptime(e['ts'], '%Y-%m-%d %H:%M:%S'))
            except:
                pass
    mttp = 0.0
    if len(crit_ts) >= 2:
        crit_ts.sort()
        gaps = [(crit_ts[i+1]-crit_ts[i]).total_seconds()/60 for i in range(len(crit_ts)-1)]
        mttp = round(sum(gaps)/len(gaps), 1)

    # Top source IPs
    src_counter = Counter(e['src'] for e in events if e['src'] and e['src'] != '—')
    top_ips     = [{'ip': ip, 'count': cnt} for ip, cnt in src_counter.most_common(10)]

    # Threat type distribution (from events)
    type_counter = Counter(e['type'] for e in events if e['type'])
    threat_dist  = dict(type_counter.most_common(8))

    # Timeline buckets (hourly)
    hourly: defaultdict[str, int] = defaultdict(int)
    for e in events:
        try:
            dt  = datetime.datetime.strptime(e['ts'], '%Y-%m-%d %H:%M:%S')
            key = dt.strftime('%Y-%m-%d %H:00')
            hourly[key] += 1
        except:
            pass
    timeline = [{'label': k, 'count': v} for k, v in sorted(hourly.items())[-24:]]

    # Unique IPs, users
    unique_ips   = len(set(e['src'] for e in events if e['src'] and e['src'] != '—'))
    unique_users = len(set(e['user'] for e in events if e['user'] and e['user'] != '—'))

    return {
        'total_events':  total,
        'active_threats':len([a for a in alerts if a['severity'] == 'critical']),
        'logs_analyzed': total,
        'critical_count':critical,
        'warning_count': warning,
        'info_count':    info,
        'risk_score':    risk,
        'risk_level':    'High' if risk>=70 else 'Medium' if risk>=40 else 'Low',
        'mttp':          mttp,
        'unique_ips':    unique_ips,
        'unique_users':  unique_users,
        'top_ips':       top_ips,
        'threat_dist':   threat_dist,
        'timeline':      timeline,
        'alerts_count':  len(alerts),
    }

# ════════════════════════════════════════════════════════
#  MULTI-FILE CORRELATION
# ════════════════════════════════════════════════════════
def correlate_files(all_events_by_file: Dict[str, List[dict]]) -> List[dict]:
    """Find IPs that appear across multiple files (cross-file correlation)."""
    if len(all_events_by_file) < 2:
        return []
    ip_files: defaultdict[str, set] = defaultdict(set)
    for fname, events in all_events_by_file.items():
        for ev in events:
            if ev['src'] and ev['src'] != '—':
                ip_files[ev['src']].add(fname)

    corr = []
    for ip, files in ip_files.items():
        if len(files) >= 2:
            corr.append({
                'ip':    ip,
                'files': list(files),
                'count': len(files),
                'private': is_private_ip(ip),
            })
    corr.sort(key=lambda x: x['count'], reverse=True)
    return corr[:20]

# ════════════════════════════════════════════════════════
#  CSV REPORT
# ════════════════════════════════════════════════════════
def generate_csv_report(events: List[dict], alerts: List[dict], metrics: dict) -> str:
    out = io.StringIO()

    # Section: summary
    out.write('CFIP Analysis Report\n')
    out.write(f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
    out.write('=== SUMMARY ===\n')
    for k, v in metrics.items():
        if not isinstance(v, (list, dict)):
            out.write(f'{k},{v}\n')

    out.write('\n=== ALERTS ===\n')
    alert_writer = csv.DictWriter(out, fieldnames=['rule','mitre','severity','src','detail','count'])
    alert_writer.writeheader()
    alert_writer.writerows(alerts)

    out.write('\n=== EVENTS ===\n')
    ev_writer = csv.DictWriter(out, fieldnames=['ts','src','dst','user','event','proto','status','type','file'])
    ev_writer.writeheader()
    for ev in events:
        ev_writer.writerow({k: ev.get(k,'') for k in ['ts','src','dst','user','event','proto','status','type','file']})

    return out.getvalue()

# ════════════════════════════════════════════════════════
#  PDF REPORT
# ════════════════════════════════════════════════════════
def generate_pdf_report(events: List[dict], alerts: List[dict], metrics: dict) -> Optional[bytes]:
    if not HAS_FPDF:
        return None
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_fill_color(37, 99, 235)
        pdf.rect(0, 0, 210, 28, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 18)
        pdf.set_xy(10, 8)
        pdf.cell(0, 12, 'CFIP - Cyber Forensic Intelligence Platform', ln=True)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_xy(10, 20)
        pdf.cell(0, 6, f'Analysis Report  |  {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        pdf.set_text_color(0, 0, 0)
        pdf.ln(18)

        # Risk badge
        risk = metrics.get('risk_score', 0)
        if risk >= 70:
            pdf.set_fill_color(220, 38, 38)
        elif risk >= 40:
            pdf.set_fill_color(202, 138, 4)
        else:
            pdf.set_fill_color(22, 163, 74)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(40, 10, f"RISK: {metrics.get('risk_level','?')} ({risk})", fill=True, ln=False, align='C')
        pdf.set_text_color(0, 0, 0)
        pdf.ln(14)

        # Summary metrics
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, 'Executive Summary', ln=True)
        pdf.set_font('Helvetica', '', 10)
        summary_items = [
            ('Total Events Analyzed', metrics.get('total_events', 0)),
            ('Critical Events',       metrics.get('critical_count', 0)),
            ('Warning Events',        metrics.get('warning_count', 0)),
            ('Active Threats',        metrics.get('active_threats', 0)),
            ('Unique Source IPs',     metrics.get('unique_ips', 0)),
            ('Unique Users',          metrics.get('unique_users', 0)),
            ('Mean Time to Preempt',  f"{metrics.get('mttp', 0)} min"),
        ]
        for label, val in summary_items:
            pdf.cell(80, 7, f'  {label}:', border='B')
            pdf.cell(0, 7, str(val), border='B', ln=True)
        pdf.ln(6)

        # Alerts
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, f'Detected Threats ({len(alerts)})', ln=True)
        if alerts:
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_fill_color(241, 245, 249)
            pdf.cell(45, 7, 'Rule', fill=True, border=1)
            pdf.cell(30, 7, 'Severity', fill=True, border=1)
            pdf.cell(30, 7, 'Source IP', fill=True, border=1)
            pdf.cell(0,  7, 'Detail', fill=True, border=1, ln=True)
            pdf.set_font('Helvetica', '', 8)
            for alert in alerts[:30]:
                sev = alert['severity'].upper()
                if sev == 'CRITICAL':
                    pdf.set_text_color(220, 38, 38)
                elif sev == 'WARNING':
                    pdf.set_text_color(202, 138, 4)
                else:
                    pdf.set_text_color(37, 99, 235)
                pdf.cell(45, 6, alert.get('rule','')[:30], border=1)
                pdf.cell(30, 6, sev, border=1)
                pdf.cell(30, 6, str(alert.get('src','—'))[:18], border=1)
                pdf.set_text_color(0,0,0)
                pdf.cell(0, 6, str(alert.get('detail',''))[:70], border=1, ln=True)
        pdf.ln(6)

        # Top IPs
        top_ips = metrics.get('top_ips', [])
        if top_ips:
            pdf.set_font('Helvetica', 'B', 13)
            pdf.cell(0, 8, 'Top Source IPs', ln=True)
            pdf.set_font('Helvetica', '', 10)
            for item in top_ips[:8]:
                pdf.cell(50, 6, f"  {item['ip']}")
                pdf.cell(0, 6, f"{item['count']} events", ln=True)
            pdf.ln(4)

        # Recent events table
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, f'Event Log (first 50 of {len(events)})', ln=True)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(38, 6, 'Timestamp', fill=True, border=1)
        pdf.cell(28, 6, 'Source IP', fill=True, border=1)
        pdf.cell(20, 6, 'Protocol', fill=True, border=1)
        pdf.cell(16, 6, 'Status', fill=True, border=1)
        pdf.cell(0,  6, 'Event', fill=True, border=1, ln=True)
        pdf.set_font('Helvetica', '', 7)
        for ev in events[:50]:
            sev = ev.get('status','')
            if sev == 'critical':
                pdf.set_text_color(220, 38, 38)
            elif sev == 'warning':
                pdf.set_text_color(202, 138, 4)
            else:
                pdf.set_text_color(37, 99, 235)
            pdf.cell(38, 5, str(ev.get('ts',''))[:19], border=1)
            pdf.cell(28, 5, str(ev.get('src',''))[:16], border=1)
            pdf.cell(20, 5, str(ev.get('proto',''))[:8], border=1)
            pdf.cell(16, 5, sev.upper()[:4], border=1)
            pdf.set_text_color(0,0,0)
            pdf.cell(0, 5, str(ev.get('event',''))[:65], border=1, ln=True)

        # Recommendations
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, 'Security Recommendations', ln=True)
        pdf.set_font('Helvetica', '', 10)
        recs = _build_recommendations(alerts, metrics)
        for i, rec in enumerate(recs, 1):
            pdf.multi_cell(0, 6, f'{i}. {rec}')
            pdf.ln(1)

        return bytes(pdf.output())
    except Exception as e:
        print(f'[analyzer] PDF error: {e}')
        return None


def _build_recommendations(alerts: List[dict], metrics: dict) -> List[str]:
    recs = []
    rules = {a['rule'] for a in alerts}
    risk  = metrics.get('risk_score', 0)

    if 'Brute-Force Attack' in rules or 'HTTP Authentication Brute-Force' in rules:
        recs.append('Implement account lockout after 5 failed attempts and enable MFA on all accounts.')
        recs.append('Block offending IPs at the firewall/WAF level and enable geofencing for sensitive services.')
    if 'Credential Stuffing' in rules:
        recs.append('Deploy credential stuffing protection (CAPTCHA, IP rate-limiting, breach password lists).')
    if 'Privilege Escalation' in rules:
        recs.append('Audit sudo/su rules and enforce principle of least privilege. Review admin group memberships.')
    if 'Lateral Movement' in rules:
        recs.append('Implement network segmentation and Zero-Trust architecture to limit lateral movement.')
    if 'Audit Log Cleared' in rules:
        recs.append('Enable immutable logging (WORM storage) and alert on any log-clearing events immediately.')
    if 'Persistence Mechanism Detected' in rules:
        recs.append('Audit all new services and scheduled tasks. Use application whitelisting.')
    if 'Access from Suspicious Countries' in rules:
        recs.append('Implement geolocation blocking for high-risk countries at the perimeter firewall.')
    if risk >= 70:
        recs.append('CRITICAL: Initiate incident response procedure immediately. Consider isolating affected hosts.')
    if not recs:
        recs.append('Maintain current security posture. Continue regular log review and patch management.')
    return recs
