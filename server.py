"""
CFIP – Cyber Forensic Intelligence Platform
Real-Data Flask Backend  |  server.py

Modes:
  1. Simulation  – background synthetic events when no file uploaded
  2. Real-Data   – actual log parsing via analyzer.py on file upload

Run:  python server.py
URL:  http://127.0.0.1:5000
"""
from __future__ import annotations
import os, json, uuid, time, random, datetime, threading, collections, io
from flask import Flask, Response, jsonify, request, send_from_directory, session, redirect, url_for
from flask_cors import CORS
import analyzer as az

# ─── Setup ────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB
app.secret_key = 'cfip-secret-key-change-in-production-2025'

# ─── Demo user store (replace with DB in production) ──────────
_USERS = {
    'admin':   {'password': 'admin123',  'name': 'Admin',   'role': 'SOC Admin'},
    'kartik':  {'password': 'cfip2025',  'name': 'Kartik',  'role': 'SOC Analyst'},
    'analyst': {'password': 'cfip2025',  'name': 'Analyst', 'role': 'SOC Analyst'},
}

ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv', '.json', '.evtx', '.pcap'}

# ════════════════════════════════════════════════════════
#  SHARED STATE
# ════════════════════════════════════════════════════════
_lock  = threading.Lock()
_state = {
    'running':       True,
    'speed':         1.5,
    'mode':          'simulation',   # 'simulation' | 'real'
    'active_threats':7,
    'logs_analyzed': 0,
    'risk_score':    45.0,
    'mttp':          4.2,
    'failed_logins': collections.deque(maxlen=50),
    'log_buffer':    collections.deque(maxlen=500),
    'timeline_buffer':collections.deque(maxlen=50),
    # Real-data slots (updated on file upload)
    'real_events':   [],
    'real_alerts':   [],
    'real_metrics':  {},
    'real_files':    {},            # fname -> events (for correlation)
    'analysis_jobs': {},            # job_id -> result dict
}

# ════════════════════════════════════════════════════════
#  SIMULATION ENGINE  (fallback / background)
# ════════════════════════════════════════════════════════
_SIM_IPS = [
    '192.168.1.105','10.0.0.88','172.16.0.42',
    '198.51.100.3','203.0.113.77','45.33.32.156',
    '91.108.4.1','185.220.101.3','10.0.0.50',
]
_SIM_EVENTS = {
    'critical': [
        ('SSH Brute-force Attack',        'SSH',  'failed_login'),
        ('Reverse Shell Detected',        'TCP',  'malware'),
        ('GeoIP Anomaly – Foreign Source','TCP',  'geoip'),
        ('Lateral Movement via RDP',      'RDP',  'lateral'),
        ('C2 Beacon on Port 4444',        'TCP',  'c2'),
        ('Privilege Escalation via Sudo', 'SYS',  'privesc'),
        ('Ransomware Signature Found',    'N/A',  'malware'),
    ],
    'warning': [
        ('Multiple Failed Logins',        'SSH',  'failed_login'),
        ('Port Scan Detected',            'TCP',  'scan'),
        ('Unusual DNS Volume',            'UDP',  'dns'),
        ('Outbound Traffic Spike',        'TCP',  'exfil'),
        ('API Rate Limit Exceeded',       'HTTPS','api'),
        ('ARP Broadcast Flood',           'ARP',  'dos'),
    ],
    'info': [
        ('User Auth Success',             'SSH',  None),
        ('VPN Tunnel Established',        'UDP',  None),
        ('File Transfer Completed',       'SMB',  None),
        ('Certificate Renewed',           'TLS',  None),
        ('Backup Job Started',            'SMB',  None),
    ],
}
_KC = [
    ('Reconnaissance', 'warning'), ('Weaponization','warning'),
    ('Delivery',       'critical'), ('Exploitation', 'critical'),
    ('Installation',   'critical'), ('C2 Callback',  'critical'),
    ('Exfiltration',   'critical'),
]

def _sim_worker():
    kc_idx = 0
    tick   = 0
    while True:
        with _lock:
            running = _state['running']
            speed   = _state['speed']
        if not running:
            time.sleep(0.4)
            continue

        tick += 1
        now = datetime.datetime.now()
        ts  = now.strftime('%Y-%m-%d %H:%M:%S')
        r   = random.random()
        sev = 'critical' if r < 0.22 else 'warning' if r < 0.50 else 'info'
        ev, proto, ev_type = random.choice(_SIM_EVENTS[sev])
        src = random.choice(_SIM_IPS)
        dst = random.choice(['10.0.0.1','8.8.8.8','10.0.0.5','1.1.1.1'])

        entry = {
            'ts': ts, 'src': src, 'dst': dst,
            'user':  random.choice(['admin','root','webserver','guest']) if random.random()<0.4 else None,
            'event': ev, 'proto': proto, 'status': sev, 'type': ev_type,
            'bytes': f'{random.randint(100,999)} KB', 'file': '[simulation]',
        }

        with _lock:
            _state['log_buffer'].append(entry)
            _state['logs_analyzed'] += 1
            if ev_type == 'failed_login':
                _state['failed_logins'].append(now.timestamp())
            recent_fails = sum(1 for t in _state['failed_logins'] if now.timestamp()-t < 60)
            base  = _state['risk_score']
            delta = 3 if sev=='critical' else 1 if sev=='warning' else -0.5
            _state['risk_score'] = round(max(10, min(99, base + delta*random.uniform(0.3,1.1))), 1)
            if sev == 'critical':
                _state['active_threats'] = min(50, _state['active_threats']+1)
            elif sev == 'info' and random.random()<0.25:
                _state['active_threats'] = max(0, _state['active_threats']-1)
            _state['mttp'] = round(max(1.0, min(15.0, _state['mttp']+random.uniform(-0.3,0.5))), 1)

        if tick % 8 == 0:
            phase, phase_sev = _KC[kc_idx % len(_KC)]
            kc_idx += 1
            with _lock:
                _state['timeline_buffer'].append({
                    'ts': ts, 'phase': phase,
                    'detail': f'{ev} from {src}', 'status': phase_sev,
                })

        time.sleep(speed + random.uniform(-0.2, 0.5))

_sim = threading.Thread(target=_sim_worker, daemon=True)
_sim.start()

# ════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════
def _allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS

def _safe_read(filepath: str, max_mb: int = 50) -> str:
    """Read file with size guard. Returns text content."""
    size = os.path.getsize(filepath)
    limit = max_mb * 1024 * 1024
    with open(filepath, 'r', errors='replace') as f:
        if size > limit:
            return f.read(limit)
        return f.read()

def _inject_real_events_to_stream(events: list):
    """Push real parsed events into the SSE buffer."""
    for ev in events[-200:]:             # last 200 real events
        buf_entry = {
            'ts':     ev.get('ts',''),
            'src':    ev.get('src','—'),
            'dst':    ev.get('dst','—'),
            'user':   ev.get('user'),
            'event':  ev.get('event',''),
            'proto':  ev.get('proto','—'),
            'status': ev.get('status','info'),
            'type':   ev.get('type'),
            'bytes':  '—',
            'file':   ev.get('file','uploaded'),
        }
        with _lock:
            _state['log_buffer'].append(buf_entry)

# ════════════════════════════════════════════════════════
#  FLASK ROUTES
# ════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Redirect root to login; go to dashboard if already logged in."""
    if session.get('logged_in'):
        return send_from_directory(BASE_DIR, 'index.html')
    return redirect('/login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/login.html')
    return send_from_directory(BASE_DIR, 'index.html')

# ── Auth endpoints ──────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    body     = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip().lower()
    password = body.get('password', '')

    user = _USERS.get(username)
    if user and user['password'] == password:
        session['logged_in'] = True
        session['username']  = username
        session['name']      = user['name']
        session['role']      = user['role']
        return jsonify({
            'success': True,
            'name':    user['name'],
            'role':    user['role'],
        })
    return jsonify({'success': False, 'error': 'Invalid username or password.'}), 401

@app.route('/api/signup', methods=['POST'])
def api_signup():
    body     = request.get_json(silent=True) or {}
    name     = (body.get('name') or '').strip()
    username = (body.get('username') or '').strip().lower()
    email    = (body.get('email') or '').strip()
    password = body.get('password', '')

    if not all([name, username, email, password]):
        return jsonify({'success': False, 'error': 'All fields are required.'}), 400
    if not __import__('re').match(r'^[a-zA-Z0-9_]{3,}$', username):
        return jsonify({'success': False, 'error': 'Username must be 3+ chars: letters, numbers, underscores.'}), 400
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters.'}), 400
    if username in _USERS:
        return jsonify({'success': False, 'error': 'Username already taken.'}), 409

    # Register new user
    _USERS[username] = {'password': password, 'name': name, 'role': 'SOC Analyst', 'email': email}

    # Auto-login
    session['logged_in'] = True
    session['username']  = username
    session['name']      = name
    session['role']      = 'SOC Analyst'

    return jsonify({'success': True, 'name': name, 'role': 'SOC Analyst'})

@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    session.clear()
    return redirect('/login.html')

@app.route('/api/session')
def api_session():
    """Check current session state."""
    if session.get('logged_in'):
        return jsonify({'logged_in': True, 'username': session.get('username'), 'name': session.get('name'), 'role': session.get('role')})
    return jsonify({'logged_in': False}), 401

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

# ── SSE stream ─────────────────────────────────────────────────
@app.route('/api/stream')
def stream():
    """Real-time Server-Sent Events – one new event per buffer tick."""
    def generate():
        last_seen = 0
        while True:
            with _lock:
                buf = list(_state['log_buffer'])
            if len(buf) > last_seen:
                for entry in buf[last_seen:]:
                    yield f'data: {json.dumps(entry)}\n\n'
                last_seen = len(buf)
            time.sleep(0.2)
    return Response(generate(), headers={
        'Content-Type':      'text/event-stream',
        'Cache-Control':     'no-cache',
        'X-Accel-Buffering': 'no',
    })

# ── Live metrics snapshot ───────────────────────────────────────
@app.route('/api/metrics')
def api_metrics():
    with _lock:
        mode    = _state['mode']
        rm      = _state['real_metrics']
    if mode == 'real' and rm:
        return jsonify({
            'active_threats': rm.get('active_threats', 0),
            'logs_analyzed':  rm.get('total_events', 0),
            'mttp':           rm.get('mttp', 0.0),
            'risk_score':     rm.get('risk_score', 0),
            'risk_level':     rm.get('risk_level', 'Low'),
            'mode':           'real',
            'ts':             datetime.datetime.now().isoformat(),
        })
    with _lock:
        risk = _state['risk_score']
        return jsonify({
            'active_threats': _state['active_threats'],
            'logs_analyzed':  _state['logs_analyzed'],
            'mttp':           _state['mttp'],
            'risk_score':     risk,
            'risk_level':     'High' if risk>=70 else 'Medium' if risk>=40 else 'Low',
            'mode':           'simulation',
            'ts':             datetime.datetime.now().isoformat(),
        })

# ── File upload + Real Analysis ─────────────────────────────────
@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
    if not _allowed_file(f.filename):
        return jsonify({'success': False, 'error': f'File type not supported. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    save_path = os.path.join(UPLOAD_DIR, f.filename)
    try:
        f.save(save_path)
        file_size = os.path.getsize(save_path)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Save failed: {e}'}), 500

    return jsonify({
        'success':  True,
        'filename': f.filename,
        'size':     file_size,
        'message':  f'File saved. Trigger /api/analyze to run analysis.',
    })

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze one or more uploaded files. Returns a job_id for polling."""
    body  = request.get_json(silent=True) or {}
    files = body.get('files', [])         # list of filenames already uploaded
    if not files:
        # Try reading raw filename from form
        files = request.form.getlist('files') or []

    if not files:
        # Auto-analyze all files in uploads dir
        files = [fn for fn in os.listdir(UPLOAD_DIR) if _allowed_file(fn)]

    if not files:
        return jsonify({'success': False, 'error': 'No files to analyze'}), 400

    job_id = str(uuid.uuid4())[:8]

    def _run_analysis():
        all_events     = []
        events_by_file = {}
        formats_used   = []
        errors         = []

        for fn in files:
            fpath = os.path.join(UPLOAD_DIR, fn)
            if not os.path.exists(fpath):
                errors.append(f'{fn}: not found in uploads directory')
                continue
            try:
                content = _safe_read(fpath)
                evs, fmt = az.parse_log_file(content, fn)
                all_events.extend(evs)
                events_by_file[fn] = evs
                formats_used.append({'file': fn, 'format': fmt, 'events': len(evs)})
            except Exception as e:
                errors.append(f'{fn}: parse error – {e}')

        # Threat detection
        alerts      = az.detect_threats(all_events) if all_events else []
        metrics     = az.calculate_metrics(all_events, alerts) if all_events else {}
        correlation = az.correlate_files(events_by_file)

        # Build timeline events (top 50 by severity)
        timeline_evs = sorted(
            [e for e in all_events if e['status'] in ('critical','warning')],
            key=lambda x: x['ts'], reverse=True
        )[:50]

        result = {
            'job_id':      job_id,
            'status':      'done',
            'files':       formats_used,
            'errors':      errors,
            'total_events':len(all_events),
            'alerts':      alerts,
            'metrics':     metrics,
            'correlation': correlation,
            'timeline':    timeline_evs[:30],
            'top_events':  (
                sorted(all_events, key=lambda x: ('critical','warning','info').index(x['status']))
            )[:200],
            'ts': datetime.datetime.now().isoformat(),
        }

        with _lock:
            _state['analysis_jobs'][job_id] = result
            # Update global state
            _state['mode']           = 'real'
            _state['real_events']    = all_events
            _state['real_alerts']    = alerts
            _state['real_metrics']   = metrics
            _state['real_files']     = events_by_file
            if metrics:
                _state['risk_score']     = float(metrics.get('risk_score', 0))
                _state['active_threats'] = int(metrics.get('active_threats', 0))
                _state['logs_analyzed']  = int(metrics.get('total_events', 0))
                _state['mttp']           = float(metrics.get('mttp', 0))

        # Inject real events into SSE stream so frontend sees them live
        _inject_real_events_to_stream(all_events)

        # Build timeline buffer from real events
        with _lock:
            _state['timeline_buffer'].clear()
            for ev in timeline_evs[:30]:
                _state['timeline_buffer'].append({
                    'ts':     ev['ts'],
                    'phase':  ev.get('type', 'event') or 'event',
                    'detail': ev.get('event', ''),
                    'status': ev.get('status', 'info'),
                })

    # Run in background thread
    threading.Thread(target=_run_analysis, daemon=True).start()
    # Mark job as running
    with _lock:
        _state['analysis_jobs'][job_id] = {'job_id': job_id, 'status': 'running'}

    return jsonify({'success': True, 'job_id': job_id, 'files': files})

@app.route('/api/analysis/<job_id>')
def api_analysis_result(job_id):
    """Poll for analysis result."""
    with _lock:
        result = _state['analysis_jobs'].get(job_id)
    if not result:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(result)

# ── Geolocation ────────────────────────────────────────────────
@app.route('/api/geolocate/<ip>')
def api_geolocate(ip):
    try:
        geo = az.geolocate_ip(ip)
        return jsonify({'ip': ip, **geo})
    except Exception as e:
        return jsonify({'ip': ip, 'error': str(e)}), 500

# ── Multi-IP geolocation (batch) ────────────────────────────────
@app.route('/api/geolocate-batch', methods=['POST'])
def api_geo_batch():
    ips = (request.get_json(silent=True) or {}).get('ips', [])
    results = {}
    for ip in ips[:15]:   # limit to avoid rate limits
        results[ip] = az.geolocate_ip(ip)
    return jsonify(results)

# ── Report download ────────────────────────────────────────────
@app.route('/api/report/<job_id>/<fmt>')
def api_report(job_id, fmt):
    with _lock:
        result = _state['analysis_jobs'].get(job_id)
    if not result or result.get('status') != 'done':
        return jsonify({'error': 'Job not ready or not found'}), 404

    events  = result.get('top_events', [])
    alerts  = result.get('alerts', [])
    metrics = result.get('metrics', {})

    if fmt == 'csv':
        csv_data = az.generate_csv_report(events, alerts, metrics)
        return Response(csv_data,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=cfip_report_{job_id}.csv'})

    if fmt == 'pdf':
        pdf_bytes = az.generate_pdf_report(events, alerts, metrics)
        if pdf_bytes is None:
            return jsonify({'error': 'PDF generation unavailable. Install: pip install fpdf2'}), 500
        return Response(pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=cfip_report_{job_id}.pdf'})

    return jsonify({'error': f'Unknown format: {fmt}'}), 400

# ── Windows Live Event Log ──────────────────────────────────────
@app.route('/api/windows-events')
def api_windows_events():
    log_name = request.args.get('log', 'Security')
    count    = min(int(request.args.get('count', 100)), 500)
    try:
        events = az._read_live_windows_event_log(log_name, count)
        if events:
            alerts  = az.detect_threats(events)
            metrics = az.calculate_metrics(events, alerts)
            job_id  = f'win_{log_name.lower()}_{int(time.time())}'
            result  = {
                'job_id':      job_id,
                'status':      'done',
                'files':       [{'file': f'Windows {log_name}', 'format': 'Windows Event Log', 'events': len(events)}],
                'errors':      [],
                'total_events':len(events),
                'alerts':      alerts,
                'metrics':     metrics,
                'correlation': [],
                'timeline':    [e for e in events if e['status'] in ('critical','warning')][:30],
                'top_events':  events[:200],
                'ts':          datetime.datetime.now().isoformat(),
            }
            with _lock:
                _state['analysis_jobs'][job_id] = result
                _state['mode']           = 'real'
                _state['real_metrics']   = metrics
                _state['active_threats'] = int(metrics.get('active_threats', 0))
                _state['risk_score']     = float(metrics.get('risk_score', 0))
            _inject_real_events_to_stream(events)
            return jsonify({'success': True, 'job_id': job_id, **result})
        else:
            return jsonify({'success': False, 'error': 'No events read (check permissions or log name)'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ── Timeline ────────────────────────────────────────────────────
@app.route('/api/timeline')
def api_timeline():
    with _lock:
        return jsonify(list(_state['timeline_buffer'])[-15:])

# ── Simulation control ──────────────────────────────────────────
@app.route('/api/control', methods=['POST'])
def api_control():
    body = request.get_json(silent=True) or {}
    with _lock:
        if 'running' in body: _state['running'] = bool(body['running'])
        if 'speed'   in body: _state['speed']   = float(body['speed'])
        if body.get('reset_mode'):
            _state['mode'] = 'simulation'
            _state['real_events']  = []
            _state['real_alerts']  = []
            _state['real_metrics'] = {}
    return jsonify({'ok': True, 'running': _state['running'], 'mode': _state['mode']})

# ── Status ──────────────────────────────────────────────────────
@app.route('/api/status')
def api_status():
    with _lock:
        return jsonify({
            'mode':          _state['mode'],
            'running':       _state['running'],
            'speed':         _state['speed'],
            'logs_analyzed': _state['logs_analyzed'],
            'has_pandas':    az.HAS_PANDAS,
            'has_requests':  az.HAS_REQUESTS,
            'has_fpdf':      az.HAS_FPDF,
            'jobs':          list(_state['analysis_jobs'].keys()),
        })

# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 58)
    print('  CFIP - Cyber Forensic Intelligence Platform')
    print('  [OK] Real-data analysis engine loaded')
    print('  [OK] Dashboard -> http://127.0.0.1:5000')
    print('  pandas  :', 'available' if az.HAS_PANDAS   else 'not installed (pip install pandas)')
    print('  requests:', 'available' if az.HAS_REQUESTS else 'not installed (pip install requests)')
    print('  fpdf2   :', 'available' if az.HAS_FPDF     else 'not installed (pip install fpdf2)')
    print('=' * 58)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
