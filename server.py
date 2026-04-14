# -*- coding: utf-8 -*-
"""
CFIP Backend — Windows Python Server
Cyber Forensic Intelligence Platform
Run: python server.py
Then open: http://localhost:3000
"""

import json
import subprocess
import threading
import time
import os
import socket
import platform
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import ctypes
import sys

# ── WebSocket support (install with: pip install websockets) ──
try:
    import asyncio
    import websockets
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
PORT    = 3000
WS_PORT = 3001
PUBLIC  = os.path.join(os.path.dirname(__file__), "public")

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def classify(line: str) -> str:
    l = line.lower()
    if any(k in l for k in ["fail","error","denied","invalid","breach","attack","brute","4625"]):
        return "err"
    if any(k in l for k in ["warn","suspicious","unusual","alert","unknown","4648","4673"]):
        return "warn"
    if any(k in l for k in ["accept","success","opened","started","4624","4672"]):
        return "ok"
    return "info"

def run_ps(command: str, timeout: int = 10) -> str:
    """Run a PowerShell command and return stdout."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=timeout
    )
    return result.stdout.strip()

# ─────────────────────────────────────────────
#  DATA FETCHERS
# ─────────────────────────────────────────────
def get_stats():
    import psutil
    mem   = psutil.virtual_memory()
    cpu   = psutil.cpu_percent(interval=0.5)
    boot  = psutil.boot_time()
    uptime_secs = int(time.time() - boot)
    return {
        "platform":   platform.system(),
        "hostname":   socket.gethostname(),
        "uptime":     uptime_secs,
        "cpuPct":     cpu,
        "memTotalMB": round(mem.total / 1024 / 1024),
        "memUsedMB":  round(mem.used  / 1024 / 1024),
        "memPct":     mem.percent,
        "cpuCount":   os.cpu_count(),
        "arch":       platform.machine(),
        "admin":      is_admin(),
    }

def get_os_logs():
    """Pull last 60 Security + System events via PowerShell."""
    ps = """
$events = @()
$events += Get-EventLog -LogName Security -Newest 40 -ErrorAction SilentlyContinue |
    Select-Object TimeGenerated, EntryType, EventID, Message
$events += Get-EventLog -LogName System -Newest 20 -ErrorAction SilentlyContinue |
    Select-Object TimeGenerated, EntryType, EventID, Message
$events | Sort-Object TimeGenerated | ConvertTo-Json -Depth 2
"""
    try:
        raw = run_ps(ps, timeout=15)
        if not raw:
            return {"os": "windows", "lines": [], "error": "No events returned — run as Administrator"}
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        lines = []
        for e in data:
            t   = e.get("TimeGenerated", "")
            et  = e.get("EntryType", "Information")
            eid = e.get("EventID", "")
            msg = (e.get("Message") or "")[:200].replace("\r","").replace("\n"," ")
            raw_line = f"[{t}] EID:{eid} {et}: {msg}"
            lines.append({"raw": raw_line, "type": classify(raw_line)})
        return {"os": "windows", "lines": lines}
    except subprocess.TimeoutExpired:
        return {"os": "windows", "lines": [], "error": "PowerShell timed out"}
    except json.JSONDecodeError as ex:
        # fallback: return raw text split into lines
        lines = [{"raw": l, "type": classify(l)} for l in raw.split("\n") if l.strip()]
        return {"os": "windows", "lines": lines}

def get_network_connections():
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.status in ("ESTABLISHED", "LISTEN"):
                la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                conns.append(f"{c.status:<12} {la:<25} {ra:<25} pid={c.pid}")
        return {"connections": conns[:30]}
    except Exception as e:
        return {"connections": [], "error": str(e)}

def get_processes():
    try:
        import psutil
        procs = []
        for p in sorted(psutil.process_iter(["pid","name","cpu_percent","memory_info"]),
                        key=lambda x: x.info["cpu_percent"] or 0, reverse=True)[:20]:
            mem_mb = round((p.info["memory_info"].rss if p.info["memory_info"] else 0) / 1024 / 1024, 1)
            procs.append({
                "pid":  p.info["pid"],
                "name": p.info["name"],
                "cpu":  f'{p.info["cpu_percent"] or 0:.1f}%',
                "mem":  f"{mem_mb}MB",
            })
        return {"processes": procs}
    except Exception as e:
        return {"processes": [], "error": str(e)}

# ─────────────────────────────────────────────
#  HTTP REQUEST HANDLER
# ─────────────────────────────────────────────
class CFIPHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC, **kwargs)

    def log_message(self, fmt, *args):
        pass  # silence default access log

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/stats":
            try:
                self.send_json(get_stats())
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/os-logs":
            try:
                self.send_json(get_os_logs())
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/network-connections":
            try:
                self.send_json(get_network_connections())
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/running-processes":
            try:
                self.send_json(get_processes())
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/ping":
            self.send_json({"status": "ok", "platform": "windows", "admin": is_admin()})

        else:
            # Serve static files from public/
            super().do_GET()

# ─────────────────────────────────────────────
#  WEBSOCKET SERVER  (live log streaming)
# ─────────────────────────────────────────────
streaming_clients = set()

async def ws_handler(websocket):
    streaming_clients.add(websocket)
    await websocket.send(json.dumps({
        "raw":  f"# WebSocket connected — Windows / Python backend",
        "type": "ok"
    }))
    polling = False
    poll_task = None

    async def poll_new_events():
        """Poll Windows Security log every 3 seconds for new entries."""
        ps_template = """
Get-EventLog -LogName Security -Newest 3 -After (Get-Date).AddSeconds(-4) `
    -ErrorAction SilentlyContinue |
    Select-Object TimeGenerated,EntryType,EventID,Message |
    ConvertTo-Json -Depth 1
"""
        while True:
            await asyncio.sleep(3)
            try:
                raw = await asyncio.to_thread(run_ps, ps_template, 8)
                if raw:
                    data = json.loads(raw)
                    if isinstance(data, dict): data = [data]
                    for e in data:
                        t   = e.get("TimeGenerated","")
                        et  = e.get("EntryType","")
                        eid = e.get("EventID","")
                        msg = (e.get("Message") or "")[:200].replace("\r","").replace("\n"," ")
                        line = f"[{t}] EID:{eid} {et}: {msg}"
                        await websocket.send(json.dumps({"raw": line, "type": classify(line)}))
            except Exception:
                pass

    try:
        async for msg in websocket:
            try:
                data = json.loads(msg)
            except:
                continue
            if data.get("action") == "start-stream" and poll_task is None:
                await websocket.send(json.dumps({"raw": "# Streaming Windows Security events (every 3s)...", "type": "info"}))
                poll_task = asyncio.create_task(poll_new_events())
            elif data.get("action") == "stop-stream" and poll_task:
                poll_task.cancel()
                poll_task = None
                await websocket.send(json.dumps({"raw": "# Stream stopped.", "type": "warn"}))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        streaming_clients.discard(websocket)
        if poll_task:
            poll_task.cancel()

def start_ws_server():
    if not WS_AVAILABLE:
        print("  ⚠  WebSocket unavailable — run: pip install websockets")
        return
    async def _run():
        async with websockets.serve(ws_handler, "localhost", WS_PORT):
            await asyncio.Future()
    asyncio.run(_run())

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    SEP = "-" * 52
    print("\n" + SEP)
    print("  CFIP XDR - Cyber Forensic Intelligence Platform")
    print("  Windows Python Backend v2.4")
    print(SEP)
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Host    : {socket.gethostname()}")
    print(f"  Admin   : {'YES' if is_admin() else 'NO - log access may be limited'}")
    print(SEP)

    # Check psutil
    try:
        import psutil
        print("  psutil  : installed ✓")
    except ImportError:
        print("  psutil  : NOT installed — run: pip install psutil")
        print("  (Stats and process endpoints will fail without it)")

    # Check websockets
    if WS_AVAILABLE:
        print("  websockets: installed ✓")
    else:
        print("  websockets: NOT installed — run: pip install websockets")
        print("  (Live stream button will not work without it)")

    print(SEP)

    # Start WebSocket in a background thread
    if WS_AVAILABLE:
        ws_thread = threading.Thread(target=start_ws_server, daemon=True)
        ws_thread.start()
        print(f"\n  [WS]  WebSocket : ws://localhost:{WS_PORT}")

    # Start HTTP server
    httpd = HTTPServer(("", PORT), CFIPHandler)
    print(f"  [HTTP] Dashboard : http://localhost:{PORT}")
    print("\n  Press Ctrl+C to stop.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")

if __name__ == "__main__":
    main()
