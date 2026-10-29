"""Administrator-only loopback dashboard. Never expose this server to agents."""
import json, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .core import packed

PAGE='''<!doctype html><html><meta charset="utf-8"><title>ACES — Cryptographic ecosystem</title><style>body{background:#101722;color:#e1ecf5;font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}h1{color:#71dfd0}button{padding:12px;margin:5px;background:#22394c;color:white;border:1px solid #71dfd0;border-radius:8px}pre{white-space:pre-wrap;background:#182636;padding:20px;border-radius:12px}small{color:#b6c5d1}</style><h1>ACES</h1><p>Autonomous Cryptographic Evolution Sandbox</p><small>Experimental byte-permutation laboratory · correctness is not security</small><p><button onclick="ctl('running')">Start / resume</button><button onclick="ctl('paused')">Pause</button><button onclick="ctl('stopped')">Stop</button><button onclick="location.href='/audit'">Export audit</button></p><h2>Ecosystem</h2><pre id="status"></pre><h2>Challenge history</h2><pre id="challenges"></pre><h2>Observer intelligence</h2><pre id="findings"></pre><script>const token=__TOKEN__;async function ctl(state){await fetch('/control',{method:'POST',headers:{'Content-Type':'application/json','X-ACES-Token':token},body:JSON.stringify({state})});refresh()}async function refresh(){let r=await fetch('/status');let d=await r.json();for(let k of ['status','challenges','findings'])document.getElementById(k).textContent=JSON.stringify(d[k],null,2)}refresh();setInterval(refresh,3000)</script></html>'''

def serve(engine,port=8765):
    token=secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        def send(self,status,data,kind='application/json'):
            b=data.encode(); self.send_response(status); self.send_header('Content-Type',kind); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if self.headers.get('Host') not in (f'127.0.0.1:{port}',f'localhost:{port}'): return self.send(403,'{}')
            path=urlparse(self.path).path
            if path=='/': return self.send(200,PAGE.replace('__TOKEN__',json.dumps(token)),'text/html; charset=utf-8')
            with engine.connect() as db:
                if path=='/audit': return self.send(200,packed([dict(r) for r in db.execute('SELECT * FROM events')]))
                if path!='/status': return self.send(404,'{}')
                value={'status':{'control':db.execute('SELECT state FROM control').fetchone()[0],'agents':[dict(r) for r in db.execute('SELECT role,turns FROM sessions')],'candy':db.execute('SELECT COALESCE(SUM(amount),0) FROM rewards').fetchone()[0],'candidates':db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]},'challenges':[dict(r) for r in db.execute('SELECT id,candidate,state,parent,published FROM challenges')],'findings':[dict(r) for r in db.execute('SELECT * FROM findings')]}
            return self.send(200,packed(value))
        def do_POST(self):
            if not secrets.compare_digest(self.headers.get('X-ACES-Token',''),token): return self.send(403,'{}')
            if self.path!='/control': return self.send(404,'{}')
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<1024: raise ValueError()
                state=json.loads(self.rfile.read(n))['state']
                if state not in ('running','paused','stopped'): raise ValueError()
                with engine.tx() as db:
                    db.execute('UPDATE control SET state=?',(state,)); engine.event(db,'administrative_control',{'state':state})
                self.send(200,packed({'state':state}))
            except (ValueError,KeyError): self.send(400,'{}')
        def log_message(self,*args): pass
    print(f'Administrator dashboard: http://127.0.0.1:{port}',flush=True)
    ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
