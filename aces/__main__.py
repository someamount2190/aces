import argparse, json, threading
from .core import Engine
from .web import serve
from .runtime import Coordinator
p=argparse.ArgumentParser(); p.add_argument('--db',default='aces.sqlite3'); p.add_argument('--config'); p.add_argument('--port',type=int,default=8765); a=p.parse_args()
e=Engine(a.db)
if a.config:
    c=Coordinator(e,json.load(open(a.config)))
    threading.Thread(target=c.run,daemon=True).start()
else: print('No model configured: dashboard and state engine only; autonomous agents are inactive.')
serve(e,a.port)
