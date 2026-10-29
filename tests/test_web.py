import json, multiprocessing, socket, tempfile, time, unittest, urllib.request, urllib.error
from pathlib import Path
from aces.core import Engine
from aces.web import serve
class WebTests(unittest.TestCase):
    def test_dashboard_and_control_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as s:
                s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
            engine=Engine(Path(directory)/'db')
            process=multiprocessing.Process(target=serve,args=(engine,port)); process.start()
            try:
                url=f'http://127.0.0.1:{port}'
                for _ in range(50):
                    try:
                        with urllib.request.urlopen(url,timeout=1) as r: page=r.read().decode()
                        break
                    except OSError: time.sleep(.02)
                self.assertIn('ACES',page)
                with urllib.request.urlopen(url+'/status') as r: self.assertEqual(json.load(r)['status']['control'],'paused')
                with self.assertRaises(urllib.error.HTTPError) as exc:
                    urllib.request.urlopen(urllib.request.Request(url+'/control',data=b'{"state":"running"}',headers={'Content-Type':'application/json'}))
                self.assertEqual(exc.exception.code,403)
                token=json.loads(page.split('const token=')[1].split(';async')[0])
                req=urllib.request.Request(url+'/control',data=b'{"state":"running"}',headers={'Content-Type':'application/json','X-ACES-Token':token})
                with urllib.request.urlopen(req) as r: self.assertEqual(json.load(r)['state'],'running')
                with urllib.request.urlopen(url+'/audit') as r: self.assertEqual(json.load(r)[0]['kind'],'administrative_control')
            finally:
                process.terminate(); process.join()
