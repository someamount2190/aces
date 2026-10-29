"""Explicit deterministic integration demonstration; NOT autonomous LLM operation."""
import argparse, json
from aces.core import Engine
p=argparse.ArgumentParser(); p.add_argument('--db',default='demo.sqlite3'); a=p.parse_args()
e=Engine(a.db)
spec={'name':'XOR byte toy','program':[['xor_key',0]],'math':'c = p XOR k','limitations':'8-bit keys; trivial exhaustive recovery','assumptions':'none'}
c=e.register(spec)['candidate']; e.publish(c)
ch=e.view('adversary')['challenge']; pub=ch['public']
args={k:pub[k] for k in ('known_plaintext','known_ciphertext','ciphertext')}; args['program']=pub['spec']['program']
attack=e.tool('adversary','compute',args)
result=e.submit(ch['id'],attack['solutions'][0]['plaintext'])
e.tool('observer','record_finding',{'challenge':ch['id'],'finding':'Exhaustive enumeration of all 256 keys recovers target from a known pair.'})
c2=e.register(dict(spec,name='Rotated XOR toy',program=[['xor_key',0],['rol',3]],math='rotate(p XOR k,3)'))['candidate']
e.publish(c2,parent=ch['id'])
print(json.dumps({'label':'deterministic tool integration demo; no model calls','verified':result,'candy':e.view('adversary')['candy'],'next_challenge':e.view('adversary')['challenge']['id'],'feedback':e.view('generator')['feedback']},indent=2))
