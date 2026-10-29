import json, os, urllib.request, urllib.parse, time
from .core import ROLES, packed
from .prompts import CHARTERS as PROMPTS

class Provider:
    def __init__(self, config): self.config=config
    def complete(self,role,messages):
        c=self.config; agent=c['agents'][role]
        url=c['base_url'].rstrip('/')+'/chat/completions'
        parsed=urllib.parse.urlparse(url)
        if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('localhost','127.0.0.1','::1')):
            raise ValueError('provider requires HTTPS or loopback HTTP')
        key=os.environ.get(c.get('api_key_env','ACES_API_KEY'),'')
        body={'model':agent['model'],'messages':messages,'max_completion_tokens':agent.get('max_tokens',1200)}
        if agent.get('reasoning_effort'): body['reasoning_effort']=agent['reasoning_effort']
        req=urllib.request.Request(url,data=packed(body).encode(),headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+key} if key else {})})
        with urllib.request.urlopen(req,timeout=60) as response:
            raw=response.read(2_000_001)
        if len(raw)>2_000_000: raise ValueError('provider response too large')
        return json.loads(raw)['choices'][0]['message']['content']

class Coordinator:
    def __init__(self,engine,config):
        self.engine=engine; self.config=config; self.provider=Provider(config)
    def tick(self):
        for role in ROLES:
            e=self.engine
            with e.connect() as db:
                if db.execute('SELECT state FROM control').fetchone()[0]!='running': return
                row=db.execute('SELECT * FROM sessions WHERE role=?',(role,)).fetchone()
                last_event=db.execute('SELECT COALESCE(MAX(id),0) FROM events WHERE kind NOT IN (\'model_turn\',\'model_error\')').fetchone()[0]
            view=e.view(role)
            # No LLM polling when there is no relevant work.
            if role=='integrator' and (not view['catalog'] or (view['challenge'] and view['challenge']['state']=='ACTIVE')): continue
            if role=='adversary' and (not view['challenge'] or view['challenge']['state']!='ACTIVE'): continue
            history=json.loads(row['messages'])
            if row['turns']>=self.config.get('max_turns_per_agent',50): continue
            if role in ('generator','observer') and row['cursor']==last_event and row['turns']: continue
            if history and history[-1]['role']=='user' and json.loads(history[-1]['content']).get('idle') and row['cursor']==last_event: continue
            messages=[{'role':'system','content':PROMPTS[role]}]+history[-12:]+[{'role':'user','content':packed({'environment':view})}]
            work_id=e.begin_work(role,last_event)
            try:
                answer=self.provider.complete(role,messages)
                action=json.loads(answer)
                if action.get('idle'): result={'idle':True}
                else: result=e.tool(role,action['tool'],action['args'])
                messages += [{'role':'assistant','content':answer},{'role':'user','content':packed(result)}]
                e.finish_work(work_id,answer,'idle' if result.get('idle') else 'tool_executed',messages=messages[1:])
                with e.tx() as db: e.event(db,'model_turn',{'role':role,'outcome':'idle' if result.get('idle') else 'tool_executed'})
            except Exception as exc:
                # Charge failed sessions too; no infinite retry on malformed output.
                e.finish_work(work_id,None,error_type=type(exc).__name__)
                with e.tx() as db: e.event(db,'model_error',{'role':role,'type':type(exc).__name__})
    def run(self):
        while True:
            self.tick(); time.sleep(self.config.get('interval_seconds',3))
