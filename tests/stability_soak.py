#!/usr/bin/env python3
"""Bounded native Linux baseline/candidate comparison; synthetic network only."""
import argparse
import concurrent.futures
import http.server
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid

spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('protocol_smoke.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
state={};reports={};expected={};expected_lock=threading.Lock();stop_holds=threading.Event()
class CountWriter:
    def __init__(self,inner):self.inner=inner;self.count=0
    def write(self,data):
        n=self.inner.write(data);self.count+=len(data) if n is None else n;return n
    def __getattr__(self,name):return getattr(self.inner,name)
class Handler(f.Handler):
    def do_GET(self):
        parsed=urllib.parse.urlsplit(self.path)
        if parsed.path=='/ok':
            node=int(urllib.parse.parse_qs(parsed.query)['soak'][0])
            up=len(self.raw_requestline)+sum(len(k.encode('latin1'))+2+len(v.encode('latin1'))+2 for k,v in self.headers.raw_items())+2
            original=self.wfile;counted=CountWriter(original);self.wfile=counted
            try:super().do_GET()
            finally:
                self.wfile=original
                with expected_lock:expected[node]=expected.get(node,0)+up+counted.count
            return
        args=urllib.parse.parse_qs(parsed.query);node=int(args['node_id'][0]);s=state[node]
        if s['offline']:
            self.send_error(503);return
        if parsed.path.endswith('/config'):self.reply(s['definition'])
        elif parsed.path.endswith('/user'):self.reply({'users':s['users']})
        else:self.send_error(404)
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length',0)));parsed=urllib.parse.urlsplit(self.path)
        if parsed.path.endswith('/handshake'):
            self.reply({'websocket':{'enabled':False},'settings':{'push_interval':5,'pull_interval':2}});return
        args=urllib.parse.parse_qs(parsed.query);node=int(json.loads(raw).get('node_id',0));s=state.get(node)
        if s and s['report_offline']:
            self.send_error(503);return
        if parsed.path.endswith('/report') and s:
            value=json.loads(raw);reports[node]['batches']+=1;reports[node]['kernel_objects']=value.get('metrics',{}).get('kernel_objects');reports[node]['active_connections']=value.get('metrics',{}).get('active_connections')
            # XBoard /push body is a map of user ID -> [upload, download].
            for key,v in value.get("traffic",{}).items():
                if isinstance(v,list) and len(v)==2:reports[node]['bytes']+=sum(v)
        self.reply({'data':True})
class Server(http.server.ThreadingHTTPServer):
    daemon_threads=True;request_queue_size=256

def memory(pid):
    p=Path('/proc')/str(pid);r={}
    for line in (p/'status').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in ('VmRSS','VmHWM','RssAnon','RssFile','Threads'):r[key]=int(value.split()[0])
    for line in (p/'smaps_rollup').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in ('Pss','Private_Dirty','Private_Clean'):r[key]=int(value.split()[0])
    fields=(p/'stat').read_text().rsplit(')',1)[1].split();r['cpu_ticks']=int(fields[11])+int(fields[12]);r['fds']=sum(1 for _ in (p/'fd').iterdir())
    return r

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--baseline',required=True);ap.add_argument('--candidate',required=True);ap.add_argument('--client',required=True);ap.add_argument('--seconds',type=int,default=1800);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert Path('/.dockerenv').exists();assert not any(line.split()[1]=='00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:]);assert subprocess.check_output(['uname','-m'],text=True).strip()=='aarch64'
    server=Server(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();api=server.server_address[1]
    processes=[];clients=[];cases=[];records=[];success={};failures={};started=time.monotonic()
    try:
      with tempfile.TemporaryDirectory() as folder:
        root=Path(folder);cert=root/'cert.pem';key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-days','1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        for node,(version,binary,protocol,kernel) in enumerate([(v,b,p,k) for v,b in [('baseline',a.baseline),('candidate',a.candidate)] for p,k in [('vless','xray'),('anytls','singbox')]],901):
            runtime=root/str(node);runtime.mkdir();port=f.free_port();tls=protocol=='anytls';label=version+'-'+protocol
            definition={'protocol':protocol,'server_port':port,'listen_ip':'127.0.0.1','network':'tcp','tls':int(tls),'flow':'','tls_settings':{'server_name':'localhost'},'base_config':{'push_interval':5,'pull_interval':2},'cert_config':{'cert_mode':'none'}}
            state[node]={'definition':definition,'users':[dict(f.USER,device_limit=0)],'offline':False,'report_offline':False};reports[node]={'batches':0,'bytes':0}
            route={'type':'field','ip':['127.0.0.1/32'],'outboundTag':'direct'} if kernel=='xray' else {'ip_cidr':['127.0.0.1/32'],'outbound':'direct'}
            cfg={'panel':{'url':f'http://127.0.0.1:{api}','token':'synthetic-only-token','node_id':node,'node_type':protocol},'kernel':{'type':kernel,'config_dir':str(runtime),'log_level':'warn','custom_route':[route]},'cert':{'prefer_local':True,'cert_mode':'file' if tls else 'none','cert_file':str(cert),'key_file':str(key)},'node':{'push_interval':5,'pull_interval':2,'track_interval':1,'device_report_interval':5},'log':{'level':'info'},'health_port':0}
            path=runtime/'config.json';path.write_text(json.dumps(cfg));log=(runtime/'server.log').open('w');process=subprocess.Popen([binary,'-c',str(path)],stdout=log,stderr=log);processes.append(process)
            deadline=time.monotonic()+30
            while time.monotonic()<deadline and not f.listening(port,'tcp'):assert process.poll() is None,(runtime/'server.log').read_text();time.sleep(.1)
            assert f.listening(port,'tcp')
            proxy=f.free_port();out={'type':protocol,'tag':'proxy','server':'127.0.0.1','server_port':port}
            if protocol=='vless':out['uuid']=f.USER['uuid']
            else:out.update(password=f.USER['uuid'],tls={'enabled':True,'server_name':'localhost','certificate_path':str(cert)})
            client_cfg={'log':{'level':'warn'},'inbounds':[{'type':'http','listen':'127.0.0.1','listen_port':proxy}],'outbounds':[out],'route':{'final':'proxy'}}
            cp=runtime/'client.json';cp.write_text(json.dumps(client_cfg));clog=(runtime/'client.log').open('w');client=subprocess.Popen([a.client,'run','-c',str(cp)],stdout=clog,stderr=clog);clients.append(client)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline and not f.listening(proxy,'tcp'):assert client.poll() is None;time.sleep(.1)
            cases.append({'node':node,'label':label,'process':process,'proxy':proxy,'runtime':runtime});success[label]=0;failures[label]=0
        print(json.dumps({'event':'started','duration_seconds':a.seconds,'cases':[c['label'] for c in cases]}),flush=True)
        started=time.monotonic();cycle=0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
          while time.monotonic()-started<a.seconds:
            elapsed=time.monotonic()-started
            offline=int(elapsed)%60 in range(35,43)
            report_offline=int(elapsed)%60 in range(25,43)
            for c in cases:
                s=state[c['node']];s['offline']=offline;s['report_offline']=report_offline
                if cycle%5==0:
                    generation=cycle//5;s['users']=[dict(f.USER,device_limit=0)]+[{'id':10000+generation*250+i,'uuid':str(uuid.uuid5(uuid.NAMESPACE_DNS,f'synthetic-soak-{generation}-{i}')),'device_limit':0,'speed_limit':0} for i in range(250)]
            jobs=[(c,pool.submit(f.proxy_request,c['proxy'],api,'/ok?soak='+str(c['node']),timeout=4)) for c in cases for _ in range(2)]
            for c,job in jobs:
                try:
                    _,data=job.result();assert b'synthetic_proxy_request' in data;success[c['label']]+=1
                except Exception:failures[c['label']]+=1
            if cycle%10==0:
                sample={'elapsed_seconds':round(elapsed,2),'offline':offline,'report_offline':report_offline,'cases':{c['label']:{**memory(c['process'].pid),'success':success[c['label']],'failures':failures[c['label']],**reports[c['node']]} for c in cases}}
                records.append(sample);a.output.write_text(json.dumps({'samples':records,'complete':False},indent=2));print(json.dumps(sample),flush=True)
            cycle+=1;time.sleep(max(0,started+cycle-time.monotonic()))
        for s in state.values():s['offline']=False;s['report_offline']=False
        time.sleep(12)
        for c in cases:
            assert c['process'].poll() is None
        for client in clients:f.stop(client)
        for process in processes:f.stop(process)
        for c in cases:
            assert success[c['label']]>a.seconds and failures[c['label']]==0,(c['label'],success,failures)
            assert reports[c['node']]['batches']>0 and reports[c['node']]['bytes']>0,reports
            assert reports[c['node']]['bytes']==expected[c['node']],(c['label'],reports[c['node']],expected[c['node']])
        result={'complete':True,'pass':True,'duration_seconds':round(time.monotonic()-started,2),'native_arch':'aarch64','network_isolated':True,'synthetic_only':True,'cycles':cycle,'users_per_generation':251,'samples':records,'success':success,'failures':failures,'reports':reports,'expected_bytes':expected}
        a.output.write_text(json.dumps(result,indent=2));print(json.dumps({'event':'complete','pass':True,'duration_seconds':result['duration_seconds'],'success':success}),flush=True)
    finally:
      for p in clients+processes:f.stop(p)
      server.shutdown();server.server_close()
if __name__=='__main__':main()
