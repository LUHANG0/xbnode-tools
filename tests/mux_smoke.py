#!/usr/bin/env python3
"""Actual Xray mux.cool/XUDP streams, synthetic isolated target and users."""
import argparse
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('protocol_smoke.py'));f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--client',required=True);a=p.parse_args()
 assert Path('/.dockerenv').exists();assert not any(line.split()[1]=='00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:])
 server=f.http.server.ThreadingHTTPServer(('127.0.0.1',0),f.Handler);threading.Thread(target=server.serve_forever,daemon=True).start();api=server.server_address[1]
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));target=udp.getsockname()[1]
 def echo():
  while True:
   try:data,peer=udp.recvfrom(65535);udp.sendto(data,peer)
   except OSError:return
 threading.Thread(target=echo,daemon=True).start();results=[]
 try:
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)
   for protocol in ['vless','vmess']:
    clients=[];conns=[];runtime=root/protocol;runtime.mkdir();port=f.free_port();node=901
    f.definitions[node]={'protocol':protocol,'server_port':port,'listen_ip':'127.0.0.1','network':'tcp','tls':0,'flow':'','base_config':{'push_interval':5,'pull_interval':2}}
    f.user_sets[node]=[dict(f.USER,device_limit=0),f.OTHER]
    cfg={'panel':{'url':f'http://127.0.0.1:{api}','token':'synthetic-only-token','node_id':node,'node_type':protocol},'kernel':{'type':'xray','config_dir':str(runtime),'log_level':'warn','custom_route':[{'type':'field','ip':['127.0.0.1/32'],'outboundTag':'direct'}]},'cert':{'cert_mode':'none'},'node':{'push_interval':5,'pull_interval':2,'track_interval':1,'device_report_interval':5},'log':{'level':'info'},'health_port':0}
    path=runtime/'server.json';path.write_text(json.dumps(cfg));log=(runtime/'server.log').open('w');process=subprocess.Popen([a.binary,'-c',str(path)],stdout=log,stderr=log)
    try:
     deadline=time.monotonic()+30
     while not f.listening(port,'tcp') and time.monotonic()<deadline:assert process.poll() is None;time.sleep(.1)
     def start(user):
      http_port,socks_port=f.free_port(),f.free_port();account={'id':user['uuid'],'encryption':'none'} if protocol=='vless' else {'id':user['uuid'],'security':'auto'}
      client={'log':{'loglevel':'warning','access':'none'},'inbounds':[{'listen':'127.0.0.1','port':http_port,'protocol':'http','settings':{}},{'listen':'127.0.0.1','port':socks_port,'protocol':'socks','settings':{'udp':True,'auth':'noauth'}}],'outbounds':[{'protocol':protocol,'settings':{'vnext':[{'address':'127.0.0.1','port':port,'users':[account]}]},'mux':{'enabled':True,'concurrency':8,'xudpConcurrency':8,'xudpProxyUDP443':'allow'}}]}
      path=runtime/('client-'+str(user['id'])+'.json');path.write_text(json.dumps(client));clog=(runtime/('client-'+str(user['id'])+'.log')).open('w');proc=subprocess.Popen([a.client,'run','-config',str(path)],stdout=clog,stderr=clog);clients.append(proc)
      deadline=time.monotonic()+20
      while not f.listening(http_port,'tcp') and time.monotonic()<deadline:assert proc.poll() is None;time.sleep(.1)
      return http_port,socks_port
     proxy,socks=start(f.USER);valid,_=start(f.OTHER)
     _,data=f.proxy_request(proxy,api);assert b'synthetic_proxy_request' in data
     f.udp_target_request(socks,target)
     f.hold_release.clear()
     for _ in range(3):conn,_=f.proxy_request(proxy,api,'/hold',keep_open=True);conns.append(conn)
     kept,_=f.proxy_request(valid,api,'/hold',keep_open=True)
     try:
      f.user_sets[node]=[f.OTHER]
      for conn in conns:
       conn.settimeout(15)
       try:closed=conn.recv(8192)==b''
       except OSError:closed=True
       assert closed,'revoked multiplexed stream live'
      kept.settimeout(.3)
      try:assert kept.recv(8192)!=b'','valid multiplexed user kicked'
      except socket.timeout:pass
      _,data=f.proxy_request(valid,api);assert b'synthetic_proxy_request' in data
      try:f.udp_target_request(socks,target,timeout=3)
      except (OSError,AssertionError):pass
      else:raise AssertionError('revoked XUDP allowed')
      result={'protocol':protocol,'mux_tcp':True,'xudp_target':True,'three_streams_revoked':True,'other_user_kept':True,'revoked_xudp_rejected':True};results.append(result);print(json.dumps(result),flush=True)
     finally:f.hold_release.set();kept.close()
    except Exception:
     print((runtime/'server.log').read_text()[-5000:],flush=True)
     for path in runtime.glob('client-*.log'):print(path.read_text()[-3000:],flush=True)
     raise
    finally:
     f.hold_release.set()
     for conn in conns:conn.close()
     for proc in clients:f.stop(proc)
     f.stop(process)
 finally:udp.close();server.shutdown();server.server_close()
 print(json.dumps({'pass':len(results)==2,'results':results,'isolated':True}),flush=True)
if __name__=='__main__':main()
