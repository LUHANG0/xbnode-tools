#!/usr/bin/env python3
"""One controlled upgrade for the existing, manually deployed node 36.

Never used by xbnode update. No panel writes, credential printing, identity
creation, service replacement, XrayR enablement, or old-file cleanup.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request

UNIT='xboard-node-36.service'
BINARY=Path('/usr/local/bin/xboard-node-36')
CONFIG=Path('/etc/xboard-node-36')
SERVICE=Path('/etc/systemd/system')/UNIT
DROPINS=Path(str(SERVICE)+'.d')
OLD='56fe0307c87c46b042e919a012908fcee0dfc2ac5b4d43c73604a0f2d0a3dbde'
PORT=30000

def run(*args,check=True,timeout=30):
    r=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and r.returncode:raise RuntimeError('command failed: '+args[0])
    return r.stdout.strip()
def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def tree_state():
    result={}
    for p in [SERVICE,*sorted(CONFIG.rglob('*')),*sorted(DROPINS.rglob('*'))]:
        if p.is_symlink():raise RuntimeError('unexpected configuration symlink')
        if p.is_file():
            st=p.stat();result[str(p)]={'sha256':digest(p),'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
    if str(SERVICE) not in result or str(CONFIG/'credentials.env') not in result:raise RuntimeError('expected configuration missing')
    return result

def properties():
    raw=run('systemctl','show',UNIT,'--property=MainPID,ActiveState,SubState,NRestarts,DynamicUser,User,MemoryCurrent')
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
def journal(pid,since):
    rows=[]
    for line in run('journalctl','-u',UNIT,'--since','@'+str(int(since)),'-o','json','--no-pager',check=False).splitlines():
        try:
            row=json.loads(line)
            if str(row.get('_PID'))==str(pid):rows.append(str(row.get('MESSAGE','')))
        except (ValueError,TypeError):pass
    return rows

def health(expected,since,required_pid=None,hash_binary=True):
    props=properties();pid=int(props.get('MainPID','0'));assert props.get('ActiveState')=='active' and props.get('SubState')=='running' and pid>0,'service inactive'
    assert props.get('DynamicUser')=='yes' and props.get('User')!='root','non-root service contract changed'
    if required_pid is not None:assert pid==required_pid,'unexpected process restart'
    # Type=simple may announce MainPID while systemd's privileged executor is
    # still preparing its sandbox. Wait for exec before checking program UID;
    # an actual node program running as root remains a fatal contract failure.
    if os.readlink(f'/proc/{pid}/exe')!=str(BINARY):
        raise RuntimeError('program exec pending')
    status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line}
    uid=int(status['Uid'].split()[0]);assert uid!=0,'process is root'
    if hash_binary:assert digest(f'/proc/{pid}/exe')==expected,'running program hash mismatch'
    sockets=run('ss','-H','-lntup');own=[line for line in sockets.splitlines() if 'pid='+str(pid)+',' in line]
    assert any(line.split()[0]=='tcp' and line.split()[4].endswith(':'+str(PORT)) for line in own),'owned TCP listener missing'
    # The known service exposes exactly one TCP listener; no health/pprof port.
    assert len(own)==1,'unexpected extra listener'
    messages=journal(pid,since)
    assert not any(re.search(r'panic:|\bFATAL\b|failed to start kernel|invalid config|address already in use',line,re.I) for line in messages),'fatal/startup journal entry'
    users=[]
    for line in messages:
        m=re.search(r'(?:initial snapshot ready|xray started|sing-box started).*?users=(\d+)|started, (\d+) users',line)
        if m:users.append(int(next(x for x in m.groups() if x is not None)))
    assert users and users[-1]>0,'user load unconfirmed'
    reports=[]
    for line in messages:
        m=re.search(r'report pushed: (\d+) users, (\d+) online',line)
        if m:reports.append([int(m[1]),int(m[2])])
    pss=None
    try:
        for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
            if line.startswith('Pss:'):pss=int(line.split()[1])*1024
    except OSError:pass
    return {'pid':pid,'uid':uid,'loaded_users':users[-1],'restarts':int(props.get('NRestarts','0')),
            'rss_bytes':int(status['VmRSS'].split()[0])*1024,'pss_bytes':pss,'cgroup_memory_bytes':int(props.get('MemoryCurrent','0')),
            'fds':sum(1 for _ in Path(f'/proc/{pid}/fd').iterdir()),'reports':len(reports),'last_report_counts':reports[-1] if reports else None}

def atomic_program(source,destination):
    destination=Path(destination);fd,name=tempfile.mkstemp(prefix='.node36-upgrade-',dir=destination.parent)
    try:
        with os.fdopen(fd,'wb') as stream,Path(source).open('rb') as incoming:shutil.copyfileobj(incoming,stream);stream.flush();os.fsync(stream.fileno())
        os.chmod(name,0o755);os.chown(name,0,0);os.replace(name,destination)
    finally:
        if os.path.exists(name):os.unlink(name)

def backup(folder,baseline):
    archive=folder/'rollback.tar.gz'
    with tarfile.open(archive,'w:gz',dereference=False) as tar:
        for p in (BINARY,SERVICE,CONFIG,DROPINS):
            if p.exists():tar.add(p,arcname=str(p).lstrip('/'))
    os.chmod(archive,0o600)
    with tarfile.open(archive,'r:gz') as tar:
        for name,info in baseline.items():
            member=tar.getmember(name.lstrip('/'));assert member.isfile() and member.mode==info['mode'] and member.uid==info['uid'] and member.gid==info['gid']
            assert hashlib.sha256(tar.extractfile(member).read()).hexdigest()==info['sha256'],'backup content verification failed'
    old=folder/'rollback-program'
    with tarfile.open(archive,'r:gz') as tar:
        old.write_bytes(tar.extractfile(str(BINARY).lstrip('/')).read())
    old.chmod(0o700);assert digest(old)==OLD
    return archive,old

def main():
    p=argparse.ArgumentParser();p.add_argument('--folder',type=Path,required=True);p.add_argument('--release',required=True);p.add_argument('--sha256',required=True);p.add_argument('--version',required=True);p.add_argument('--client',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--observe-seconds',type=int,default=600);p.add_argument('--apply',action='store_true');a=p.parse_args()
    if not __debug__:raise RuntimeError('optimized Python execution is not supported')
    assert os.geteuid()==0 and re.fullmatch(r'v\d+\.\d+\.\d+',a.release) and re.fullmatch(r'[a-f0-9]{64}',a.sha256)
    assert a.observe_seconds>=600,'observation window must be at least ten minutes'
    assert digest(BINARY)==OLD,'production baseline changed; inspect before continuing'
    assert run(str(BINARY),'-v').startswith('xboard-node v1.13-maint-20261022 '),'old version differs'
    assert run('systemctl','is-active','XrayR.service',check=False)!='active','old XrayR unexpectedly active'
    assert run('systemctl','is-enabled','XrayR.service',check=False) in ('disabled','masked'),'old XrayR enablement differs'
    assert run('systemctl','is-enabled',UNIT)=='enabled','node service enablement differs'
    original=tree_state();props=properties();assert props.get('ActiveState')=='active' and props.get('SubState')=='running'
    assert not BINARY.is_symlink() and digest('/proc/'+props['MainPID']+'/exe')==OLD,'running baseline differs'
    if not a.apply:
        print(json.dumps({'preview':True,'service':UNIT,'old_sha256':OLD,'new_sha256':a.sha256,'release':a.release,'config_files':len(original),'observe_seconds':a.observe_seconds}));return
    lock=open('/run/lock/xboard-node-36-upgrade.lock','a+');os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    os.umask(0o077);a.folder.mkdir(mode=0o700,parents=False,exist_ok=False)
    archive,old=backup(a.folder,original)
    (a.folder/'baseline-private.json').write_text(json.dumps(original,indent=2))
    candidate=a.folder/'candidate-amd64';url=f'https://github.com/LUHANG0/xbnode-tools/releases/download/{a.release}/xboard-node-linux-amd64'
    with urllib.request.urlopen(url,timeout=90) as incoming,candidate.open('wb') as out:shutil.copyfileobj(incoming,out)
    assert digest(candidate)==a.sha256,'release download hash mismatch';candidate.chmod(0o700)
    assert run(str(candidate),'-v').startswith('xboard-node '+a.version+' '),'candidate version mismatch'
    # Existing synthetic client and public fixture only, inside a fresh network
    # namespace with no route to the production panel or client network.
    shutil.copyfile(a.client,a.folder/'xray-test-client');(a.folder/'xray-test-client').chmod(0o700)
    env=dict(os.environ,NODE_PROBE_ROOT=str(a.folder),NODE_PROBE_BINARY=candidate.name,NODE_PROBE_REALITY='1')
    command=['unshare','--net','--','python3',str(a.fixture)]
    test=subprocess.run(command,text=True,capture_output=True,timeout=150,env=env)
    (a.folder/'isolated-compat.log').write_text(test.stdout+test.stderr)
    assert test.returncode==0,'isolated REALITY/Vision process failed'
    compatibility=json.loads(test.stdout.strip().splitlines()[-1]);assert compatibility.get('pass') is True and compatibility.get('reality_vision') is True,'isolated REALITY/Vision compatibility failed'
    assert tree_state()==original and digest(BINARY)==OLD,'production changed during preflight'
    replaced=False;switched=time.time();result={'service':UNIT,'release':a.release,'version':a.version,'sha256':a.sha256,'backup':str(archive),'backup_verified':True,'isolated_compat':True,'samples':[]}
    def save(): (a.folder/'result.json').write_text(json.dumps(result,indent=2))
    try:
        atomic_program(candidate,BINARY);replaced=True;run('systemctl','restart',UNIT,timeout=60)
        deadline=time.monotonic()+45
        while True:
            try:initial=health(a.sha256,switched);break
            except (AssertionError,OSError,RuntimeError) as error:
                fatal=('fatal/startup journal entry','non-root service contract changed','process is root','unexpected extra listener','running program hash mismatch')
                state=properties()
                if str(error) in fatal or state.get('ActiveState')=='failed' or int(state.get('NRestarts','0'))>0:raise
                if time.monotonic()>=deadline:raise
                time.sleep(1)
        assert initial['restarts']==0,'startup restarted unexpectedly'
        result['switch_seconds']=round(time.time()-switched,3);result['initial']=initial;save();print(json.dumps({'switched':True,'pid':initial['pid'],'switch_seconds':result['switch_seconds']}),flush=True)
        started=time.monotonic()
        while time.monotonic()-started<a.observe_seconds:
            sample=health(a.sha256,switched,initial['pid'],hash_binary=False);assert tree_state()==original,'configuration changed';assert sample['restarts']==initial['restarts'],'unexpected service restart'
            sample['elapsed']=round(time.monotonic()-started,2);result['samples'].append(sample);save()
            if len(result['samples'])%4==0:print(json.dumps({'observed_seconds':sample['elapsed'],'rss_bytes':sample['rss_bytes'],'reports':sample['reports'],'last_report_counts':sample['last_report_counts']}),flush=True)
            time.sleep(15)
        result['final']=health(a.sha256,switched,initial['pid']);assert result['final']['reports']>=1,'no successful periodic REST report observed';assert tree_state()==original
        assert run('systemctl','is-active','XrayR.service',check=False)!='active';assert run('systemctl','is-enabled','XrayR.service',check=False) in ('disabled','masked')
        result['complete']=True;result['pass']=True;result['config_service_unchanged']=True;save();print(json.dumps({'complete':True,'pass':True,'result':str(a.folder/'result.json'),'final':result['final']}),flush=True)
    except BaseException as error:
        if replaced:
            atomic_program(old,BINARY);rollback=time.time();run('systemctl','restart',UNIT,timeout=60)
            deadline=time.monotonic()+45
            while True:
                try:restored=health(OLD,rollback);break
                except (AssertionError,OSError,RuntimeError):
                    if time.monotonic()>=deadline:raise RuntimeError('rollback requires attention; files preserved') from None
                    time.sleep(1)
            result.update({'pass':False,'rolled_back':True,'rollback_verified':True,'rollback_state':restored,'error_type':type(error).__name__});save();print(json.dumps({'pass':False,'rolled_back':True,'result':str(a.folder/'result.json')}),flush=True)
        raise
if __name__=='__main__':main()
