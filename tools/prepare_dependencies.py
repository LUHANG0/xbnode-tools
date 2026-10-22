#!/usr/bin/env python3
"""Copy pinned dependencies and apply reviewed replacements without cache edits.

The exported archive includes these complete modified dependency sources and a
relative maintenance.mod; build with go build -modfile=maintenance.mod.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def prepare(source, go='go', patch_root=None):
    source=Path(source).resolve();patch_root=Path(patch_root).resolve()
    entries=json.loads((patch_root/'lock.json').read_text());modules={};destinations={}
    original_files={name:(source/name).read_bytes() for name in ('go.mod','go.sum')}
    target=source/'maintenance-dependencies';target.mkdir(exist_ok=True)
    for e in entries:
        if e['module'] not in modules:
            module=json.loads(subprocess.check_output([go,'list','-m','-json',e['module']],cwd=source,text=True));actual=module.get('Replace',module)
            if actual['Version']!=e['version']:raise RuntimeError('Unexpected module version: '+e['module'])
            if not actual.get('Dir'):
                downloaded=json.loads(subprocess.check_output([go,'mod','download','-json',actual['Path']+'@'+actual['Version']],cwd=source,text=True))
                if downloaded.get('Error') or not downloaded.get('Dir'):raise RuntimeError('Pinned dependency download failed: '+e['module'])
                actual=dict(actual,Dir=downloaded['Dir'])
            destination=target/e['file'].split('/')[0]
            shutil.copytree(actual['Dir'],destination)
            for path in destination.rglob('*'):
                if path.is_dir():path.chmod(0o755)
                elif path.is_file():path.chmod(0o644)
            destination.chmod(0o755)
            modules[e['module']]=actual;destinations[e['module']]=destination
        original=Path(modules[e['module']]['Dir'])/e['path']
        if e['base_sha256'] is None:
            if original.exists():raise RuntimeError('New test path already exists: '+e['path'])
        elif hashlib.sha256(original.read_bytes()).hexdigest()!=e['base_sha256']:raise RuntimeError('Dependency source mismatch: '+e['path'])
        shutil.copyfile(patch_root/e['file'],destinations[e['module']]/e['path'])
    for name,content in original_files.items():
        if (source/name).read_bytes()!=content:raise RuntimeError('Original dependency lock changed: '+name)
    for name in ('mod','sum'):shutil.copyfile(source/('go.'+name),source/('maintenance.'+name))
    for module,destination in destinations.items():
        subprocess.run([go,'mod','edit','-modfile=maintenance.mod','-replace='+module+'=./'+str(destination.relative_to(source))],cwd=source,check=True)
    (target/'PATCHES.json').write_text(json.dumps(entries,indent=2)+'\n')
    return source/'maintenance.mod'
