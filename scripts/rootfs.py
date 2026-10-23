#!/usr/bin/env python3
"""Snapshot explicitly trusted host tools and their runtime dependencies into a new rootfs."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('destination',type=pathlib.Path)
parser.add_argument('--python',default='/usr/bin/python3')
parser.add_argument('--tool',action='append',default=['/bin/ls','/bin/sh'])
args=parser.parse_args()
if os.geteuid()!=0:
    parser.error('run as root on a disposable Linux host; no setuid installation is performed')
root=args.destination.absolute()
if root.exists():
    parser.error('destination must not already exist')
root.mkdir(mode=0o755)
for name in ['bin','etc','tmp','proc','dev','sys','.microbox-old','.microbox-egress','opt/microbox']:
    (root/name).mkdir(parents=True,exist_ok=True,mode=0o755)
(root/'.microbox-egress/fetch.sock').touch(mode=0o644)
seen=set()
def copy_file(source,target=None):
    source=pathlib.Path(source)
    target=root/str(target or source).lstrip('/')
    if str(target) in seen:return
    seen.add(str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target,follow_symlinks=True)
    os.chmod(target,0o755 if os.access(source,os.X_OK) else 0o644)
def libraries(binary):
    r=subprocess.run(['ldd',str(binary)],capture_output=True,text=True)
    if 'not found' in r.stdout:raise RuntimeError(r.stdout)
    if r.returncode and 'not a dynamic executable' not in r.stderr+r.stdout and 'statically linked' not in r.stderr+r.stdout:raise RuntimeError(r.stderr)
    for text in re.findall(r'(?:=>\s*)?(/[^\s()]+)',r.stdout):copy_file(text)
python=pathlib.Path(args.python).absolute()
info=json.loads(subprocess.check_output([str(python),'-I','-c','import json,sysconfig;print(json.dumps({"stdlib":sysconfig.get_path("stdlib")}))'],text=True))
copy_file(python,'/usr/bin/python3');libraries(python)
stdlib=pathlib.Path(info['stdlib'])
# Trusted distribution standard library only; no application/site packages or writable host paths.
shutil.copytree(stdlib,root/str(stdlib).lstrip('/'),symlinks=False,ignore=shutil.ignore_patterns('__pycache__','site-packages','dist-packages','test','tests','ensurepip'))
for so in (root/str(stdlib).lstrip('/')).rglob('*.so'):
    libraries(so)
for tool in args.tool:
    p=pathlib.Path(tool)
    if not p.is_absolute():raise ValueError('tool paths must be absolute')
    copy_file(p);libraries(p)
repo=pathlib.Path(__file__).resolve().parents[1]
copy_file(repo/'python/microbox_fetch.py','/opt/microbox/microbox_fetch.py')
for p in root.rglob('*'):
    if p.is_dir():os.chmod(p,0o755)
    elif p.is_file():os.chmod(p,0o755 if p.stat().st_mode&0o111 else 0o644)
records=[]
for p in sorted(root.rglob('*')):
    if p.is_file():records.append(dict(path='/'+str(p.relative_to(root)),bytes=p.stat().st_size,mode=oct(p.stat().st_mode&0o777),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
manifest=dict(schema=1,source_python=str(python.resolve()),files=records)
encoded=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
(root/'microbox-rootfs.json').write_text(json.dumps(dict(manifest,manifest_sha256=hashlib.sha256(encoded).hexdigest()),indent=2)+'\n')
print(json.dumps(dict(rootfs=str(root),files=len(records),manifest_sha256=hashlib.sha256(encoded).hexdigest())))
