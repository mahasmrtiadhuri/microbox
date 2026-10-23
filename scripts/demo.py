#!/usr/bin/env python3
"""Run a Python workload and independently verify its audit root."""
import argparse,json,pathlib,subprocess,uuid
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--rootfs',required=True,type=pathlib.Path)
p.add_argument('--cgroup',required=True,type=pathlib.Path)
p.add_argument('--output',required=True,type=pathlib.Path)
a=p.parse_args();repo=pathlib.Path(__file__).resolve().parents[1]
a.output.mkdir(parents=True,exist_ok=True)
config=dict(rootfs=str(a.rootfs.resolve()),helper=str((repo/'target/release/microbox-helper').resolve()),cgroup_parent=str(a.cgroup.resolve()),audit_path=str(a.output.resolve()/f'{uuid.uuid4()}.jsonl'),argv=['/usr/bin/python3','-I','-c','import json,os; print(json.dumps({"sandbox_uid":os.getuid(),"answer":sum(range(1000))}))'],memory_bytes=134217728,tmp_bytes=16777216,pids=64,cpu_quota_us=50000,timeout_ms=5000,output_limit_bytes=65536,deny_mode='kill')
path=a.output/'demo-config.json';path.write_text(json.dumps(config,indent=2)+'\n')
cli=str(repo/'target/release/microbox-cli')
r=subprocess.run([cli,'run',str(path)],check=True,capture_output=True,text=True)
out=json.loads(r.stdout)
subprocess.run([cli,'verify',config['audit_path'],out['audit_root']],check=True)
print(bytes.fromhex(out['stdout']['prefix_hex']).decode(),end='')
print(json.dumps(out,indent=2))
if out['termination']!='exited' or out['exit_code']!=0:raise SystemExit(1)
