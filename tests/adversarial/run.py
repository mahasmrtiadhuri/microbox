#!/usr/bin/env python3
"""Real kernel integration tests. Never skip or emulate unavailable prerequisites."""
import json, os, pathlib, subprocess, tempfile, uuid
base=pathlib.Path(__file__).resolve().parents[2]
cli=base/'target/release/microbox-cli'
helper=base/'target/release/microbox-helper'
root=pathlib.Path(os.environ['MICROBOX_ROOTFS']).resolve()
parent=pathlib.Path(os.environ['MICROBOX_CGROUP']).resolve()
results=[]
with tempfile.TemporaryDirectory(prefix='microbox-adversarial-') as work:
    work=pathlib.Path(work)
    def config(mode,deny='kill',**kw):
        c=dict(rootfs=str(root),helper=str(helper),cgroup_parent=str(parent),audit_path=str(work/(str(uuid.uuid4())+'.jsonl')),argv=['/bin/probe',mode],memory_bytes=33554432,tmp_bytes=1048576,pids=24,cpu_quota_us=50000,timeout_ms=2000,output_limit_bytes=16384,deny_mode=deny)
        c.update(kw)
        path=work/(str(uuid.uuid4())+'.json');path.write_text(json.dumps(c));return path,c
    def run(mode,deny='kill',**kw):
        path,c=config(mode,deny,**kw)
        r=subprocess.run([str(cli),'run',str(path)],capture_output=True,text=True,timeout=15)
        assert r.returncode==0,(mode,r.stdout,r.stderr)
        out=json.loads(r.stdout)
        assert out['cleanup_complete'] and not list(parent.glob('run-*')),out
        subprocess.run([str(cli),'verify',c['audit_path'],out['audit_root']],check=True,capture_output=True)
        assert out['setup_ready'],out
        return out,c
    def passed(name,out):
        results.append(dict(test=name,outcome=out));print('PASS',name,flush=True)
    for mode in ['true','pid','fds','net','fs','tmp']:
        out,_=run(mode);assert out['termination']=='exited' and out['exit_code']==0,out
        passed(mode,out)
    for mode in ['ptrace','unshare']:
        out,_=run(mode);assert out['termination']=='seccomp' and out['signal']==31,out
        passed(mode+'-kill',out)
        out,_=run(mode,deny='errno');assert out['termination']=='exited' and out['exit_code']==0,out
        passed(mode+'-errno',out)
    out,_=run('fork',timeout_ms=500)
    assert out['termination']=='timeout' and out['resources']['pids_events']['max']>0,out
    passed('pids_max',out)
    out,_=run('oom');assert out['termination']=='killed_by_oom' and out['resources']['memory_events']['oom_kill']>0,out
    passed('oom',out)
    out,_=run('output');assert out['termination']=='output_limit',out
    assert len(out['stdout']['prefix_hex'])<=32768,out
    passed('bounded-output',out)
    path,c=config('sleep')
    r=subprocess.run([str(cli),'cancel-test',str(path)],capture_output=True,text=True,timeout=15)
    assert r.returncode==0,(r.stdout,r.stderr)
    passed('async-cancellation',json.loads(r.stdout))
    path,c=config('true',argv=['/bin/missing'])
    r=subprocess.run([str(cli),'run',str(path)],capture_output=True,text=True,timeout=15)
    assert r.returncode==0 and json.loads(r.stdout)['termination']=='exec_failed',(r.stdout,r.stderr)
    passed('exec-failure',json.loads(r.stdout))
    path,c=config('true',cgroup_parent=str(work))
    r=subprocess.run([str(cli),'run',str(path)],capture_output=True,text=True,timeout=15)
    assert r.returncode!=0 and 'MissingCgroupV2' in r.stderr,(r.stdout,r.stderr)
    passed('fail-closed-preflight',{'rejected':True})
    logs=base/'results';logs.mkdir(exist_ok=True)
    (logs/'adversarial.json').write_text(json.dumps(results,indent=2)+'\n')
print(f'{len(results)} real-kernel adversarial checks passed')
