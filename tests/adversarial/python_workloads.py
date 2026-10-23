#!/usr/bin/env python3
import concurrent.futures,json,os,pathlib,subprocess,tempfile,uuid
repo=pathlib.Path(__file__).resolve().parents[2]
cli=repo/'target/release/microbox-cli';root=pathlib.Path(os.environ['MICROBOX_ROOTFS']).resolve();parent=pathlib.Path(os.environ['MICROBOX_CGROUP']).resolve()
with tempfile.TemporaryDirectory(prefix='microbox-python-') as tmp:
    def run(name,argv):
        audit=pathlib.Path(tmp)/(str(uuid.uuid4())+'.jsonl')
        c=dict(rootfs=str(root),helper=str(repo/'target/release/microbox-helper'),cgroup_parent=str(parent),audit_path=str(audit),argv=argv,memory_bytes=134217728,tmp_bytes=16777216,pids=64,cpu_quota_us=50000,timeout_ms=5000,output_limit_bytes=65536,deny_mode='kill')
        path=audit.with_suffix('.json');path.write_text(json.dumps(c))
        p=subprocess.run([str(cli),'run',str(path)],capture_output=True,text=True,timeout=15)
        assert p.returncode==0,(name,p.stdout,p.stderr)
        out=json.loads(p.stdout)
        if out['termination']=='seccomp':
            trace=pathlib.Path(tmp)/'failure.trace'
            c['audit_path']=str(pathlib.Path(tmp)/(str(uuid.uuid4())+'.jsonl'));path.write_text(json.dumps(c))
            subprocess.run(['strace','-f','-e','trace=!clock_nanosleep,wait4','-o',str(trace),str(cli),'run',str(path)],capture_output=True,text=True,timeout=20)
            lines=trace.read_text().splitlines()
            victims={line.split()[0] for line in lines if 'killed by SIGSYS' in line}
            for pid in victims:
                print('\n'.join(line for line in lines if line.split()[0]==pid)[-12000:],flush=True)
        assert out['termination']=='exited' and out['exit_code']==0,(name,out)
        subprocess.run([str(cli),'verify',str(audit),out['audit_root']],check=True,capture_output=True)
        print('PASS',name,flush=True)
        return out
    run('dynamic-ls',['/bin/ls','/'])
    run('shell',['/bin/sh','-c','test -d /proc && test -d /tmp'])
    run('python-subprocess',['/usr/bin/python3','-I','-c','import subprocess;subprocess.run(["/bin/ls","/"],check=True)'])
    run('python-cold-start',['/usr/bin/python3','-I','-c','pass'])
    run('python-standard-library',['/usr/bin/python3','-I','-c','import json,hashlib,sqlite3,socket,threading,os; assert os.getuid()==65534; assert sqlite3.connect(":memory:").execute("select 1").fetchone()==(1,); t=threading.Thread(target=lambda:None); t.start(); t.join(); print(hashlib.sha256(b"microbox").hexdigest())'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda n:run(f'concurrent-python-{n}',['/usr/bin/python3','-I','-c','import time; time.sleep(0.05)']),range(4)))
    assert not list(parent.glob('run-*'))
print('9 dynamic/Python/concurrent workload checks passed')
