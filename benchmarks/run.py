#!/usr/bin/env python3
"""Three explicit payload classes. Includes cold interpreter startup, no overhead subtraction."""
import json,os,pathlib,platform,subprocess,tempfile,uuid,statistics,time
base=pathlib.Path(__file__).resolve().parents[1]
classes={'static-native':['/bin/probe','true'],'dynamic-ls':['/bin/ls','/'],'python-cold':['/usr/bin/python3','-I','-c','pass']}
samples={}
with tempfile.TemporaryDirectory(prefix='microbox-bench-') as d:
    for label,argv in classes.items():
        rows=[]
        for _ in range(int(os.environ.get('MICROBOX_BENCH_RUNS','30'))):
            c=dict(rootfs=os.environ['MICROBOX_ROOTFS'],helper=str(base/'target/release/microbox-helper'),cgroup_parent=os.environ['MICROBOX_CGROUP'],audit_path=d+'/'+str(uuid.uuid4())+'.jsonl',argv=argv,memory_bytes=134217728,tmp_bytes=16777216,pids=64,cpu_quota_us=50000,timeout_ms=5000,output_limit_bytes=65536,deny_mode='kill')
            p=pathlib.Path(d)/'config.json';p.write_text(json.dumps(c))
            start=time.perf_counter_ns();r=subprocess.run([str(base/'target/release/microbox-cli'),'run',str(p)],capture_output=True,text=True,check=True);elapsed=(time.perf_counter_ns()-start)//1000
            o=json.loads(r.stdout);assert o['termination']=='exited' and o['exit_code']==0,o
            rows.append(dict(o['timings_us'],cli_end_to_end=elapsed))
        samples[label]=dict(argv=argv,samples_us=rows,summary_us={k:dict(median=statistics.median(r[k] for r in rows),maximum=max(r[k] for r in rows)) for k in rows[0]})
metadata=dict(schema=2,kernel=platform.release(),machine=platform.machine(),platform=platform.platform(),cpu=next((l.strip() for l in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),''),cgroup_parent=os.environ['MICROBOX_CGROUP'],runs_per_class=len(rows),timing_note='Parent-observed readiness includes helper launch, cgroup setup, IPC and polling; ready-to-helper-exit includes exec, workload and init reaping. Python startup is retained in its own class.',payloads=samples)
path=base/'results';path.mkdir(exist_ok=True);(path/'benchmark.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(json.dumps({k:v['summary_us'] for k,v in samples.items()},indent=2))
