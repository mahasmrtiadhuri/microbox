#!/usr/bin/env python3
"""Raw measurements; no comparison or sub-millisecond claim."""
import json,os,pathlib,platform,subprocess,tempfile,uuid,statistics,time
base=pathlib.Path(__file__).resolve().parents[1]
rows=[]
with tempfile.TemporaryDirectory(prefix='microbox-bench-') as d:
    for _ in range(int(os.environ.get('MICROBOX_BENCH_RUNS','30'))):
        c=dict(rootfs=os.environ['MICROBOX_ROOTFS'],helper=str(base/'target/release/microbox-helper'),cgroup_parent=os.environ['MICROBOX_CGROUP'],audit_path=d+'/'+str(uuid.uuid4())+'.jsonl',argv=['/bin/probe','true'],memory_bytes=33554432,tmp_bytes=1048576,pids=24,cpu_quota_us=50000,timeout_ms=2000,output_limit_bytes=4096,deny_mode='kill')
        p=pathlib.Path(d)/'config.json';p.write_text(json.dumps(c))
        start=time.perf_counter_ns();r=subprocess.run([str(base/'target/release/microbox-cli'),'run',str(p)],capture_output=True,text=True,check=True);elapsed=(time.perf_counter_ns()-start)//1000
        o=json.loads(r.stdout);assert o['termination']=='exited' and o['exit_code']==0,o
        rows.append(dict(o['timings_us'],cli_end_to_end=elapsed))
metadata=dict(kernel=platform.release(),machine=platform.machine(),platform=platform.platform(),cpu=next((l.strip() for l in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),''),cgroup_parent=os.environ['MICROBOX_CGROUP'],runs=len(rows),payload='static C probe true',timing_note='Parent-observed readiness includes helper launch, cgroup setup, IPC and poll scheduling. Ready-to-helper-exit includes exec and init reaping; not exact execve timing.',samples_us=rows)
path=base/'results';path.mkdir(exist_ok=True);(path/'benchmark.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(json.dumps({k:dict(median=statistics.median(r[k] for r in rows),maximum=max(r[k] for r in rows)) for k in rows[0]},indent=2))
