#!/usr/bin/env python3
"""Offline TLS integration in a disposable private network and mount namespace."""
import http.server,json,os,pathlib,signal,socket,ssl,subprocess,tempfile,threading,time,uuid
repo=pathlib.Path(__file__).resolve().parents[2]
root=pathlib.Path(os.environ['MICROBOX_ROOTFS']).resolve()
cgroup=pathlib.Path(os.environ['MICROBOX_CGROUP']).resolve()
cli=repo/'target/release/microbox-cli';egress=repo/'target/release/microbox-egress'
checks=[];requests=[];proxies=[]
def checked(command,**kw):return subprocess.run(command,check=True,capture_output=True,text=True,**kw)
# This process is launched by unshare --net --mount; neither address nor hosts file affects the host.
checked(['ip','addr','add','93.184.216.34/32','dev','lo']);checked(['ip','link','set','lo','up'])
with tempfile.TemporaryDirectory(prefix='microbox-egress-') as temp:
    work=pathlib.Path(temp);os.chmod(work,0o755)
    hosts=work/'hosts';hosts.write_text('127.0.0.1 localhost private.test\n93.184.216.34 mixed.test\n127.0.0.1 mixed.test\n')
    checked(['mount','--bind',str(hosts),'/etc/hosts'])
    checked(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(work/'ca.key'),'-out',str(work/'ca.pem'),'-days','1','-subj','/CN=microbox disposable fixture CA','-addext','basicConstraints=critical,CA:TRUE'])
    checked(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(work/'server.key'),'-out',str(work/'server.csr'),'-subj','/CN=fetch.test'])
    ext=work/'extensions';ext.write_text('subjectAltName=DNS:fetch.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    checked(['openssl','x509','-req','-in',str(work/'server.csr'),'-CA',str(work/'ca.pem'),'-CAkey',str(work/'ca.key'),'-CAcreateserial','-out',str(work/'server.pem'),'-days','1','-extfile',str(ext)])
    for p in [work/'ca.pem',work/'server.pem']:os.chmod(p,0o644)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_GET(self):
            requests.append(self.path)
            if self.path=='/slow':time.sleep(1)
            body=b'X'*8192 if self.path=='/large' else b'microbox-fixture'
            self.send_response(302 if self.path=='/redirect' else 200)
            if self.path=='/redirect':self.send_header('Location','https://private.test/never')
            self.send_header('Content-Length',str(len(body)));self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
    server=http.server.ThreadingHTTPServer(('93.184.216.34',443),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(work/'server.pem',work/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    def proxy(name,ca=True,max_requests=64):
        private=work/name;private.mkdir(mode=0o700);os.chown(private,65533,65533)
        policy=dict(socket=str(private/'fetch.sock'),audit_path=str(private/'audit.jsonl'),allowed_hosts=['fetch.test','wrong.test','private.test','mixed.test'],dns_pins={'fetch.test':['93.184.216.34'],'wrong.test':['93.184.216.34']},additional_ca_pem=str(work/'ca.pem') if ca else None,max_response_bytes=1024,max_requests=max_requests,concurrency=4,timeout_ms=500)
        path=work/(name+'.json');path.write_text(json.dumps(policy));os.chmod(path,0o644)
        # A dedicated unprivileged identity runs the entire proxy; the sandbox uses UID 65534.
        env=dict(os.environ,HTTPS_PROXY='http://127.0.0.1:9',ALL_PROXY='http://127.0.0.1:9')
        p=subprocess.Popen(['setpriv','--reuid=65533','--regid=65533','--clear-groups',str(egress),'serve',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        proxies.append((p,policy))
        deadline=time.monotonic()+10
        while not pathlib.Path(policy['socket']).is_socket():
            if p.poll() is not None:raise AssertionError(p.communicate())
            if time.monotonic()>deadline:raise AssertionError('proxy readiness timeout')
            time.sleep(.01)
        return p,policy
    def run(code,policy=None,network=None):
        audit=work/(str(uuid.uuid4())+'.jsonl')
        cfg=dict(rootfs=str(root),helper=str(repo/'target/release/microbox-helper'),cgroup_parent=str(cgroup),audit_path=str(audit),argv=['/usr/bin/python3','-I','-c',code],memory_bytes=134217728,tmp_bytes=16777216,pids=64,cpu_quota_us=50000,timeout_ms=10000,output_limit_bytes=65536,deny_mode='kill')
        if policy:cfg['network']=dict(mode='https_fetch',socket=policy['socket'])
        if network:cfg['network']=network
        path=work/(str(uuid.uuid4())+'.json');path.write_text(json.dumps(cfg))
        result=subprocess.run([str(cli),'run',str(path)],capture_output=True,text=True,timeout=20)
        assert result.returncode==0,(result.stdout,result.stderr)
        out=json.loads(result.stdout)
        assert out['termination']=='exited' and out['exit_code']==0,(out,bytes.fromhex(out['stderr']['prefix_hex']))
        checked([str(cli),'verify',str(audit),out['audit_root']])
        assert not list(cgroup.glob('run-*'))
        return out
    def finish(p,policy):
        if p.poll() is None:p.send_signal(signal.SIGTERM)
        out,err=p.communicate(timeout=10)
        assert p.returncode==0,(out,err)
        records=[json.loads(line) for line in out.splitlines()]
        anchor=records[-1]['audit_root'];checked([str(cli),'verify',policy['audit_path'],anchor])
        assert not pathlib.Path(policy['socket']).exists()
        return anchor
    try:
        p,policy=proxy('grant')
        payload=(repo/'tests/egress/payload.py').read_text()
        result=run(payload,policy)
        details=json.loads(bytes.fromhex(result['stdout']['prefix_hex']))
        assert details['checks']==16,details
        checks.extend(['https-capability-'+str(n) for n in range(details['checks'])])
        anchor=finish(p,policy)
        assert '/never' not in requests,requests
        checks.append('redirect-target-not-contacted')
        p,policy=proxy('untrusted-ca',ca=False)
        code="import sys;sys.path.insert(0,'/opt/microbox');from microbox_fetch import fetch,FetchDenied\ntry:fetch('https://fetch.test/ok')\nexcept FetchDenied as e:assert str(e)=='tls_or_network_failed',str(e)\nelse:raise AssertionError('untrusted CA accepted')"
        run(code,policy);finish(p,policy);checks.append('untrusted-ca-rejected')
        run("import socket\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ntry:s.connect('/.microbox-egress/fetch.sock')\nexcept OSError:pass\nelse:raise AssertionError('ungranted capability reachable')")
        checks.append('airgap-has-no-proxy-grant')
        p,policy=proxy('quota',max_requests=2)
        for _ in range(2):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.connect(policy['socket']);s.sendall(b'{"url":"http://fetch.test"}\n');assert json.loads(s.recv(4096))['outcome']=='denied'
        p.wait(timeout=5);finish(p,policy);checks.append('session-request-budget-enforced')
        output=repo/'results';output.mkdir(exist_ok=True)
        (output/'egress.json').write_text(json.dumps(dict(checks=checks,requests_seen=requests,audit_root=anchor),indent=2)+'\n')
        for name in checks:print('PASS',name,flush=True)
        print(f'{len(checks)} HTTPS capability checks passed')
    finally:
        for p,policy in proxies:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        server.shutdown();server.server_close()
