import json,socket,sys
sys.path.insert(0,'/opt/microbox')
from microbox_fetch import fetch,FetchDenied
checks=[]
def denied(url,reason=None):
    try:fetch(url)
    except FetchDenied as e:
        if reason:assert str(e)==reason,(url,str(e),reason)
        checks.append(url)
    else:raise AssertionError('egress unexpectedly allowed '+url)
status,body=fetch('https://fetch.test/ok');assert status==200 and body==b'microbox-fixture';checks.append('allowed-tls')
for url in ['http://fetch.test/ok','https://fetch.test:8443/ok','https://not-allowed.test/ok','https://fetch.test.evil/ok','https://user:pass@fetch.test/ok','https://127.0.0.1/ok','https://fetch.test/#fragment']:
    denied(url,'url_not_authorized')
denied('https://private.test/ok','destination_not_public')
denied('https://mixed.test/ok','destination_not_public')
denied('https://wrong.test/ok','tls_or_network_failed')
denied('https://fetch.test/redirect','redirect_denied')
denied('https://fetch.test/large','response_too_large')
denied('https://fetch.test/slow')
# Unknown fields cannot smuggle methods or headers through the proxy API.
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
    s.connect('/.microbox-egress/fetch.sock');s.sendall(b'{"url":"https://fetch.test/ok","method":"POST"}\n')
    response=json.loads(s.recv(4096));assert response['outcome']=='denied' and response['reason']=='malformed_request'
checks.append('method-smuggling-denied')
# The grant never adds direct IPv4 connectivity.
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
try:s.connect(('93.184.216.34',443))
except OSError:checks.append('direct-ip-blocked')
else:raise AssertionError('proxy bypass succeeded')
finally:s.close()
print(json.dumps({'checks':len(checks),'egress':'passed'}))
