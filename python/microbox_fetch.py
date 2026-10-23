"""Bounded HTTPS GET capability client. No network interface or TLS stack is needed in the sandbox."""
import json
import socket

class FetchDenied(RuntimeError):
    pass

def fetch(url, socket_path='/.microbox-egress/fetch.sock', timeout=10, max_response_bytes=1024*1024):
    if not 0 < max_response_bytes <= 1024*1024 or not 0 < timeout <= 60:
        raise ValueError('invalid response or deadline bound')
    if not isinstance(url, str) or len(url.encode())>4000:
        raise ValueError('URL exceeds request bound')
    request=json.dumps({'url':url},separators=(',',':')).encode()+b'\n'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(socket_path)
        stream.sendall(request)
        data=bytearray()
        while True:
            chunk=stream.recv(4096)
            if not chunk:
                raise FetchDenied('proxy_closed')
            data.extend(chunk)
            if len(data)>2*max_response_bytes+1024:
                raise FetchDenied('response_bound_exceeded')
            if b'\n' in data:
                break
    try:
        response=json.loads(data)
        if not isinstance(response,dict):
            raise ValueError('response must be an object')
        if response.get('outcome')!='fetched':
            reason=response.get('reason','invalid_response')
            raise FetchDenied(reason if isinstance(reason,str) else 'invalid_response')
        status=response['status']
        if type(status) is not int or not 100<=status<=599:
            raise ValueError('invalid status')
        body=bytes.fromhex(response['body_hex'])
    except (ValueError,TypeError,KeyError) as error:
        raise FetchDenied('invalid_response') from error
    if len(body)>max_response_bytes:
        raise FetchDenied('response_bound_exceeded')
    return status,body
