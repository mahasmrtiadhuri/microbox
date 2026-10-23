import json
import pathlib
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from microbox_fetch import FetchDenied, fetch

class ClientContract(unittest.TestCase):
    def exchange(self, reply, callback, limit=1024):
        with tempfile.TemporaryDirectory(prefix='microbox-client-') as directory:
            path=str(pathlib.Path(directory)/'fetch.sock')
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            errors=[]
            def server():
                try:
                    connection,_=listener.accept()
                    with connection:
                        request=connection.recv(4096)
                        self.assertEqual(json.loads(request),{'url':'https://example.com/'})
                        try:connection.sendall(reply)
                        except BrokenPipeError:pass
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=server,daemon=True)
            thread.start()
            try:callback(lambda:fetch('https://example.com/',socket_path=path,max_response_bytes=limit))
            finally:
                listener.close()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            if errors:raise errors[0]

    def test_fetch_frame_and_bytes(self):
        response=b'{"outcome":"fetched","status":200,"body_hex":"6869","peer_ip":"8.8.8.8"}\n'
        self.exchange(response,lambda call:self.assertEqual(call(),(200,b'hi')))

    def test_policy_denial_is_preserved(self):
        def check(call):
            with self.assertRaisesRegex(FetchDenied,'destination_not_public'):call()
        self.exchange(b'{"outcome":"denied","reason":"destination_not_public"}\n',check)

    def test_malformed_response_fails_closed(self):
        def check(call):
            with self.assertRaisesRegex(FetchDenied,'invalid_response'):call()
        self.exchange(b'{"outcome":"fetched","status":true,"body_hex":"zz"}\n',check)

    def test_response_is_bounded(self):
        def check(call):
            with self.assertRaisesRegex(FetchDenied,'response_bound_exceeded'):call()
        self.exchange(b'x'*4096+b'\n',check,limit=16)

if __name__=='__main__':
    unittest.main()
