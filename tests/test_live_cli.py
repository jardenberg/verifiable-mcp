"""Exercise both shipped CLIs against a loopback MCP fixture, never production."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / 'test-vectors/v0.2.1.json').read_text())
KEY = 'org.jardenberg/verifiable-mcp'
PRIVATE = VECTORS['test_jwk_private']  # Published fixture key, never a production key.
private_key = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(PRIVATE['d'] + '='))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def signed(payload, text):
    digest = lambda value: 'sha256:' + hashlib.sha256(value).hexdigest()
    wrapper = {'iat': 1787308800, 'payload': payload,
               'payload_digest': digest(rfc8785.dumps(payload)),
               'content_digest': digest(text.encode()),
               'provenance': {'server_operator': 'TEST', 'canonical_origin': 'https://example.test',
                              'dataset_version': 'fixture', 'last_updated': '2026-09-28', 'rights': 'Test data'}}
    header = {'alg': 'EdDSA', 'typ': 'verifiable-mcp+jws', 'kid': PRIVATE['kid']}
    message = b64(rfc8785.dumps(header)) + '.' + b64(rfc8785.dumps(wrapper))
    return {'spec': '0.2.1', 'jws': message + '.' + b64(private_key.sign(message.encode()))}


def response(case):
    text = 'Fixture prose: å, 😀, and 0.1'
    payload = {'value': 0.1, 'text': 'different structured data', '\U0001f600': 1, '\ue000': 2}
    result = {'content': [{'type': 'text', 'text': text}], 'structuredContent': payload,
              '_meta': {KEY: signed(payload, text)}}
    msg = {'jsonrpc': '2.0', 'id': 1, 'result': result}
    if case in ('rpc-error', 'tampered-error', 'error-id', 'http-error'):
        error = {'code': -32602, 'message': 'Fixture rejected input'}
        envelope = signed({'id': 1, 'error': error}, '')
        msg = {'jsonrpc': '2.0', 'id': 1, 'error': {**error, 'data': {KEY: envelope}}}
        if case == 'tampered-error': msg['error']['message'] = 'UNSIGNED replacement'
        if case == 'error-id': msg['id'] = 2
    elif case == 'tool-error':
        result = {'isError': True, 'content': [{'type': 'text', 'text': text}],
                  '_meta': {KEY: signed({'isError': True, 'message': text}, text)}}
        msg['result'] = result
    elif case == 'tampered-payload': result['structuredContent'] = {'value': 999}
    elif case == 'tampered-text': result['content'][0]['text'] += ' altered'
    elif case == 'missing-structured': del result['structuredContent']
    elif case == 'missing-text': del result['content']
    elif case == 'wrong-id': msg['id'] = 2
    elif case == 'both-result-error': msg['error'] = {'code': -1, 'message': 'ambiguous'}
    elif case == 'unsigned': result['_meta'] = {}
    return msg


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def send(self, value, status=200, content_type='application/json'):
        data = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path != '/.well-known/mcp.json': return self.send({'bad_path': self.path}, 404)
        self.send({'signing': {'jwks': VECTORS['jwks']}})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        case = urlsplit(self.path).path.rstrip('/').split('/')[-1]
        version = '2026-07-28' if case == 'custom-version' else '2025-11-25'
        if (self.headers.get('MCP-Protocol-Version') != version
                or self.headers.get('Mcp-Method') != 'tools/call'
                or self.headers.get('Mcp-Name') != 'fixture'
                or body.get('params') != {'name': 'fixture', 'arguments': {'query': 'å'}}):
            return self.send({'missing_headers_or_arguments': True}, 400)
        msg = response(case)
        if case == 'sse':
            data = ': heartbeat\r\nevent: message\r\ndata:\r\n\r\n'
            data += 'data: {"jsonrpc":"2.0","method":"notifications/progress"}\r\n\r\n'
            data += 'event: message\r\ndata:' + json.dumps(msg) + '\r\n\r\n'
            return self.send(data, content_type='text/event-stream')
        self.send(msg, 400 if case == 'http-error' else 500 if case == 'http-failure' else 200)


class LiveCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
    def test_both_clis(self):
        cases = [
            ('/mcp', [], True), ('/api/mcp', [], True), ('/nested/mcp/?q=1', [], True),
            ('/sse', [], True), ('/custom-version', ['--protocol-version', '2026-07-28'], True),
            ('/rpc-error', [], False), ('/tool-error', [], False), ('/http-error', [], False),
            ('/rpc-error', ['--expect-error'], True), ('/tool-error', ['--expect-error'], True),
            ('/http-error', ['--expect-error'], True), ('/mcp', ['--expect-error'], False),
            ('/tampered-error', ['--expect-error'], False), ('/error-id', ['--expect-error'], False),
            ('/tampered-payload', [], False), ('/tampered-text', [], False),
            ('/missing-structured', [], False), ('/missing-text', [], False),
            ('/wrong-id', [], False), ('/both-result-error', [], False), ('/unsigned', [], False),
            ('/http-failure', [], False),
        ]
        for runtime, filename in [(sys.executable, 'verify.py'), ('node', 'verify.mjs')]:
            for path, flags, passed in cases:
                with self.subTest(cli=filename, path=path, flags=flags):
                    command = [runtime, str(ROOT / 'verifiers' / filename), '--live',
                               f'http://127.0.0.1:{self.server.server_port}{path}',
                               'fixture', '{"query":"å"}', *flags]
                    run = subprocess.run(command, capture_output=True, text=True, timeout=10)
                    self.assertEqual(run.returncode == 0, passed, run.stdout + run.stderr)
                    if passed:
                        marker = 'live signed error' if '--expect-error' in flags else 'live successful tool result'
                        self.assertIn(marker, run.stdout)
        print(f'{len(cases) * 2} CLI regression scenarios passed')


if __name__ == '__main__': unittest.main()
