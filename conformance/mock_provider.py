"""Loopback-only provider fixtures with independent response and wire oracles."""
import copy
import json
import threading
from collections import Counter
from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from generate_vectors import b64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

MASTER = 'conformance-only-master-key'
TOKEN = 'synthetic-test-token'


def metadata(value):
    nonce = b'aaaaaaaaaaaa'
    key = hashlib.pbkdf2_hmac('sha512', MASTER.encode(), MASTER.encode(), 1, 32)
    return '002' + nonce.decode() + b64(AESGCM(key).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), None))


def listing(provider, count=2):
    folders, files, expected = [], [], []
    for i in range(count):
        name = ['Grüße 中文 🚀', '.hidden'][i] if i < 2 else f'item-{i:03}'
        folder_id, file_id = f'folder-{i:03}', f'file-{i:03}'
        size = i * 4096 + 17
        if provider == 'filen':
            folders.append({'uuid': folder_id, 'name': metadata({'name': name, 'creation': 1700000000000}), 'parent': 'root'})
            files.append({'uuid': file_id, 'parent': 'root', 'version': 2, 'chunks': 1,
                          'bucket': 'test-bucket', 'region': 'test-region',
                          'metadata': metadata({'name': name + '.txt', 'size': size,
                                                'key': '0123456789abcdefghijklmnopqrstuv',
                                                'mime': 'text/plain', 'lastModified': 1700000000000})})
        else:
            folders.append({'uuid': folder_id, 'plainName': name})
            files.append({'uuid': file_id, 'plainName': name, 'type': 'txt', 'size': str(size)})
        expected += [{'uuid': folder_id, 'name': name, 'is_dir': True, 'size': 0},
                     {'uuid': file_id, 'name': name + '.txt', 'is_dir': False, 'size': size}]
    return folders, files, sorted(expected, key=lambda x: x['uuid'])


def cases():
    result = []
    for provider in ['filen', 'internxt']:
        for label, count, repeat in [('empty', 0, 1), ('unicode', 2, 1), ('cached', 2, 2)]:
            result.append({'id': f'{provider}.mock.list.{label}', 'op': f'{provider}.mock.list',
                           'scenario': label, 'count': count, 'repeat': repeat, 'expected': listing(provider, count)[2]})
        for status in [401, 403, 404]:
            result.append({'id': f'{provider}.mock.list.http-{status}', 'op': f'{provider}.mock.list',
                           'scenario': 'http-error', 'http_status': status, 'expected': {'status': 'rejected'}})
        result += [
            {'id': f'{provider}.mock.list.invalid-json', 'op': f'{provider}.mock.list',
             'scenario': 'invalid-json', 'expected': {'status': 'rejected'}},
            {'id': f'{provider}.mock.list.retry-503', 'op': f'{provider}.mock.list',
             'scenario': 'retry-503', 'count': 2, 'expected': listing(provider)[2]},
        ]
    for count in [49, 50, 51, 100, 101]:
        result.append({'id': f'internxt.mock.list.pagination-{count}', 'op': 'internxt.mock.list',
                       'scenario': 'pagination', 'count': count, 'expected': listing('internxt', count)[2]})
    result += [
        {'id': 'filen.mock.list.api-error', 'op': 'filen.mock.list', 'scenario': 'api-error', 'expected': {'status': 'rejected'}},
        {'id': 'filen.mock.list.missing-data', 'op': 'filen.mock.list', 'scenario': 'missing-data', 'expected': {'status': 'rejected'}},
        {'id': 'filen.mock.list.corrupt-metadata', 'op': 'filen.mock.list', 'scenario': 'corrupt-metadata',
         'expected': {'status': 'rejected'}, 'known_difference': 'Dart lists an [Encrypted] placeholder; Rust rejects undecryptable metadata',
         'engine_expected': {'dart': {'status': 'ok', 'value': [{'uuid': 'broken', 'name': '[Encrypted]', 'is_dir': True, 'size': 0}]}}},
        {'id': 'internxt.mock.list.missing-result', 'op': 'internxt.mock.list', 'scenario': 'missing-result',
         'expected': {'status': 'rejected'}, 'known_difference': 'Both SDKs accept a missing listing collection as an empty directory',
         'engine_expected': {'dart': {'status': 'ok', 'value': []}, 'rust': {'status': 'ok', 'value': []}}},
        {'id': 'internxt.mock.list.wrong-result-type', 'op': 'internxt.mock.list', 'scenario': 'wrong-result-type', 'expected': {'status': 'rejected'}},
    ]
    for action in ['create', 'rename', 'move', 'trash']:
        for status in [200, 403]:
            result.append({'id': f'internxt.mock.{action}.{status}', 'op': 'internxt.mock.mutate',
                           'scenario': 'mutate', 'action': action, 'http_status': status,
                           'expected': 'created-folder' if action == 'create' and status == 200 else
                                       (True if status == 200 else {'status': 'rejected'})})
    return result


class MockProvider(AbstractContextManager):
    def __init__(self, fixtures):
        self.fixtures = {c['id']: c for c in fixtures if '.mock.' in c['op']}
        self.requests, self.errors = [], []
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle_request(self):
                parsed = urlsplit(self.path)
                parts = parsed.path.split('/', 3)
                if len(parts) < 4 or parts[2] not in owner.fixtures:
                    self.send_error(404)
                    return
                engine, identifier, path = parts[1], parts[2], '/' + parts[3].rstrip('/')
                case = owner.fixtures[identifier]
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                try:
                    body = json.loads(body) if body else None
                except ValueError:
                    owner.errors.append(identifier + ': request body is not JSON')
                query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                record = {'engine': engine, 'id': identifier, 'method': self.command,
                          'path': path, 'raw_path': parsed.path, 'query': query, 'body': body}
                with owner.lock:
                    owner.requests.append(record)
                    attempt = sum(r['id'] == identifier and r['engine'] == engine for r in owner.requests)
                if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                    owner.errors.append(identifier + ': missing/wrong bearer authentication')
                status, response = owner.respond(case, record, attempt)
                raw = response if isinstance(response, bytes) else json.dumps(response, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def for_engine(self, fixtures, engine):
        output = copy.deepcopy(fixtures)
        for case in output['cases']:
            if case['id'] in self.fixtures:
                case['base_url'] = f'http://127.0.0.1:{self.server.server_port}/{engine}/{case["id"]}'
        return output

    def respond(self, case, request, attempt):
        scenario = case['scenario']
        if scenario == 'http-error':
            return case['http_status'], {'message': 'synthetic denial'}
        if scenario == 'invalid-json':
            return 200, b'{broken-json'
        if scenario == 'retry-503' and attempt == 1:
            return 503, {'message': 'synthetic temporary outage'}
        provider = case['op'].split('.')[0]
        path = request['path']
        if provider == 'filen':
            if request['method'] != 'POST' or path != '/v3/dir/content' or request['body'] != {'uuid': 'root'}:
                self.errors.append(case['id'] + ': unexpected Filen listing request')
                return 400, {'status': False}
            folders, files, _ = listing('filen', case.get('count', 0))
            if scenario == 'corrupt-metadata':
                folders = [{'uuid': 'broken', 'name': '002truncated', 'parent': 'root'}]
            if scenario == 'missing-data':
                return 200, {'status': True}
            return 200, {'status': scenario != 'api-error', 'message': 'synthetic', 'data': {'folders': folders, 'uploads': files}}
        if case['op'] == 'internxt.mock.mutate':
            # Dart invalidates caches by fetching the item's parent metadata.
            if request['method'] == 'GET' and path == '/files/file':
                return 200, {'uuid': 'file', 'folderUuid': 'root', 'parentUuid': 'root'}
            methods = {'create': ('POST', '/folders', {'plainName': '新規 Grüße', 'parentFolderUuid': 'root'}),
                       'rename': ('PUT', '/files/file/meta', {'plainName': '新規 Grüße', 'type': 'txt'}),
                       'move': ('PATCH', '/files/file', {'destinationFolder': 'destination'}),
                       'trash': ('POST', '/storage/trash/add', {'items': [{'uuid': 'file', 'type': 'file'}]})}
            method, target, body = methods[case['action']]
            if (request['method'], path, request['body']) != (method, target, body):
                self.errors.append(case['id'] + ': wrong mutation method, URL or payload')
                return 400, {'message': 'bad mutation'}
            return case['http_status'], {'uuid': 'created-folder'}
        folders, files, _ = listing('internxt', case.get('count', 0))
        kind = path.rsplit('/', 1)[-1]
        if request['method'] != 'GET' or path not in ['/folders/content/root/folders', '/folders/content/root/files']:
            self.errors.append(case['id'] + ': unexpected Internxt listing request')
            return 400, {}
        query = request['query']
        if set(query) != {'offset', 'limit', 'sort', 'direction'} or query.get('limit') != '50' or query.get('sort') != 'plainName' or query.get('direction') != 'ASC':
            self.errors.append(case['id'] + ': incorrect pagination/sort parameters ' + str(query))
        if scenario == 'missing-result':
            return 200, {'unexpected': True}
        if scenario == 'wrong-result-type':
            return 200, {'result': 'not-a-list'}
        offset = int(query.get('offset', '-1'))
        return 200, {'result': (folders if kind == 'folders' else files)[offset:offset+50]}

    def verify(self, engines):
        errors = list(self.errors)
        for engine in engines:
            for identifier, case in self.fixtures.items():
                requests = [r for r in self.requests if r['engine'] == engine and r['id'] == identifier]
                if not requests:
                    errors.append(f'{identifier} [{engine}]: no real HTTP request')
                    continue
                if case['op'] == 'internxt.mock.mutate':
                    mutations = [r for r in requests if r['method'] != 'GET']
                    if len(mutations) != 1:
                        errors.append(f'{identifier} [{engine}]: mutation replayed or omitted')
                    continue
                scenario = case['scenario']
                early_error = scenario in ['http-error', 'invalid-json', 'api-error', 'missing-data', 'wrong-result-type']
                if scenario == 'corrupt-metadata' and engine == 'rust':
                    early_error = True
                expected = 1 if early_error else (1 if case['op'].startswith('filen') and engine == 'rust' else 2)
                if case['op'].startswith('internxt') and not early_error:
                    expected = (case.get('count', 0) // 50 + 1) * 2
                    # Detect skipped, duplicated or stuck pagination even if output
                    # happens to match (e.g. repeated zero-sized folders).
                    offsets = Counter((r['path'].rsplit('/', 1)[-1], r['query'].get('offset')) for r in requests[1 if scenario == 'retry-503' else 0:])
                    wanted = Counter((kind, str(offset)) for kind in ['folders', 'files'] for offset in range(0, case.get('count', 0)+1, 50))
                    if offsets != wanted:
                        errors.append(f'{identifier} [{engine}]: missing/duplicate pagination offsets')
                if scenario == 'retry-503':
                    expected += 1
                if len(requests) != expected:
                    errors.append(f'{identifier} [{engine}]: expected {expected} HTTP requests, got {len(requests)}')
        return errors
