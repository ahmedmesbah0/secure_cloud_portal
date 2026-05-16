"""
Web-based GUI backend — thin HTTP API over the existing client/server system.
Uses only Python stdlib (http.server + json).
Launch: python3 gui_server.py
"""
import os, sys, json, time, threading, queue, io, base64, datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LOG_QUEUE = queue.Queue()


class LogInterceptor(io.TextIOBase):
    def __init__(self, q, original):
        super().__init__()
        self.q = q
        self.orig = original
    def write(self, text):
        if text and text.strip():
            self.q.put(text.strip())
        if self.orig:
            self.orig.write(text)
        return len(text) if text else 0
    def flush(self):
        if self.orig:
            self.orig.flush()


class AppState:
    ca = None
    server = None
    client = None
    current_user = None
    ready = False


def init_backend():
    import shutil
    for d in ['keys']:
        if os.path.exists(d):
            shutil.rmtree(d)
    data_dir = 'data'
    if os.path.exists(data_dir):
        for item in os.listdir(data_dir):
            p = os.path.join(data_dir, item)
            if item.endswith('.db'):
                continue
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)

    old_stdout = sys.stdout
    sys.stdout = LogInterceptor(LOG_QUEUE, old_stdout)

    from ca.certificate_authority import CertificateAuthority
    from server.server import SecureServer
    from client.client import SecureClient

    AppState.ca = CertificateAuthority(bits=256)
    AppState.server = SecureServer(host='127.0.0.1', port=5558,
                                   ca=AppState.ca, elgamal_bits=256)
    t = threading.Thread(target=AppState.server.start, daemon=True)
    t.start()
    time.sleep(1)
    AppState.client = SecureClient(host='127.0.0.1', port=5558,
                                   ca=AppState.ca, elgamal_bits=256)
    AppState.client.connect()
    AppState.ready = True


class GUIHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/' or path == '/index.html':
            self._serve_file('gui_frontend.html', 'text/html')
        elif path.startswith('/api/'):
            self._handle_api_get(path)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        self._handle_api_post(path, body)

    def _json_response(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _serve_file(self, fname, ctype):
        fpath = os.path.join(os.path.dirname(__file__), fname)
        with open(fpath, 'rb') as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.end_headers()
        self.wfile.write(content)

    def _handle_api_get(self, path):
        if path == '/api/status':
            self._json_response({
                'ready': AppState.ready,
                'user': AppState.current_user
            })
        elif path == '/api/logs':
            logs = []
            try:
                while True:
                    logs.append(LOG_QUEUE.get_nowait())
            except queue.Empty:
                pass
            self._json_response({'logs': logs})
        elif path == '/api/files':
            if not AppState.current_user:
                self._json_response({'error': 'Not logged in'}, 401)
                return
            files = AppState.client.list_files()
            self._json_response({'files': files})
        elif path == '/api/certs':
            certs = AppState.ca.list_certificates()
            rows = []
            for c in certs:
                rows.append({
                    'serial': c['serial'],
                    'subject': c['subject'],
                    'issued': datetime.datetime.fromtimestamp(
                        c['issued_at']).strftime('%Y-%m-%d %H:%M'),
                    'expires': datetime.datetime.fromtimestamp(
                        c['expires_at']).strftime('%Y-%m-%d %H:%M'),
                    'valid': AppState.ca.verify_certificate(c),
                })
            self._json_response({'certs': rows})
        elif path == '/api/db':
            data = AppState.server.auth.get_all_data()
            for u in data['users']:
                u['created_at'] = datetime.datetime.fromtimestamp(
                    u['created_at']).strftime('%Y-%m-%d %H:%M:%S')
            for f in data['files']:
                f['uploaded_at'] = datetime.datetime.fromtimestamp(
                    f['uploaded_at']).strftime('%Y-%m-%d %H:%M:%S')
            self._json_response(data)
        else:
            self.send_error(404)

    def _handle_api_post(self, path, body):
        if path == '/api/register':
            ok = AppState.client.register(body['username'], body['password'])
            self._json_response({'ok': ok})
        elif path == '/api/login':
            ok = AppState.client.login(body['username'], body['password'])
            if ok:
                AppState.current_user = body['username']
            self._json_response({'ok': ok, 'user': AppState.current_user})
        elif path == '/api/logout':
            AppState.current_user = None
            self._json_response({'ok': True})
        elif path == '/api/upload':
            fname = body['filename']
            data = base64.b64decode(body['data'])
            tmp = os.path.join('data', fname)
            os.makedirs('data', exist_ok=True)
            with open(tmp, 'wb') as f:
                f.write(data)
            ok = AppState.client.upload_file(tmp)
            os.remove(tmp)
            self._json_response({'ok': ok})
        elif path == '/api/download':
            fname = body['filename']
            tmp = os.path.join('data', f'_dl_{fname}')
            ok = AppState.client.download_file(fname, tmp)
            if ok and os.path.exists(tmp):
                with open(tmp, 'rb') as f:
                    raw = f.read()
                os.remove(tmp)
                self._json_response({
                    'ok': True,
                    'data': base64.b64encode(raw).decode(),
                    'filename': fname
                })
            else:
                self._json_response({'ok': False, 'error': 'Download failed'})
        elif path == '/api/rotate':
            AppState.client.rotate_key()
            self._json_response({'ok': True})
        elif path == '/api/benchmark':
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                from performance.benchmark import (benchmark_encryption,
                    benchmark_ciphertext_size, benchmark_memory)
                benchmark_encryption()
                benchmark_ciphertext_size()
                benchmark_memory()
            finally:
                sys.stdout = old
            self._json_response({'result': buf.getvalue()})
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logs


def main():
    print("Starting backend initialization...")
    threading.Thread(target=init_backend, daemon=True).start()

    port = 8080
    httpd = HTTPServer(('127.0.0.1', port), GUIHandler)
    print(f"\n  Open http://127.0.0.1:{port} in your browser\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()


if __name__ == '__main__':
    main()
