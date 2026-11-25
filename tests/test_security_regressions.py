"""Reviewed security regressions; all payloads and folders are synthetic."""
import urllib.parse
import mimetypes
import http.client
import http.cookies
import time
from html.parser import HTMLParser

from local_gallery import gallery
from test_gallery import _boot, _req, _roots, _stop


def test_common_credential_names_hidden_from_http(tmp_path):
    roots = _roots(tmp_path)
    names = ['auth.json', 'Cookies', 'Login Data', 'id_ed25519', 'id_ecdsa',
             'server.ppk', 'vault.kdbx', 'release.jks', 'wallet.dat',
             'AppData/Local/hermes/auth.json']
    for name in names:
        p = roots['outputs'] / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'SYNTHETIC-NOT-A-CREDENTIAL')
    srv = _boot(roots)
    try:
        statuses = {name: _req(srv, '/raw?path=' + urllib.parse.quote('outputs/' + name))[0]
                    for name in names}
        assert statuses == dict.fromkeys(names, 403)
        page = _req(srv, '/view?path=outputs')[2].decode('utf-8')
        assert all(name.split('/')[0] not in page for name in names)
    finally:
        _stop(srv)


def test_only_fixed_passive_types_inline(tmp_path, monkeypatch):
    roots = _roots(tmp_path)
    active = ['report.xht', 'feed.rdf', 'schema.xsd', 'service.wsdl', 'odd.unknown']
    for name in active:
        (roots['outputs'] / name).write_bytes(b'<synthetic/>')
    # A platform/registry mapping must not influence inline policy or its MIME.
    monkeypatch.setattr(mimetypes, 'guess_type', lambda *a, **k: ('text/html', None))
    srv = _boot(roots)
    try:
        for name in active:
            status, headers, body = _req(srv, '/raw?path=outputs/' + name)
            assert status == 200 and body == b'<synthetic/>'
            assert 'attachment' in headers.get('Content-Disposition', ''), name
            assert 'sandbox' in headers.get('Content-Security-Policy', ''), name
            assert headers['Content-Type'] == 'application/octet-stream'
            assert headers['X-Content-Type-Options'] == 'nosniff'
        for name, mime in [('shot.png', 'image/png'), ('clip.mp4', 'video/mp4'),
                           ('note.txt', 'text/plain; charset=utf-8')]:
            status, headers, _ = _req(srv, '/raw?path=outputs/' + name)
            assert status == 200 and headers['Content-Type'] == mime
            assert headers.get('Content-Disposition') is None
    finally:
        _stop(srv)


def test_host_authority_checked_before_auth(tmp_path):
    srv = _boot(_roots(tmp_path), token='synthetic-login')
    port = srv.server_address[1]
    try:
        for host in ['attacker.example:' + str(port), 'localhost:1',
                     '127.0.0.1:' + str(port) + '@attacker.example',
                     '127.0.0.1:' + str(port) + '/extra', '']:
            status, headers, body = _req(srv, '/?token=synthetic-login', {'Host': host})
            assert status == 421, (host, status)
            assert headers.get('Set-Cookie') is None and b'outputs' not in body
        for host in [f'127.0.0.1:{port}', f'LOCALHOST:{port}']:
            assert _req(srv, '/?token=synthetic-login', {'Host': host})[0] == 200
        for hosts in [[], [f'127.0.0.1:{port}', 'attacker.example']]:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                conn.putrequest('GET', '/?token=synthetic-login', skip_host=True)
                for host in hosts:
                    conn.putheader('Host', host)
                conn.endheaders()
                response = conn.getresponse()
                assert response.status == 421
                response.read()
            finally:
                conn.close()
    finally:
        _stop(srv)


def test_session_is_random_expiring_and_server_local(tmp_path, monkeypatch):
    roots = _roots(tmp_path)
    srv = _boot(roots, token='synthetic-login')
    other = _boot(roots, token='synthetic-login')
    try:
        _, headers, _ = _req(srv, '/?token=synthetic-login')
        cookie = headers.get('Set-Cookie', '')
        jar = http.cookies.SimpleCookie(cookie)
        value = jar['local_gallery'].value
        assert value != 'synthetic-login' and len(value) >= 32
        assert int(jar['local_gallery']['max-age']) == 3600
        assert headers['Cache-Control'] == 'no-store'
        assert headers['Referrer-Policy'] == 'no-referrer'
        auth = {'Cookie': cookie.split(';', 1)[0]}
        assert _req(srv, '/', auth)[0] == 200
        assert _req(other, '/', auth)[0] == 401
        assert _req(srv, '/', {'Cookie': 'local_gallery=synthetic-login'})[0] == 401
        again = _req(srv, '/?token=synthetic-login')[1]['Set-Cookie']
        assert again.split(';', 1)[0] != auth['Cookie']
        clock = time.monotonic
        monkeypatch.setattr(time, 'monotonic', lambda: clock() + 3601)
        assert _req(srv, '/', auth)[0] == 401
    finally:
        _stop(srv)
        _stop(other)


def test_session_store_bounded_oldest_evicted(tmp_path, monkeypatch):
    # A smaller cap exercises the same eviction path without thousands of HTTP calls.
    monkeypatch.setattr(gallery, '_MAX_SESSIONS', 2, raising=False)
    srv = _boot(_roots(tmp_path), token='synthetic-login')
    try:
        cookies = [_req(srv, '/?token=synthetic-login')[1]['Set-Cookie'].split(';', 1)[0]
                   for _ in range(3)]
        assert len(set(cookies)) == 3
        assert _req(srv, '/', {'Cookie': cookies[0]})[0] == 401
        for cookie in cookies[1:]:
            assert _req(srv, '/', {'Cookie': cookie})[0] == 200
    finally:
        _stop(srv)


def test_every_file_card_has_explicit_download_link(tmp_path):
    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links = []

        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                self.links.append(dict(attrs).get('href', ''))

    roots = _roots(tmp_path)
    (roots['outputs'] / '보고서 & notes.md').write_bytes(b'Synthetic note')
    srv = _boot(roots)
    try:
        parser = Links()
        parser.feed(_req(srv, '/view?path=outputs')[2].decode('utf-8'))
        for name in ('shot.png', 'clip.mp4', 'note.txt', '보고서 & notes.md'):
            links = [link for link in parser.links
                     if urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
                     == {'path': ['outputs/' + name], 'download': ['1']}]
            assert len(links) == 1, name
            status, headers, _ = _req(srv, links[0])
            assert status == 200 and 'attachment' in headers['Content-Disposition']
    finally:
        _stop(srv)
