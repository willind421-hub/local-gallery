"""Local Gallery tests - read-only surface, layered path defence, hidden secrets, roots.

Core contract: the viewer cannot modify originals (GET only), cannot reach anything
outside the registered roots or any hidden/secret file, and can download originals.
All fixtures are synthetic and created under pytest's tmp_path.
"""
import http.server
import os
import re
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from local_gallery import gallery


def _roots(tmp_path):
    a = tmp_path / "outputs"
    b = tmp_path / "images"
    a.mkdir()
    b.mkdir()
    (a / "shot.png").write_bytes(b"png")
    (a / "clip.mp4").write_bytes(b"mp4")
    (a / "note.txt").write_text("hi", encoding="utf-8")
    (a / ".env").write_text("SECRET=1", encoding="utf-8")
    (a / "sub").mkdir()
    (a / "sub" / "deep.jpg").write_bytes(b"jpg")
    return {"outputs": a.resolve(), "images": b.resolve()}


def test_parse_roots_and_default(tmp_path):
    d = tmp_path / "drop"
    d.mkdir()
    got = gallery.parse_roots(f"a={tmp_path};b={d}", default_root=d)
    assert set(got) == {"a", "b"}
    # Missing paths are ignored.
    assert gallery.parse_roots(f"x={tmp_path/'없음'}", default_root=None) == {}
    # Empty spec -> the default root, registered as "outputs".
    assert list(gallery.parse_roots("", default_root=d)) == ["outputs"]
    # ... or under an explicit default name.
    assert list(gallery.parse_roots("", default_root=d, default_name="drop")) == ["drop"]


def test_is_hidden_blocks_secrets(tmp_path):
    for name in (".env", ".env.local", "creds.credential", "id_rsa", "key.pem",
                 "app.key", "my_token.txt", ".secrets"):
        assert gallery.is_hidden(name), name
    for name in ("shot.png", "note.txt", "clip.mp4", "보고서.md"):
        assert not gallery.is_hidden(name), name


def test_safe_resolve_traversal_defense(tmp_path):
    roots = _roots(tmp_path)
    # Normal.
    ok = gallery.safe_resolve(roots, "outputs/shot.png")
    assert ok and ok[0] == "outputs" and ok[1].name == "shot.png"
    assert gallery.safe_resolve(roots, "outputs/sub/deep.jpg")[1].name == "deep.jpg"
    # Unregistered root.
    assert gallery.safe_resolve(roots, "etc/passwd") is None
    # Parent escape.
    assert gallery.safe_resolve(roots, "outputs/../images/x") is None
    assert gallery.safe_resolve(roots, "outputs/../../secret") is None
    # Drive letter (absolute-path segment).
    assert gallery.safe_resolve(roots, "outputs/C:/Windows") is None
    # Secret file segment.
    assert gallery.safe_resolve(roots, "outputs/.env") is None
    assert gallery.safe_resolve(roots, "outputs/my_token.log") is None
    # Empty path.
    assert gallery.safe_resolve(roots, "") is None
    assert gallery.safe_resolve(roots, "/") is None


def test_safe_resolve_symlink_escape(tmp_path):
    """A symlink pointing outside the root is blocked by resolve() containment."""
    roots = _roots(tmp_path)
    outside = tmp_path / "밖.txt"
    outside.write_text("x", encoding="utf-8")
    link = roots["outputs"] / "link"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here (e.g. Windows without developer mode)")
    assert gallery.safe_resolve(roots, "outputs/link") is None


def test_classify_ext():
    assert gallery.classify_ext("a.PNG") == "image"
    assert gallery.classify_ext("a.mp4") == "video"
    assert gallery.classify_ext("a.mp3") == "audio"
    assert gallery.classify_ext("a.md") == "other"


def test_list_dir_hides_secrets_and_marks_kind(tmp_path):
    roots = _roots(tmp_path)
    names = {e["name"]: e for e in gallery.list_dir(roots["outputs"])}
    assert ".env" not in names                       # secrets are invisible
    assert names["shot.png"]["kind"] == "image"
    assert names["clip.mp4"]["kind"] == "video"
    assert names["sub"]["is_dir"] is True
    assert names["note.txt"]["kind"] == "other"


def test_render_pages_have_download_and_no_secret(tmp_path):
    roots = _roots(tmp_path)
    page = gallery.render_dir_page("outputs", "", gallery.list_dir(roots["outputs"]))
    assert "download=1" in page                      # original download link (a read)
    assert "<video" in page and "shot.png" in page
    assert ".env" not in page                        # secrets do not leak into HTML
    roots_page = gallery.render_roots_page(roots)
    assert "outputs" in roots_page and "images" in roots_page


def test_handler_is_read_only(tmp_path):
    """Write methods exist on the handler and answer 405 (structural protection)."""
    Handler = gallery._make_handler(_roots(tmp_path), None)
    for m in ("do_POST", "do_PUT", "do_DELETE"):
        assert hasattr(Handler, m)
    # do_GET exists; other methods (do_PATCH ...) are undefined, so the base
    # BaseHTTPRequestHandler answers 501. Read-only surface.
    assert hasattr(Handler, "do_GET")


# ---------------------------------------------------------------- short-lived server helpers

def _boot(roots, token=None):
    """Start on port 0 (any free port). Tests must shut it down."""
    handler = gallery._make_handler(roots, token)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _stop(srv):
    srv.shutdown()
    srv.server_close()


def _req(srv, path, headers=None, method="GET"):
    """(status, headers, body) - 4xx/5xx come back as codes, not exceptions."""
    port = srv.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {},
                                 method=method)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


# ---------------------------------------------------------------- token session (cookie)

def test_authed_query_and_cookie_unit(tmp_path):
    """Handler unit: query token / cookie acceptance and refusal (no socket)."""
    roots = _roots(tmp_path)
    Handler = gallery._make_handler(roots, "sekret")
    h = Handler.__new__(Handler)
    # Query token passes and flags cookie issuance (_auth_via_query).
    h.headers = {}
    assert h._authed({"token": ["sekret"]}) is True
    assert h._auth_via_query is True
    # Cookie alone also passes (session after the first authentication).
    h.headers = {"Cookie": "local_gallery=sekret"}
    assert h._authed({}) is True
    # No token, no cookie, wrong value: all refused.
    h.headers = {}
    assert h._authed({}) is False
    assert h._authed({"token": ["wrong"]}) is False
    assert h._authed({"token": ["잘못된값"]}) is False    # non-ASCII input must not raise
    h.headers = {"Cookie": "local_gallery=nope"}
    assert h._authed({}) is False
    # Without a configured token: open mode (always passes).
    H2 = gallery._make_handler(roots, None)
    h2 = H2.__new__(H2)
    h2.headers = {}
    assert h2._authed({}) is True


def test_token_cookie_session_navigation(tmp_path):
    """Token mode: first visit (query) sets a cookie -> later links work with the cookie."""
    srv = _boot(_roots(tmp_path), token="sekret")
    try:
        # (a) First visit with the query token: 200 + Set-Cookie (HttpOnly).
        status, hdrs, _ = _req(srv, "/?token=sekret")
        assert status == 200
        setc = hdrs.get("Set-Cookie") or ""
        assert "local_gallery=sekret" in setc
        assert "HttpOnly" in setc and "SameSite=Strict" in setc
        # (a') Navigation with the cookie only - no token in the URL.
        cookie = {"Cookie": "local_gallery=sekret"}
        st2, _, body2 = _req(srv, "/view?path=outputs", headers=cookie)
        assert st2 == 200 and b"shot.png" in body2
        assert _req(srv, "/raw?path=outputs/shot.png", headers=cookie)[0] == 200
        # (b) Neither token nor cookie: still 401.
        assert _req(srv, "/")[0] == 401
        assert _req(srv, "/view?path=outputs")[0] == 401
        assert _req(srv, "/raw?path=outputs/shot.png")[0] == 401
        # (b') Wrong token / wrong cookie: refused.
        assert _req(srv, "/?token=wrong")[0] == 401
        assert _req(srv, "/view?path=outputs",
                    headers={"Cookie": "local_gallery=nope"})[0] == 401
        # (c) Authenticated requests still cannot escape (separate layers).
        assert _req(srv, "/raw?path=outputs/../../secret", headers=cookie)[0] == 403
    finally:
        _stop(srv)


# ---------------------------------------------------------------- inline SVG/HTML XSS

def test_svg_served_non_executable(tmp_path):
    """SVG/HTML/XML are served as attachment + CSP sandbox + nosniff (no inline script)."""
    roots = _roots(tmp_path)
    evil = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    (roots["outputs"] / "evil.svg").write_bytes(evil)
    (roots["outputs"] / "page.html").write_bytes(b"<script>alert(2)</script>")
    srv = _boot(roots, token=None)
    try:
        # SVG: forced attachment + CSP sandbox + nosniff.
        st, hdrs, body = _req(srv, "/raw?path=outputs/evil.svg")
        assert st == 200
        assert "attachment" in (hdrs.get("Content-Disposition") or "")
        assert "sandbox" in (hdrs.get("Content-Security-Policy") or "")
        assert hdrs.get("X-Content-Type-Options") == "nosniff"
        assert body == evil                         # original bytes (download works)
        # HTML files get the same treatment.
        _, hh, _ = _req(srv, "/raw?path=outputs/page.html")
        assert "attachment" in (hh.get("Content-Disposition") or "")
        assert "sandbox" in (hh.get("Content-Security-Policy") or "")
        # Normal images stay inline with their image type.
        pst, ph, _ = _req(srv, "/raw?path=outputs/shot.png")
        assert pst == 200
        assert ph.get("Content-Type") == "image/png"
        assert "attachment" not in (ph.get("Content-Disposition") or "")
        assert ph.get("X-Content-Type-Options") == "nosniff"
        # Normal video stays inline too.
        _, vh, _ = _req(srv, "/raw?path=outputs/clip.mp4")
        assert "attachment" not in (vh.get("Content-Disposition") or "")
        # An explicit download is still an attachment.
        _, dh, _ = _req(srv, "/raw?path=outputs/shot.png&download=1")
        assert "attachment" in (dh.get("Content-Disposition") or "")
    finally:
        _stop(srv)


# ---------------------------------------------------------------- first page load

def test_first_page_load(tmp_path):
    """The start page and a root page load and list what they should (no token)."""
    srv = _boot(_roots(tmp_path))
    try:
        st, hdrs, body = _req(srv, "/")
        assert st == 200
        assert hdrs.get("Content-Type") == "text/html; charset=utf-8"
        page = body.decode("utf-8")
        assert "<title>Local Gallery</title>" in page
        assert "/view?path=outputs" in page and "/view?path=images" in page
        st, _, body = _req(srv, "/view?path=outputs")
        page = body.decode("utf-8")
        assert st == 200
        for name in ("shot.png", "clip.mp4", "note.txt", "sub"):
            assert name in page
        assert ".env" not in page
        assert _req(srv, "/view?path=outputs/sub")[0] == 200
        assert _req(srv, "/view?path=images")[0] == 200       # empty root
    finally:
        _stop(srv)


def test_write_methods_refused_over_http(tmp_path):
    roots = _roots(tmp_path)
    before = (roots["outputs"] / "shot.png").read_bytes()
    srv = _boot(roots)
    try:
        for method in ("POST", "PUT", "DELETE"):
            st, _, _ = _req(srv, "/raw?path=outputs/shot.png", method=method)
            assert st == 405, method
        assert _req(srv, "/raw?path=outputs/shot.png", method="PATCH")[0] == 501
    finally:
        _stop(srv)
    assert (roots["outputs"] / "shot.png").read_bytes() == before


# ---------------------------------------------------------------- Unicode downloads (RFC 5987)

KOREAN_NAME = "보고서 결과 (최종).png"


def _filename_star(cd):
    m = re.search(r"filename\*=UTF-8''([^;\s]+)", cd or "")
    assert m, cd
    return urllib.parse.unquote(m.group(1), encoding="utf-8", errors="strict")


def test_content_disposition_ascii_safe_for_any_name():
    for name in (KOREAN_NAME, "日本語 ファイル.mp4", "emoji 🎨.png", "plain.png",
                 'quote"name.png', "back\\slash.png", "evil\r\nSet-Cookie: x=1.png"):
        value = gallery.content_disposition(name)
        value.encode("ascii")                            # header stays pure ASCII
        assert "\r" not in value and "\n" not in value   # no header injection
        assert value.startswith("attachment; filename=\"")
        fallback = re.search(r'filename="([^"]*)"', value).group(1)
        assert len(fallback) == len(name) and "\\" not in fallback
        star = re.search(r"filename\*=UTF-8''(\S+)$", value).group(1)
        assert re.fullmatch(r"[A-Za-z0-9!#$&+\-.^_`|~%]+", star)   # RFC 5987 attr-chars
        assert _filename_star(value) == name             # exact name round-trips
    assert 'filename="plain.png"' in gallery.content_disposition("plain.png")


def test_download_unicode_filename(tmp_path):
    """Korean file names download (original code dropped the connection here)."""
    roots = _roots(tmp_path)
    payload = b"\x89PNG synthetic bytes"
    (roots["outputs"] / KOREAN_NAME).write_bytes(payload)
    (roots["outputs"] / "결과 보고서.html").write_bytes(b"<p>synthetic</p>")
    srv = _boot(roots)
    try:
        q = urllib.parse.quote(f"outputs/{KOREAN_NAME}")
        st, hdrs, body = _req(srv, f"/raw?path={q}&download=1")
        assert st == 200 and body == payload
        assert hdrs.get("Content-Disposition").startswith("attachment; ")
        assert _filename_star(hdrs.get("Content-Disposition")) == KOREAN_NAME
        # Inline view of the same file: no Content-Disposition, same bytes.
        st, hdrs, body = _req(srv, f"/raw?path={q}")
        assert st == 200 and body == payload and hdrs.get("Content-Disposition") is None
        # Active format with a Korean name: forced attachment still works.
        qh = urllib.parse.quote("outputs/결과 보고서.html")
        st, hdrs, _ = _req(srv, f"/raw?path={qh}")
        assert st == 200
        assert _filename_star(hdrs.get("Content-Disposition")) == "결과 보고서.html"
        # The listing shows the name and links to it.
        st, _, page = _req(srv, "/view?path=outputs")
        assert st == 200
        assert KOREAN_NAME in page.decode("utf-8") and q in page.decode("utf-8")
    finally:
        _stop(srv)


# ---------------------------------------------------------------- paths outside the root

OUTSIDE_BYTES = b"OUTSIDE-ROOT-CONTENT"


def _outside(tmp_path):
    p = tmp_path / "outside.txt"           # sibling of both roots -> outside them
    p.write_bytes(OUTSIDE_BYTES)
    return p


def _escape_attempts(outside: Path):
    """Decoded ``path`` values that must never reach ``outside``."""
    return [
        "outputs/../outside.txt",
        "outputs/../../outside.txt",
        "outputs/sub/../../outside.txt",
        "outputs/./../outside.txt",
        "outputs\\..\\outside.txt",
        "../outside.txt",
        "..",
        str(outside),                       # absolute (native separators)
        outside.as_posix(),                 # absolute (forward slashes)
        "outputs/" + str(outside),
        "outputs/" + outside.as_posix(),
        "//?/" + outside.as_posix(),        # Windows extended-length prefix
        "C:/Windows/win.ini",
        "outputs/C:/Windows/win.ini",
        "outputs/C:..\\outside.txt",
        "/etc/passwd",
        "outputs/shot.png::$DATA",          # NTFS alternate data stream syntax
    ]


def test_safe_resolve_never_leaves_root(tmp_path):
    roots = _roots(tmp_path)
    outside = _outside(tmp_path).resolve()
    for rel in _escape_attempts(outside):
        got = gallery.safe_resolve(roots, rel)
        if got is not None:                 # e.g. "outputs//etc/passwd"-style: in-root name
            base = roots[got[0]]
            assert got[1] == base or base in got[1].parents, rel
            assert got[1] != outside, rel
    # The plainly hostile forms are refused outright.
    for rel in ("outputs/../outside.txt", "../outside.txt", "..", str(outside),
                outside.as_posix(), "outputs/C:/Windows/win.ini", "outputs/shot.png::$DATA"):
        assert gallery.safe_resolve(roots, rel) is None, rel


def test_http_refuses_paths_outside_root(tmp_path):
    roots = _roots(tmp_path)
    outside = _outside(tmp_path).resolve()
    queries = [urllib.parse.quote(rel, safe="") for rel in _escape_attempts(outside)]
    queries += [                            # raw, already-encoded query values
        "outputs%2F..%2Foutside.txt",
        "outputs/%2e%2e/outside.txt",
        "outputs/%2E%2E%2Foutside.txt",
        "outputs%5C..%5Coutside.txt",
        "outputs/%252e%252e/outside.txt",   # double-encoded: stays a literal (missing) name
        "outputs/%252e%252e%252foutside.txt",
        "outputs/..%c0%af..%c0%afoutside.txt",  # overlong UTF-8 slash
        "outputs/%2e%2e%2f%2e%2e%2foutside.txt",
    ]
    srv = _boot(roots)
    try:
        for q in queries:
            for route in ("/raw", "/view"):
                st, _, body = _req(srv, f"{route}?path={q}")
                assert st in (400, 403, 404), (route, q, st)
                assert OUTSIDE_BYTES not in body, (route, q)
        # Traversal in the URL path itself never matches a route.
        for raw in ("/../outside.txt", "/raw/../outside.txt", "/%2e%2e/outside.txt",
                    "/raw/%2e%2e%2foutside.txt"):
            st, _, body = _req(srv, raw)
            assert st == 404 and OUTSIDE_BYTES not in body, raw
        # Decoded ".." always ends in 403 (refused, not merely missing).
        assert _req(srv, "/raw?path=outputs%2F..%2Foutside.txt")[0] == 403
        assert _req(srv, "/raw?path=outputs/%2e%2e/outside.txt")[0] == 403
    finally:
        _stop(srv)


def _link_dir(link: Path, target: Path) -> str:
    """Directory symlink, or an NTFS junction where symlinks need extra privileges."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                           capture_output=True)
        if r.returncode == 0 and link.exists():
            return "junction"
    pytest.skip("cannot create a directory symlink or junction here")


def test_directory_link_outside_root_refused(tmp_path):
    roots = _roots(tmp_path)
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "data.txt").write_bytes(OUTSIDE_BYTES)
    link = roots["outputs"] / "escape"
    kind = _link_dir(link, outside_dir)
    try:
        assert gallery.safe_resolve(roots, "outputs/escape") is None, kind
        assert gallery.safe_resolve(roots, "outputs/escape/data.txt") is None, kind
        srv = _boot(roots)
        try:
            st, _, body = _req(srv, "/raw?path=outputs/escape/data.txt")
            assert st == 403 and OUTSIDE_BYTES not in body
            assert _req(srv, "/view?path=outputs/escape")[0] == 403
        finally:
            _stop(srv)
    finally:
        if kind == "junction":
            os.rmdir(link)                  # removes the junction only, not the target
        else:
            link.unlink()


def test_in_root_symlink_to_hidden_file_refused(tmp_path):
    """An innocent-looking in-root link must not expose a hidden file (fixed)."""
    roots = _roots(tmp_path)
    link = roots["outputs"] / "harmless.txt"
    try:
        link.symlink_to(roots["outputs"] / ".env")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here (e.g. Windows without developer mode)")
    assert gallery.safe_resolve(roots, "outputs/harmless.txt") is None


@pytest.mark.skipif(os.name != "nt", reason="8.3 short names are a Windows feature")
def test_short_name_alias_cannot_reveal_hidden_file(tmp_path):
    """``ENV~1`` is an alias of ``.env`` when 8.3 names are on - must stay refused (fixed)."""
    import ctypes

    roots = _roots(tmp_path)
    env = roots["outputs"] / ".env"
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(env), buf, len(buf))
    short = Path(buf.value).name if n else ""
    if not short or short.lower() == ".env":
        pytest.skip("8.3 short names are disabled on this volume")
    assert not gallery.is_hidden(short)              # the alias itself looks harmless
    assert gallery.safe_resolve(roots, f"outputs/{short}") is None
    srv = _boot(roots)
    try:
        st, _, body = _req(srv, "/raw?path=" + urllib.parse.quote(f"outputs/{short}"))
        assert st == 403 and b"SECRET" not in body
    finally:
        _stop(srv)
