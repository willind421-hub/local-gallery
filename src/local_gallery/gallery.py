"""Local Gallery - a read-only web gallery for folders of generated artefacts.

Standard library only. Something else (a script, a renderer, an AI agent) writes its
results into a folder; this gallery only shows them in a browser. Writing and viewing are
deliberately separated: the gallery handles GET only and contains no code that writes or
deletes files, so it structurally cannot modify the originals. "Read-only" means the
viewer cannot change the originals - downloading the original file is a read and is
supported (``/raw?path=...&download=1``).

Design:

- **Zero dependencies** - Python standard library only, so it runs wherever it is copied.
- **Local binding** - 127.0.0.1 by default. For remote access put it behind a VPN or an
  authenticated reverse proxy instead of binding a public interface directly. The
  optional token (env ``LOCAL_GALLERY_TOKEN``) is a second line of defence.
- **Layered path defence** - unregistered root / ``..`` and drive-letter segments /
  hidden or secret-looking names / ``resolve()`` containment for stable symlinks /
  hidden-name re-check on the resolved path. The checks are pure functions, so tests
  verify stable-tree cases. Validation and open are separate: this is not a sandbox
  against a writer replacing files or links concurrently.
- **Roots are a registry** (``NAME=PATH;NAME=PATH``) - a new folder is one more entry.
  Without a registry the current working directory is served (implicit home/drive root
  is refused). An explicitly configured invalid registry never falls back to cwd.

Usage: ``local-gallery [--root [NAME=]PATH ...] [--host 127.0.0.1] [--port 18140]``
       (or ``python -m local_gallery``). Environment: ``LOCAL_GALLERY_ROOTS``,
       ``LOCAL_GALLERY_HOST``, ``LOCAL_GALLERY_PORT``, ``LOCAL_GALLERY_TOKEN`` (optional).
"""
from __future__ import annotations

import hmac
import html
import http.cookies
import ipaddress
import os
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- constants

# Secret-looking file names (lower-case substring match). Filtered out of listings too,
# so a target URL cannot even be discovered.
_SECRET_MARKERS = (
    ".env", "credential", "secret", "token", "password",
    ".jks", ".pem", ".key", "id_rsa", ".pfx", ".p12",
    "id_ed25519", "id_ecdsa", ".ppk", ".kdbx",
)
_SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".secrets", "credentials", "appdata"}
_SECRET_NAMES = {"auth.json", "cookies", "login data", "wallet.dat"}

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".avif"}
_VIDEO_EXT = {".mp4", ".webm", ".mov", ".m4v", ".ogv"}
_AUDIO_EXT = {".mp3", ".wav", ".ogg", ".m4a", ".flac"}
_MAX_LIST = 2000            # max entries listed per folder (runaway protection)

# Fixed passive inline types; never consult the OS MIME registry. Everything else is
# octet-stream + attachment + sandbox, including SVG/HTML/XML and unknown extensions.
_INLINE_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".avif": "image/avif", ".mp4": "video/mp4", ".webm": "video/webm",
    ".mov": "video/quicktime", ".m4v": "video/mp4", ".ogv": "video/ogg",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
    ".m4a": "audio/mp4", ".flac": "audio/flac", ".txt": "text/plain; charset=utf-8",
}
_COOKIE_NAME = "local_gallery"   # contains only a random, server-local session ID
_SESSION_TTL = 3600             # absolute lifetime; navigation does not extend it
_MAX_SESSIONS = 1024            # oldest sessions evicted when the bound is reached

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18140


# ---------------------------------------------------------------- pure logic (tested)

def parse_roots(spec: Optional[str], default_root: Optional[Path] = None,
                default_name: str = "outputs") -> Dict[str, Path]:
    """``"NAME=PATH;NAME=PATH"`` -> ``{NAME: existing absolute path}``.

    Entries whose path is not an existing directory are ignored. If nothing valid is
    left, ``default_root`` (when it exists) is registered under ``default_name``.
    """
    roots: Dict[str, Path] = {}
    for part in (spec or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, path = part.partition("=")
        name, path = name.strip(), path.strip()
        if name and path:
            try:
                p = Path(path).resolve()
                if p.is_dir():
                    roots[name] = p
            except OSError:
                continue
    if not roots and default_root is not None:
        try:
            dr = Path(default_root).resolve()
            if dr.is_dir():
                roots[default_name] = dr
        except OSError:
            pass
    return roots


def is_hidden(name: str) -> bool:
    """True for secret/protected or hidden (dot) names - excluded from listing and access."""
    low = name.lower()
    if low in _SECRET_DIRS or low in _SECRET_NAMES:
        return True
    if name.startswith(".") and name not in (".",):
        return True
    return any(marker in low for marker in _SECRET_MARKERS)


def safe_resolve(roots: Dict[str, Path], rel: str) -> Optional[Tuple[str, Path]]:
    """``"ROOT/sub/path"`` -> ``(ROOT, safe absolute path)``, or ``None`` on any violation.

    Layers: unregistered root / ``..`` or drive-letter segment / hidden or secret segment /
    ``resolve()`` containment / hidden-name re-check on the resolved path.
    """
    rel = (rel or "").strip().replace("\\", "/").strip("/")
    if not rel:
        return None
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return None
    root_name, sub = parts[0], parts[1:]
    base = roots.get(root_name)
    if base is None:
        return None                              # unregistered root
    for seg in sub:
        if seg in ("", ".", "..") or ":" in seg:
            return None                          # parent escape / absolute-path segment
        if is_hidden(seg):
            return None                          # secret or hidden segment
    try:
        target = (base / "/".join(sub)).resolve()
    except OSError:
        return None
    # Containment - also neutralises normalisation tricks and symlinks leaving the root.
    if target != base and base not in target.parents:
        return None
    # Re-check hidden names on the *resolved* path: an alias such as a Windows 8.3 short
    # name (ENV~1 -> .env) or an in-root symlink can reach a hidden entry under an
    # innocent-looking name.
    if any(is_hidden(seg) for seg in target.relative_to(base).parts):
        return None
    return root_name, target


def classify_ext(name: str) -> str:
    """Kind by extension - ``image|video|audio|other``. Drives how the grid renders it."""
    ext = Path(name).suffix.lower()
    if ext in _IMAGE_EXT:
        return "image"
    if ext in _VIDEO_EXT:
        return "video"
    if ext in _AUDIO_EXT:
        return "audio"
    return "other"


def list_dir(path: Path) -> List[dict]:
    """Folder listing without hidden/secret entries: ``{name, is_dir, kind, size}``.

    Folders first, then by case-insensitive name.
    """
    out: List[dict] = []
    try:
        entries = sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name.lower()))
    except OSError:
        return out
    for e in entries[:_MAX_LIST]:
        if is_hidden(e.name):
            continue
        try:
            is_dir = e.is_dir()
            size = e.stat().st_size if e.is_file() else 0
        except OSError:
            continue
        out.append({"name": e.name, "is_dir": is_dir,
                    "kind": "dir" if is_dir else classify_ext(e.name), "size": size})
    return out


def content_disposition(filename: str) -> str:
    """``attachment`` Content-Disposition value that is safe for any file name.

    ``http.server`` encodes header values as Latin-1, so a raw non-ASCII name (e.g. a
    Korean file name) raises ``UnicodeEncodeError`` and drops the connection. Following
    RFC 6266 / RFC 5987, send an ASCII-only ``filename`` fallback plus the exact UTF-8
    name in ``filename*``. Quotes, backslashes and control characters (CR/LF) never reach
    the header, which also rules out header injection.
    """
    fallback = "".join(
        ch if 0x20 <= ord(ch) < 0x7F and ch not in '"\\' else "_" for ch in filename
    ) or "download"
    encoded = urllib.parse.quote(filename, safe="")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


def _token_matches(given: str, expected: str) -> bool:
    """Constant-time token comparison (on bytes, so non-ASCII input cannot raise)."""
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


# ---------------------------------------------------------------- HTML rendering

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def render_roots_page(roots: Dict[str, Path]) -> str:
    """Start page: one card per registered root."""
    cards = "".join(
        f'<a class="card dir" href="/view?path={urllib.parse.quote(name)}">'
        f'<div class="thumb ph">📁</div><div class="meta">{html.escape(name)}</div></a>'
        for name in sorted(roots))
    return _PAGE.replace("{{title}}", "Local Gallery").replace("{{crumb}}", "").replace(
        "{{grid}}", cards or '<p class="empty">No folders registered.</p>')


def render_dir_page(root_name: str, rel: str, entries: List[dict]) -> str:
    """Folder page: breadcrumb plus a grid of thumbnails, players and download links."""
    crumb_parts = ['<a href="/">gallery</a>']
    acc = []
    for seg in ([root_name] + [s for s in rel.split("/") if s]) if rel else [root_name]:
        acc.append(seg)
        crumb_parts.append(f'<a href="/view?path={urllib.parse.quote("/".join(acc))}">'
                           f'{html.escape(seg)}</a>')
    crumb = " / ".join(crumb_parts)
    cur = "/".join([root_name] + ([rel] if rel else [])).strip("/")
    cells = []
    for e in entries:
        child = urllib.parse.quote(f"{cur}/{e['name']}")
        label = html.escape(e["name"])
        if e["is_dir"]:
            cells.append(f'<a class="card dir" href="/view?path={child}">'
                         f'<div class="thumb ph">📁</div><div class="meta">{label}</div></a>')
        elif e["kind"] == "image":
            cells.append(f'<div class="card"><a href="/raw?path={child}" target="_blank">'
                         f'<div class="thumb"><img loading="lazy" src="/raw?path={child}"></div></a>'
                         f'<div class="meta">{label}<a class="dl" href="/raw?path={child}&download=1">⬇</a></div></div>')
        elif e["kind"] == "video":
            cells.append(f'<div class="card"><div class="thumb">'
                         f'<video controls preload="metadata" src="/raw?path={child}"></video></div>'
                         f'<div class="meta">{label}<a class="dl" href="/raw?path={child}&download=1">⬇</a></div></div>')
        elif e["kind"] == "audio":
            cells.append(f'<div class="card"><div class="thumb ph">🎵</div>'
                         f'<audio controls preload="none" src="/raw?path={child}"></audio>'
                         f'<div class="meta">{label}<a class="dl" href="/raw?path={child}&download=1">⬇</a></div></div>')
        else:
            cells.append(f'<div class="card"><a href="/raw?path={child}" target="_blank">'
                         f'<div class="thumb ph">📄</div></a>'
                         f'<div class="meta">{label} <span class="sz">{_human_size(e["size"])}</span>'
                         f'<a class="dl" href="/raw?path={child}&download=1">⬇</a></div></div>')
    grid = "".join(cells) or '<p class="empty">Empty folder.</p>'
    return _PAGE.replace("{{title}}", html.escape(cur)).replace(
        "{{crumb}}", crumb).replace("{{grid}}", grid)


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title><style>
*{box-sizing:border-box}body{margin:0;background:#111;color:#eee;
font:14px/1.5 system-ui,-apple-system,sans-serif}
header{padding:12px 18px;background:#1a1a1a;border-bottom:1px solid #2a2a2a;
position:sticky;top:0;z-index:2}header a{color:#8ab4f8;text-decoration:none}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
gap:14px;padding:18px}
.card{background:#1c1c1c;border:1px solid #2a2a2a;border-radius:10px;overflow:hidden;
text-decoration:none;color:#eee;display:flex;flex-direction:column}
.card.dir{background:#20242c}
.thumb{aspect-ratio:1;display:flex;align-items:center;justify-content:center;
background:#000;overflow:hidden}
.thumb img,.thumb video{width:100%;height:100%;object-fit:cover}
.thumb.ph{font-size:40px;background:#181818}
.meta{padding:8px 10px;font-size:12px;word-break:break-all;display:flex;
align-items:center;gap:6px;justify-content:space-between}
.dl{color:#8ab4f8;text-decoration:none;font-size:15px;flex:none}
.sz{color:#888;font-size:11px}.empty{padding:40px;color:#888}
audio{width:100%;padding:0 8px 8px}
</style></head><body>
<header>{{crumb}}</header><div class="grid">{{grid}}</div></body></html>"""


# ---------------------------------------------------------------- HTTP server (thin shell)

def _make_handler(roots: Dict[str, Path], token: Optional[str], *, host: Optional[str] = None):
    from http.server import BaseHTTPRequestHandler

    # One handler factory per server; nothing is persisted or shared across servers.
    sessions: Dict[str, float] = {}
    session_lock = threading.Lock()

    def prune_sessions(now: float):
        for sid, expires in list(sessions.items()):
            if expires <= now:
                del sessions[sid]

    class Handler(BaseHTTPRequestHandler):
        server_version = "local-gallery/1"

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            super().end_headers()

        def _valid_host(self) -> bool:
            # Exact authorities, not DNS resolution of attacker-supplied names.
            values = self.headers.get_all("Host", [])
            if len(values) != 1:
                return False
            address, port = self.server.server_address[:2]
            names = {address.lower()}
            if host:
                names.add(host.lower())
            ip = ipaddress.ip_address(address)
            if ip.is_loopback or ip.is_unspecified:
                names.update({"localhost", "127.0.0.1"})
            names.difference_update({"0.0.0.0", "::"})
            authorities = {f"[{n}]:{port}" if ":" in n else f"{n}:{port}" for n in names}
            if port == 80:
                authorities.update(names)
            return values[0].lower() in authorities

        def _deny(self, code: int, msg: str):
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(msg.encode("utf-8"))

        def _cookie_token(self) -> str:
            """Session token from the request cookie (empty string if absent)."""
            raw = self.headers.get("Cookie")
            if not raw:
                return ""
            try:
                jar = http.cookies.SimpleCookie()
                jar.load(raw)
            except http.cookies.CookieError:
                return ""
            morsel = jar.get(_COOKIE_NAME)
            return morsel.value if morsel else ""

        def _authed(self, qs: dict) -> bool:
            if not token:
                return True
            # The first URL can remain in browser history; later links omit the token.
            given = (qs.get("token") or [""])[0]
            if given and _token_matches(given, token):
                self._auth_via_query = True
                return True
            # A reusable login token is never accepted as a session ID.
            sid = self._cookie_token()
            with session_lock:
                prune_sessions(time.monotonic())
                return sid in sessions

        def _maybe_set_cookie(self):
            """After a query-token login, issue the HttpOnly session cookie."""
            if getattr(self, "_auth_via_query", False) and token:
                with session_lock:
                    now = time.monotonic()
                    prune_sessions(now)
                    while len(sessions) >= _MAX_SESSIONS:
                        del sessions[next(iter(sessions))]
                    sid = secrets.token_urlsafe(32)
                    sessions[sid] = now + _SESSION_TTL
                self.send_header(
                    "Set-Cookie",
                    f"{_COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={_SESSION_TTL}")

        def do_GET(self):
            self._auth_via_query = False
            if not self._valid_host():
                return self._deny(421, "untrusted Host")
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            if not self._authed(qs):
                return self._deny(401, "token required")
            route = parsed.path
            if route == "/":
                return self._html(render_roots_page(roots))
            if route == "/view":
                rel = (qs.get("path") or [""])[0]
                got = safe_resolve(roots, rel)
                if got is None:
                    # Bare root name (no sub path).
                    if rel in roots:
                        return self._html(render_dir_page(rel, "", list_dir(roots[rel])))
                    return self._deny(403, "access denied (path rule violation)")
                root_name, target = got
                if not target.is_dir():
                    return self._deny(400, "not a folder - use /raw")
                sub = "/".join([p for p in rel.split("/")[1:] if p])
                return self._html(render_dir_page(root_name, sub, list_dir(target)))
            if route == "/raw":
                rel = (qs.get("path") or [""])[0]
                got = safe_resolve(roots, rel)
                if got is None:
                    return self._deny(403, "access denied")
                _, target = got
                if not target.is_file():
                    return self._deny(404, "file not found")
                download = (qs.get("download") or ["0"])[0] == "1"
                return self._serve_file(target, download)
            return self._deny(404, "not found")

        # Read-only - every write method is refused (structural protection).
        def do_POST(self): self._deny(405, "read-only")
        def do_PUT(self): self._deny(405, "read-only")
        def do_DELETE(self): self._deny(405, "read-only")

        def _html(self, body: str):
            data = body.encode("utf-8")
            self.send_response(200)
            self._maybe_set_cookie()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _serve_file(self, target: Path, download: bool):
            inline_type = _INLINE_TYPES.get(target.suffix.lower())
            ctype = inline_type or "application/octet-stream"
            try:
                size = target.stat().st_size
                self.send_response(200)
                self._maybe_set_cookie()
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(size))
                # Block MIME sniffing - a type/extension mismatch cannot be "upgraded".
                self.send_header("X-Content-Type-Options", "nosniff")
                if not inline_type:
                    self.send_header("Content-Disposition", content_disposition(target.name))
                    # Even if it does get opened inline, block script and external loads.
                    self.send_header("Content-Security-Policy",
                                     "default-src 'none'; sandbox")
                elif download:
                    self.send_header("Content-Disposition", content_disposition(target.name))
                self.end_headers()
                with target.open("rb") as fh:
                    while chunk := fh.read(65536):
                        self.wfile.write(chunk)
            except (OSError, BrokenPipeError):
                pass

        def log_message(self, *a):  # quiet (no per-request log spam)
            pass

    return Handler


def _say(msg: str):
    """Print without dying on consoles that cannot encode some characters (e.g. cp949)."""
    try:
        print(msg)
    except UnicodeEncodeError:
        import sys as _sys
        enc = (_sys.stdout.encoding or "utf-8")
        print(msg.encode(enc, "replace").decode(enc, "replace"))


def serve(roots: Dict[str, Path], *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
          token: Optional[str] = None):
    """Serve ``roots`` read-only until Ctrl+C."""
    from http.server import ThreadingHTTPServer
    if not token:
        # Classify the configured name, never resolve arbitrary DNS names as proof of
        # safety. A hostname other than localhost needs a token even if it resolves local.
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host.lower() == "localhost"
        if not loopback:
            raise ValueError("non-loopback binding requires a token (LOCAL_GALLERY_TOKEN)")
    handler = _make_handler(roots, token, host=host)
    srv = ThreadingHTTPServer((host, port), handler)
    _say(f"local-gallery - http://{host}:{port}  roots: {', '.join(roots) or '(none)'}"
         + ("  [token]" if token else ""))
    _say("read-only (GET only) - original download OK - Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


def _folder_name(path: Path) -> str:
    """Root name for a folder given without ``NAME=``: its base name (``root`` for a drive)."""
    return path.resolve().name or "root"


def main(argv=None):
    """Console entry point (``local-gallery`` / ``python -m local_gallery``)."""
    import argparse
    ap = argparse.ArgumentParser(
        prog="local-gallery",
        description="Read-only web gallery for local folders (images, video, audio, HTML).",
        epilog="Roots: --root (repeatable) > env LOCAL_GALLERY_ROOTS='NAME=PATH;NAME=PATH' "
               "> current directory. Optional access token: env LOCAL_GALLERY_TOKEN.")
    ap.add_argument("--root", action="append", metavar="[NAME=]PATH",
                    help="folder to serve; repeatable. NAME defaults to the folder name.")
    ap.add_argument("--host", default=os.environ.get("LOCAL_GALLERY_HOST", DEFAULT_HOST),
                    help=f"bind address (env LOCAL_GALLERY_HOST, default {DEFAULT_HOST})")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("LOCAL_GALLERY_PORT", str(DEFAULT_PORT))),
                    help=f"port (env LOCAL_GALLERY_PORT, default {DEFAULT_PORT})")
    args = ap.parse_args(argv)
    if args.root:
        roots: Dict[str, Path] = {}
        for item in args.root:
            name, sep, path = item.partition("=")
            if not sep or not name.strip() or any(c in name for c in "/\\:"):
                name, path = "", item                      # plain PATH
            name, path = name.strip(), path.strip()
            got = parse_roots(None, default_root=Path(path),
                              default_name=name or _folder_name(Path(path)))
            if not got:
                _say(f"not a directory: {path}")
                return 1
            dup = set(got) & set(roots)
            if dup:
                _say(f"duplicate root name: {dup.pop()} - use NAME=PATH")
                return 1
            roots.update(got)
    else:
        cwd = Path.cwd()
        spec = os.environ.get("LOCAL_GALLERY_ROOTS")
        if spec is None and (cwd.resolve() == Path.home().resolve() or cwd.parent == cwd):
            _say("refusing implicit home or drive root - pass --root PATH explicitly.")
            return 1
        roots = parse_roots(spec, default_root=cwd if spec is None else None,
                            default_name=_folder_name(cwd))
    token = os.environ.get("LOCAL_GALLERY_TOKEN") or None
    if not roots:
        _say("no roots - pass --root PATH or set LOCAL_GALLERY_ROOTS.")
        return 1
    try:
        serve(roots, host=args.host, port=args.port, token=token)
    except ValueError as exc:
        _say(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
