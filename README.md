# Local Gallery

A read-only web gallery for local folders of generated artefacts — images, video, audio
and HTML reports — with one-click downloads of the original files.
Pure Python standard library, no dependencies, a single module.

[한국어](README.ko.md) · [日本語](README.ja.md)

## Problem

Scripts, renderers and AI agents keep writing results into output folders. You want to
look at them in a browser — a thumbnail grid, inline video, a download button for the
original — without installing a media server, and without giving the viewer any way to
change, delete, or wander outside those folders.

Local Gallery separates the two roles: whatever produces files writes them; the gallery
only reads and shows them.

## What it guarantees

- **Read-only.** Only `GET` is implemented. `POST`/`PUT`/`DELETE` answer `405`, any other
  method `501`. The code contains no call that writes, renames or deletes files.
  Downloading an original is a read and is supported.
- **Confined to registered roots.** `..` segments, drive letters and other `:` segments
  (including NTFS alternate data streams), absolute paths, percent-encoded traversal, and
  symlinks/junctions that lead outside a root are refused. Containment is checked on the
  fully resolved path.
- **Hidden and secret-looking entries stay invisible.** Dot files and names that look like
  credentials (`.env`, `*.pem`, `*.key`, `id_rsa`, names containing `token`, `secret`,
  `password`, `credential`, directories such as `.ssh`, `.aws`, …) are left out of
  listings and cannot be fetched — not even through an alias such as a Windows 8.3 short
  name (`ENV~1`) or an innocent-looking symlink inside the root.
- **Active content never runs on the gallery's origin.** SVG, HTML and XML files are always
  sent as attachments with `Content-Security-Policy: default-src 'none'; sandbox`;
  every file response carries `X-Content-Type-Options: nosniff`.
- **Any file name downloads.** `Content-Disposition` follows RFC 6266 / RFC 5987: an
  ASCII fallback plus the exact UTF-8 name in `filename*`, so Korean, Japanese or emoji
  names keep their name, and quotes or CR/LF in a name cannot inject headers.
- **Local by default.** Binds `127.0.0.1` unless told otherwise.
- **Optional access token** with an HttpOnly session cookie (see below).

## Design

One module, `local_gallery/gallery.py`: pure functions that hold all the decisions, plus
a thin `http.server` handler that calls them.

| Function | Role |
| --- | --- |
| `parse_roots(spec, default_root, default_name)` | `NAME=PATH;NAME=PATH` → `{name: resolved dir}`; falls back to one default folder |
| `is_hidden(name)` | dot files, secret-looking names, protected directories |
| `safe_resolve(roots, rel)` | `ROOT/sub/path` → `(root, absolute path)` or `None` |
| `list_dir(path)` | folder listing without hidden entries, folders first, capped at 2000 |
| `classify_ext(name)` | `image` / `video` / `audio` / `other` for rendering |
| `content_disposition(filename)` | RFC 5987 attachment header value |
| `render_roots_page`, `render_dir_page` | HTML pages (all names escaped, all links percent-encoded) |
| `serve(roots, host=, port=, token=)` | run the server until Ctrl+C |
| `main(argv)` | the `local-gallery` command |

`safe_resolve` applies its layers in order: unknown root name → `..`, `.` or `:` segment →
hidden segment → `Path.resolve()` must stay inside the root → no hidden name on the
resolved path. Because these are pure functions, the tests call them directly as well as
over HTTP.

Thumbnails are the originals scaled by the browser (`<img loading="lazy">`); there is no
server-side cache or transcoding. Files are streamed in 64 KiB chunks.

**Token flow.** When `LOCAL_GALLERY_TOKEN` is set, the first request must carry
`?token=<value>`. The response sets an `HttpOnly; SameSite=Strict` cookie, so links inside
the gallery work without the token in the URL. Requests with neither a matching token nor
the cookie get `401`. Comparison is constant-time.

## Quick start

```bash
pip install .                 # or: pip install -e ".[test]" for development

cd path/to/outputs
local-gallery                 # serves the current folder at http://127.0.0.1:18140

# several folders, explicit names, another port
local-gallery --root renders=./renders --root /srv/reports --port 8080

python -m local_gallery --help
```

Open the printed URL. Folder cards lead to a grid with image thumbnails, inline video and
audio players, and a ⬇ button that downloads the original.

| Setting | CLI | Environment | Default |
| --- | --- | --- | --- |
| Folders | `--root [NAME=]PATH` (repeatable) | `LOCAL_GALLERY_ROOTS="NAME=PATH;NAME=PATH"` | current directory |
| Bind address | `--host` | `LOCAL_GALLERY_HOST` | `127.0.0.1` |
| Port | `--port` | `LOCAL_GALLERY_PORT` | `18140` |
| Access token | — | `LOCAL_GALLERY_TOKEN` | none (open on localhost) |

`--root` takes precedence over `LOCAL_GALLERY_ROOTS`. A root without `NAME=` is named after
its folder; two roots with the same name are rejected.

### Access token

The token is read from the environment only, so it does not end up in shell history or
process listings. Use a random URL-safe ASCII value:

```bash
export LOCAL_GALLERY_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
local-gallery
# open http://127.0.0.1:18140/?token=<the same value> once; the cookie keeps the session
```

PowerShell: `$env:LOCAL_GALLERY_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(24))"`

No token is shipped or generated by default. The token is a second line of defence, not a
replacement for network access control: there is no TLS, and the first URL contains the
token once.

### HTTP endpoints

| Request | Result |
| --- | --- |
| `GET /` | one card per root |
| `GET /view?path=ROOT/sub/dir` | folder grid |
| `GET /raw?path=ROOT/sub/file` | the file (inline for media, attachment for SVG/HTML/XML) |
| `GET /raw?path=ROOT/sub/file&download=1` | the file as an attachment |

Refusals: `401` token required, `403` path rule violation, `404` missing, `405` write method.

## Running tests

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest -q
```

Some tests depend on the operating system and skip when it cannot provide the setup:
symlinks (Windows without Developer Mode or admin rights; directory tests fall back to an
NTFS junction there) and Windows 8.3 short names (only when enabled on the volume).

### Example

```bash
python examples/demo.py          # synthetic folder, real server, prints what it gets back
python examples/demo.py --keep   # same, then keeps serving so you can browse it
```

The demo builds a PNG gradient, a Korean-named HTML report, a note and a hidden `.env` in
a temporary folder, then shows the listing, the RFC 5987 download header and the refused
requests (`../`, `%2e%2e`, `.env`, `POST`).

## Limitations and non-goals

- No upload, delete, rename or editing — by design.
- No TLS and no user accounts. Keep it on `127.0.0.1`; for remote access use a VPN or an
  authenticated reverse proxy rather than binding a public interface.
- The token is a single shared value stored in a cookie as is.
- No server-side thumbnails, transcoding or pagination. Large folders of large images are
  heavy for the browser, and listings stop at 2000 entries per folder.
- No `HEAD` or HTTP `Range` support, so seeking in long videos may be limited and some
  browsers may refuse to stream video.
- The hidden-file filter matches names, not contents. Do not point a root at a folder that
  holds secrets under ordinary names.
- A listing may show a symlink whose target is outside the root (with the target's size);
  opening it is refused.

## Origin

Local Gallery was originally developed as part of willind, a personal AI assistant
project, where it displayed the images, videos and reports the assistant produced. This
repository is a standalone extraction: project-specific paths and names were replaced
with options, and the tests were ported to synthetic fixtures.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
