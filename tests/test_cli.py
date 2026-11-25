"""CLI tests: default root = current directory, --root, env roots, env token."""
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from local_gallery import gallery


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOCAL_GALLERY_")}
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


class _Cli:
    """Run ``python -m local_gallery`` on a free port for the duration of a ``with``."""

    def __init__(self, args, cwd, env):
        self.port = _free_port()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "local_gallery", "--port", str(self.port), *args],
            cwd=str(cwd), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def __enter__(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(self.proc.stderr.read().decode("utf-8", "replace"))
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise AssertionError("server did not start")

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stderr.close()


def test_default_root_is_current_directory(tmp_path):
    work = tmp_path / "renders"
    work.mkdir()
    (work / "frame.png").write_bytes(b"png")
    with _Cli([], cwd=work, env=_clean_env()) as cli:
        st, page = _get(cli.port, "/")
        assert st == 200 and "/view?path=renders" in page
        st, page = _get(cli.port, "/view?path=renders")
        assert st == 200 and "frame.png" in page


def test_root_option_and_env_roots(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "one.png").write_bytes(b"png")
    with _Cli(["--root", f"demo={a}", "--root", str(b)], cwd=tmp_path,
              env=_clean_env()) as cli:
        st, page = _get(cli.port, "/")
        assert st == 200 and "/view?path=demo" in page and "/view?path=b" in page
        assert "one.png" in _get(cli.port, "/view?path=demo")[1]
    with _Cli([], cwd=tmp_path, env=_clean_env(LOCAL_GALLERY_ROOTS=f"left={a};right={b}")) as cli:
        st, page = _get(cli.port, "/")
        assert st == 200 and "/view?path=left" in page and "/view?path=right" in page


def test_token_from_environment(tmp_path):
    with _Cli([], cwd=tmp_path, env=_clean_env(LOCAL_GALLERY_TOKEN="test-only-value")) as cli:
        assert _get(cli.port, "/")[0] == 401
        assert _get(cli.port, "/?token=wrong")[0] == 401
        assert _get(cli.port, "/?token=test-only-value")[0] == 200


def test_bad_root_arguments_exit_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gallery, "serve", lambda *a, **k: pytest.fail("must not serve"))
    assert gallery.main(["--root", str(tmp_path / "missing")]) == 1
    d1, d2 = tmp_path / "x" / "same", tmp_path / "y" / "same"
    d1.mkdir(parents=True)
    d2.mkdir(parents=True)
    assert gallery.main(["--root", str(d1), "--root", str(d2)]) == 1
    out = capsys.readouterr().out
    assert "not a directory" in out and "duplicate root name" in out


def test_main_passes_options_to_serve(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(gallery, "serve", lambda roots, **kw: seen.update(roots=roots, **kw))
    monkeypatch.delenv("LOCAL_GALLERY_TOKEN", raising=False)
    monkeypatch.delenv("LOCAL_GALLERY_ROOTS", raising=False)
    monkeypatch.chdir(tmp_path)
    assert gallery.main(["--host", "127.0.0.1", "--port", "0"]) == 0
    assert seen["roots"] == {tmp_path.resolve().name: tmp_path.resolve()}
    assert seen["host"] == "127.0.0.1" and seen["port"] == 0 and seen["token"] is None


@pytest.mark.parametrize("spec", ["", "   ", "broken", "absent=missing"])
def test_invalid_explicit_env_roots_never_fall_back(tmp_path, monkeypatch, spec):
    seen = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOCAL_GALLERY_ROOTS", spec)
    monkeypatch.setattr(gallery, "serve", lambda *a, **kw: seen.append(a))
    assert gallery.main([]) == 1
    assert seen == []


@pytest.mark.parametrize("location", ["home", "drive"])
def test_implicit_broad_root_refused(tmp_path, monkeypatch, location):
    # Synthetic home; drive path is inspected only, never listed or served.
    cwd = tmp_path if location == "home" else Path(tmp_path.anchor)
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: cwd))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("LOCAL_GALLERY_ROOTS", raising=False)
    seen = []
    monkeypatch.setattr(gallery, "serve", lambda *a, **kw: seen.append(a))
    assert gallery.main([]) == 1
    assert seen == []


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "example.invalid"])
def test_nonloopback_without_token_refused_before_bind(tmp_path, monkeypatch, capsys, host):
    import http.server

    # Never bind a public interface or resolve a hostname, even on the RED run.
    monkeypatch.setattr(http.server, "ThreadingHTTPServer",
                        lambda *a, **kw: pytest.fail("must refuse before binding"))
    monkeypatch.delenv("LOCAL_GALLERY_TOKEN", raising=False)
    roots = {"demo": tmp_path.resolve()}
    with pytest.raises(ValueError, match="non-loopback.*token"):
        gallery.serve(roots, host=host, port=0)
    assert gallery.main(["--root", str(tmp_path), "--host", host, "--port", "0"]) == 1
    assert "non-loopback" in capsys.readouterr().out
