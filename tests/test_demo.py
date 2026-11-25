"""The example must fail rather than print a successful-looking broken response."""
import importlib.util
from pathlib import Path
import sys

import pytest


def test_demo_checks_response_status(monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'examples' / 'demo.py'
    spec = importlib.util.spec_from_file_location('gallery_demo', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, 'argv', [str(path)])
    monkeypatch.setattr(module, 'request', lambda *a, **kw: (500, {}, b'broken'))
    with pytest.raises(AssertionError, match='start page'):
        module.main()
