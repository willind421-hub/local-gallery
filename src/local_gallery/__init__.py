"""Local Gallery - read-only web gallery for local folders of generated artefacts."""
from .gallery import (
    classify_ext,
    content_disposition,
    is_hidden,
    list_dir,
    main,
    parse_roots,
    render_dir_page,
    render_roots_page,
    safe_resolve,
    serve,
)

__version__ = "0.1.0"

__all__ = [
    "classify_ext",
    "content_disposition",
    "is_hidden",
    "list_dir",
    "main",
    "parse_roots",
    "render_dir_page",
    "render_roots_page",
    "safe_resolve",
    "serve",
    "__version__",
]
