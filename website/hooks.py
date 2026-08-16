"""MkDocs hooks for the published documentation site.

The site is built from a staged tree (``scripts/build-docs.py``) that mirrors
the repository layout, so MkDocs' own ``edit_uri`` handling produces correct
"edit this page" links for every page that is copied verbatim.

Two pages are not: the landing page is authored at ``website/index.md`` and
staged as ``index.md``, and the project README is staged as ``overview.md``
because ``index.md`` is taken. Without the fix-ups below, their edit and view
buttons would point at repository paths that do not exist.
"""

from __future__ import annotations

# Staged page -> path in the repository (None removes the edit/view buttons).
EDIT_URI_OVERRIDES: dict[str, str | None] = {
    "index.md": "website/index.md",
    "overview.md": "README.md",
}


def on_files(files, config):  # noqa: ARG001 - MkDocs event signature
    for file in files:
        if file.src_uri in EDIT_URI_OVERRIDES:
            file.edit_uri = EDIT_URI_OVERRIDES[file.src_uri]
    return files
