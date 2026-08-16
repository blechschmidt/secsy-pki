#!/usr/bin/env python3
"""build-docs.py — assemble the MkDocs source tree for the documentation site.

The guides live where contributors and GitHub expect them: `docs/` split into
topic sections, plus `README.md`, `ARCHITECTURE.md`, `TESTING.md` and
`examples/` at the repository root. `scripts/check-docs.sh` keeps that tree's
~900 relative links and its section indexes honest. The published site must not
fork it into a second copy that rots.

So this script publishes the repository's own Markdown rather than a copy of
it. It stages the files into `dist/docs-src/`, *mirroring the repository
layout* so that every relative link between them keeps resolving untouched, and
rewrites only what cannot survive the move:

  * links to things that are not part of the site (Go packages, Helm charts,
    scripts, YAML configs, Makefile) become links to that file on GitHub;
  * links to a directory that has a `README.md` become links to that README,
    since a static site cannot serve a directory listing;
  * the project README is staged as `overview.md` — `index.md` is the site's
    landing page — and links that pointed at it are retargeted.

The navigation is derived from the indexes `check-docs.sh` already enforces:
`docs/README.md` gives the section order and the short, curated page titles;
each section's own `README.md` gives the pages it contains. A new page joins
the site's menu the moment it is indexed, and there is no third list to keep in
sync. Anything found in a section folder but missing from its index is appended
rather than dropped (and reported, so `check-docs.sh` can be believed).

Output: `dist/mkdocs.yml` + `dist/docs-src/`, ready for `mkdocs build`.
Run it through `make docs-site` (build) or `make docs-serve` (live preview).
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
SRC = os.path.join(DIST, "docs-src")
OUT_CONFIG = os.path.join(DIST, "mkdocs.yml")
BASE_CONFIG = os.path.join(ROOT, "website", "mkdocs.yml")

REPO_URL = "https://github.com/blechschmidt/secsy-pki"
# The branch off-site links point at. Overridable so a fork or a release branch
# can publish links into its own tree.
REF = os.environ.get("DOCS_REF", "enterprise")

# Inline links, optionally with a "title", and reference-style definitions.
LINK_RE = re.compile(r'(?P<open>\]\(\s*)(?P<target>[^)\s]+)(?P<rest>\s*(?:"[^"]*")?\s*\))')
REFDEF_RE = re.compile(r'(?P<open>^\s*\[[^\]]+\]:\s*)(?P<target>\S+)', re.M)
EXTERNAL_RE = re.compile(r'^(?:[a-z][a-z0-9+.-]*:|//|#)')
FENCE_RE = re.compile(r'^\s*(?:```|~~~)')

# Titles for the pages that are not part of a docs/ section.
ROOT_PAGES = [
    ("Project overview", "README.md", "overview.md"),
    ("Architecture", "ARCHITECTURE.md", "ARCHITECTURE.md"),
]
# Appended as the last entry of the section whose folder name is the key.
SECTION_EXTRAS = {
    "development": [("Running the test suites", "TESTING.md", "TESTING.md")],
}
# Pages written for the site rather than imported from the repository. Their
# links are authored against the position they are staged at, not the folder
# they are stored in.
SITE_AUTHORED = {"website/index.md"}

warnings: list[str] = []


def warn(message: str) -> None:
    warnings.append(message)


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def link_targets(text: str) -> list[tuple[str, str]]:
    """(link text, target) for every inline link, in document order."""
    return re.findall(r'\[([^\]]*)\]\(\s*([^)\s]+)', text)


def clean_title(text: str) -> str:
    """Link text -> nav label: drop emphasis, code ticks and stray whitespace."""
    text = re.sub(r'`([^`]*)`', r'\1', text)
    text = re.sub(r'\*+', '', text)
    return re.sub(r'\s+', ' ', text).strip()


def heading_of(repo_rel: str) -> str:
    for line in read(os.path.join(ROOT, repo_rel)).splitlines():
        if line.startswith("# "):
            return clean_title(line[2:])
    return posixpath.basename(repo_rel)


# --------------------------------------------------------------- staging map

def staged_files() -> dict[str, str]:
    """repo-relative source -> site-relative destination."""
    staged: dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "docs")):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".md"):
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
                staged[rel] = rel

    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "examples")):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".md"):
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
                staged[rel] = rel

    for _, source, dest in ROOT_PAGES:
        staged[source] = dest
    for extras in SECTION_EXTRAS.values():
        for _, source, dest in extras:
            staged[source] = dest

    staged["website/index.md"] = "index.md"
    return staged


# ------------------------------------------------------------ link rewriting

class Rewriter:
    def __init__(self, staged: dict[str, str]):
        self.staged = staged
        self.to_github = 0
        self.retargeted = 0
        self.missing = 0

    def target(self, target: str, orig_dir: str, staged_dir: str) -> str:
        path, sep, anchor = target.partition("#")
        if not path:
            return target                                   # same-page anchor

        resolved = posixpath.normpath(posixpath.join(orig_dir, path))
        if resolved.startswith(".."):                       # escapes the repo
            return target

        dest = self.staged.get(resolved)
        if dest is None and os.path.isdir(os.path.join(ROOT, resolved)):
            # A static site cannot serve a directory; use its README instead.
            dest = self.staged.get(posixpath.join(resolved, "README.md"))

        if dest is not None:
            new = posixpath.relpath(dest, staged_dir) if staged_dir else dest
            if new != path:
                self.retargeted += 1
            return new + sep + anchor

        absolute = os.path.join(ROOT, resolved)
        if not os.path.exists(absolute):
            self.missing += 1
            warn(f"link target does not exist: {orig_dir or '.'} -> {target}")
            return target
        # Off-site: source code, charts, scripts, configs. Send readers to the
        # file on GitHub rather than 404 on a page the site does not carry. Any
        # anchor rides along — GitHub understands #L42 on a blob.
        self.to_github += 1
        kind = "tree" if os.path.isdir(absolute) else "blob"
        return f"{REPO_URL}/{kind}/{REF}/{resolved}" + sep + anchor

    def text(self, text: str, orig_rel: str, staged_rel: str) -> str:
        staged_dir = posixpath.dirname(staged_rel)
        orig_dir = staged_dir if orig_rel in SITE_AUTHORED else posixpath.dirname(orig_rel)

        def replace(match: re.Match) -> str:
            target = match.group("target")
            if EXTERNAL_RE.match(target):
                return match.group(0)
            stripped = target.strip("<>")
            rewritten = self.target(stripped, orig_dir, staged_dir)
            if rewritten == stripped:
                return match.group(0)
            if target.startswith("<"):
                rewritten = f"<{rewritten}>"
            return match.group(0).replace(target, rewritten, 1)

        # Rewrite outside fenced blocks only: a link inside a code sample is
        # sample text, not navigation.
        out, fenced = [], False
        for line in text.splitlines(keepends=True):
            if FENCE_RE.match(line):
                fenced = not fenced
            elif not fenced:
                line = LINK_RE.sub(replace, line)
                line = REFDEF_RE.sub(replace, line)
            out.append(line)
        return "".join(out)


# ------------------------------------------------------------------ nav tree

def build_nav(staged: dict[str, str]) -> list:
    """Derive the site navigation from the enforced documentation indexes."""
    docs_map = read(os.path.join(ROOT, "docs", "README.md"))

    # Curated short titles: docs/README.md links every page with a nicer label
    # than its H1 ("Cloud KMS backend (AWS / Azure / Google)").
    curated: dict[str, str] = {}
    for text, target in link_targets(docs_map):
        target = target.split("#")[0]
        if target.endswith(".md") and not target.startswith("."):
            curated[posixpath.normpath(posixpath.join("docs", target))] = clean_title(text)

    # Section order and titles: "### 3. Issuance policy … — [`issuance/`](issuance/README.md)"
    sections = re.findall(
        r'^###\s+(?:\d+\.\s*)?(.+?)\s*[—-]\s*\[[^\]]*\]\(([A-Za-z0-9._-]+)/README\.md\)\s*$',
        docs_map, re.M)
    if not sections:
        sys.exit("build-docs: no sections found in docs/README.md — has the map format changed?")

    nav: list = [{"Home": "index.md"}]
    for title, source, dest in ROOT_PAGES:
        nav.append({title: dest})
    # The map itself: every section index links back to it as "↩ documentation map".
    nav.append({"Documentation map": "docs/README.md"})

    # Examples: ordered by the catalogue, titled by each recipe's own heading.
    examples_index = read(os.path.join(ROOT, "examples", "README.md"))
    example_pages, seen = ["examples/README.md"], set()
    for _, target in link_targets(examples_index):
        target = target.split("#")[0].rstrip("/")
        candidate = posixpath.normpath(posixpath.join("examples", target))
        if not candidate.endswith(".md"):
            candidate = posixpath.join(candidate, "README.md")
        if not candidate.startswith("examples/") or candidate == "examples/README.md":
            continue                                  # the catalogue also links out to docs/
        if candidate in staged and candidate not in seen:
            seen.add(candidate)
            example_pages.append(candidate)
    nav.append({"Examples": [example_pages[0]] + [{heading_of(p): p} for p in example_pages[1:]]})

    covered = {"docs/README.md"}
    for title, folder in sections:
        index = f"docs/{folder}/README.md"
        if index not in staged:
            warn(f"section {folder}/ has no README.md — skipped")
            continue
        entries: list = [index]
        covered.add(index)

        listed: list[str] = []
        for text, target in link_targets(read(os.path.join(ROOT, index))):
            target = target.split("#")[0]
            if "/" in target or not target.endswith(".md") or target == "README.md":
                continue
            page = f"docs/{folder}/{target}"
            if page in staged and page not in listed:
                listed.append(page)
                entries.append({curated.get(page) or clean_title(text): page})
                covered.add(page)

        # check-docs.sh requires every page to be indexed; if one slips through
        # anyway, publish it rather than lose it.
        for page in sorted(p for p in staged if p.startswith(f"docs/{folder}/")):
            if page not in covered:
                warn(f"{page} is missing from docs/{folder}/README.md — appended to the nav")
                entries.append({curated.get(page) or heading_of(page): page})
                covered.add(page)

        for extra_title, _, extra_dest in SECTION_EXTRAS.get(folder, []):
            entries.append({extra_title: extra_dest})

        nav.append({clean_title(title): entries})

    for page in sorted(p for p in staged if p.startswith("docs/")):
        if page not in covered:
            warn(f"{page} is in no section listed by docs/README.md — omitted from the nav")

    return nav


def dump_nav(nav: list, indent: int = 2) -> str:
    """Minimal YAML writer: nav entries are strings or single-key mappings."""
    lines = []

    def emit(items: list, level: int) -> None:
        pad = " " * (indent * level)
        for item in items:
            if isinstance(item, str):
                lines.append(f"{pad}- {item}")
                continue
            (key, value), = item.items()
            if isinstance(value, str):
                lines.append(f"{pad}- {json.dumps(key)}: {value}")
            else:
                lines.append(f"{pad}- {json.dumps(key)}:")
                emit(value, level + 2)

    lines.append("nav:")
    emit(nav, 1)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- main

def main() -> int:
    if not os.path.exists(BASE_CONFIG):
        sys.exit(f"build-docs: missing base config {BASE_CONFIG}")
    base = read(BASE_CONFIG)
    if re.search(r'^nav:', base, re.M):
        sys.exit("build-docs: website/mkdocs.yml must not define nav: — it is generated here")

    staged = staged_files()
    nav = build_nav(staged)

    if os.path.exists(SRC):
        shutil.rmtree(SRC)
    os.makedirs(SRC)

    rewriter = Rewriter(staged)
    for source, dest in sorted(staged.items()):
        target = os.path.join(SRC, dest)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(rewriter.text(read(os.path.join(ROOT, source)), source, dest))

    shutil.copytree(os.path.join(ROOT, "website", "assets"), os.path.join(SRC, "assets"))

    with open(OUT_CONFIG, "w", encoding="utf-8") as fh:
        fh.write("# GENERATED by scripts/build-docs.py — edit website/mkdocs.yml instead.\n")
        fh.write(base.rstrip("\n") + "\n\n")
        fh.write("# Derived from docs/README.md and the per-section README indexes.\n")
        fh.write(dump_nav(nav))

    for message in warnings:
        print(f"build-docs: warning: {message}", file=sys.stderr)

    print(f"build-docs: staged {len(staged)} pages into {os.path.relpath(SRC, ROOT)} "
          f"({rewriter.retargeted} links retargeted, {rewriter.to_github} pointed at GitHub, "
          f"{len(nav)} nav sections) -> {os.path.relpath(OUT_CONFIG, ROOT)}")
    return 1 if rewriter.missing else 0


if __name__ == "__main__":
    sys.exit(main())
