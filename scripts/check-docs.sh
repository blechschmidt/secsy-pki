#!/usr/bin/env bash
#
# check-docs.sh — structural integrity gate for the documentation tree.
#
# The guides in docs/ are grouped into topic sections (docs/<section>/), each
# with its own index, and docs/README.md is the map over those sections. That
# layout is only useful while it stays true, and three things rot silently:
#
#   1. a moved or renamed page leaves dangling links behind;
#   2. a new page lands in a section folder but never reaches an index, so it is
#      reachable only by guessing the filename;
#   3. a `docs/<page>.md` path quoted in a Go comment, config.yaml, the Helm
#      chart or an alert annotation keeps pointing at where the page used to be.
#
# This script fails on all three. It needs no HSM, no database and no build —
# just a checkout — so it runs as a required CI job and via `make docs-check`.
#
# Usage:  scripts/check-docs.sh
# Exit:   0 = clean, 1 = problems found (each printed with file and target)

set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import os, re, subprocess, sys

ROOT = os.getcwd()
SKIP_DIRS = {".git", ".cloop", "node_modules", "dist", "coverage", "test-ssh"}

# Pages written for the documentation site (scripts/build-docs.py) rather than
# for the repository. They are staged at the repository root, so their relative
# links are authored against ROOT, not against the folder they are stored in.
SITE_AUTHORED = {"website/index.md"}

LINK_RE   = re.compile(r'\]\(\s*([^)\s]+?)\s*\)')
REFDEF_RE = re.compile(r'^\s*\[[^\]]+\]:\s*(\S+)', re.M)
EXTERNAL  = re.compile(r'^(https?:|mailto:|tel:|data:|#)')

problems = []


def rel(p):
    return os.path.relpath(p, ROOT)


def md_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        out += [os.path.join(dirpath, f) for f in filenames if f.endswith(".md")]
    return sorted(out)


def slugify(heading):
    """GitHub's heading -> anchor rule: strip formatting and punctuation,
    lowercase, then turn EACH remaining space into a hyphen."""
    s = heading.strip().lower()
    s = re.sub(r'`', '', s)
    s = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', s)      # [text](url) -> text
    s = re.sub(r'[*_]', '', s)
    s = re.sub(r'[^\w\s-]', '', s)
    return re.sub(r'\s', '-', s.strip())


_anchors = {}


def anchors_of(path):
    if path in _anchors:
        return _anchors[path]
    found, fenced = set(), False
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        _anchors[path] = found
        return found
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = re.match(r'^(#{1,6})\s+(.*?)\s*#*\s*$', line)
        if not m:
            continue
        base = slugify(m.group(2))
        if base in found:                                # GitHub de-duplicates
            n = 1
            while f"{base}-{n}" in found:
                n += 1
            base = f"{base}-{n}"
        found.add(base)
    for m in re.finditer(r'<a\s+(?:id|name)="([^"]+)"', text):
        found.add(m.group(1))
    _anchors[path] = found
    return found


def link_targets(text):
    return LINK_RE.findall(text) + REFDEF_RE.findall(text)


# ---------------------------------------------------------------- 1 + 2. links
checked = 0
for f in md_files():
    text = open(f, encoding="utf-8").read()
    for target in link_targets(text):
        if EXTERNAL.match(target):
            continue
        target = target.split(' ')[0].strip('<>')
        path, _, anchor = target.partition('#')
        if not path:
            continue
        checked += 1
        base = ROOT if rel(f) in SITE_AUTHORED else os.path.dirname(f)
        resolved = os.path.normpath(os.path.join(base, path))
        if not os.path.exists(resolved):
            problems.append(f"broken link   {rel(f)} -> {target}")
        elif anchor and resolved.endswith(".md") and anchor not in anchors_of(resolved):
            problems.append(f"missing anchor {rel(f)} -> {target}")

# ------------------------------------------------------- 3. every page indexed
docs = os.path.join(ROOT, "docs")
sections = sorted(d for d in os.listdir(docs) if os.path.isdir(os.path.join(docs, d)))

map_links = set(link_targets(open(os.path.join(docs, "README.md"), encoding="utf-8").read()))
for section in sections:
    index = os.path.join(docs, section, "README.md")
    if not os.path.exists(index):
        problems.append(f"section {section}/ has no README.md index")
        continue
    if f"{section}/README.md" not in map_links:
        problems.append(f"section {section}/ is not linked from the docs/README.md map")
    listed = {t.split('#')[0] for t in link_targets(open(index, encoding="utf-8").read())}
    for page in sorted(os.listdir(os.path.join(docs, section))):
        if page.endswith(".md") and page != "README.md" and page not in listed:
            problems.append(f"docs/{section}/{page} is not listed in docs/{section}/README.md")

for page in sorted(os.listdir(docs)):
    if page.endswith(".md") and page != "README.md":
        problems.append(f"docs/{page} sits outside a topic section")

# ------------------------------------- 4. docs paths quoted in code and config
tracked = subprocess.run(["git", "grep", "-Il", "docs/"], capture_output=True,
                         text=True).stdout.split()
for f in tracked:
    if f.startswith(".cloop/"):
        continue
    try:
        text = open(f, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    for quoted in sorted(set(re.findall(r'docs/[A-Za-z0-9._/-]*\.md', text))):
        if not os.path.exists(os.path.join(ROOT, quoted)):
            problems.append(f"stale doc path  {f} -> {quoted}")

# --------------------------------------------------------------------- verdict
if problems:
    print(f"docs check FAILED — {len(problems)} problem(s):\n")
    for p in problems:
        print(f"  {p}")
    sys.exit(1)

pages = sum(1 for f in md_files() if rel(f).startswith("docs/"))
print(f"docs check OK — {checked} relative links resolve, "
      f"{pages} pages across {len(sections)} sections, all indexed")
PY
