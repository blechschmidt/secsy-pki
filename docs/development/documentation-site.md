# Documentation site (GitHub Pages)

The guides in this repository are also published as a searchable, styled site:

**<https://blechschmidt.github.io/secsy-pki/>**

(That URL serves once GitHub Pages is available for the repository — see
[what the repository has to allow](#what-the-repository-has-to-allow). Everything
else on this page works today: `make docs-site` renders the same site locally,
and CI builds it on every documentation change.)

The site is not a second copy of the documentation. It is *this* Markdown tree —
`docs/`, `README.md`, `ARCHITECTURE.md`, `TESTING.md` and `examples/` — staged
and rendered by [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/).
Nothing is authored twice, so the site cannot drift from the repository, and
every page carries an **edit** link back to the file it came from.

| Piece | Where |
|-------|-------|
| Theme, extensions, validation policy | [`website/mkdocs.yml`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/website/mkdocs.yml) (base config; the build appends the generated `nav:`) |
| Landing page | [`website/index.md`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/website/index.md) — the only page written for the site |
| Styling, favicon | [`website/assets/`](https://github.com/blechschmidt/secsy-pki/tree/enterprise/website/assets) |
| Edit-link fix-ups for the two synthesized pages | [`website/hooks.py`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/website/hooks.py) |
| Pinned toolchain | [`website/requirements.txt`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/website/requirements.txt) |
| Staging + navigation generator | [`scripts/build-docs.py`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/scripts/build-docs.py) |
| Publishing workflow | [`.github/workflows/docs.yaml`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/.github/workflows/docs.yaml) |

## Building it locally

```bash
make docs-site       # build into dist/docs-site/ (strict; fails on a broken link)
make docs-serve      # live preview on http://127.0.0.1:8000
```

Both targets create a throw-away virtualenv at `dist/docs-venv/` from
`website/requirements.txt`, so the only prerequisite is Python 3. Point
`DOCS_VENV` elsewhere to reuse one, and `DOCS_PORT` to move the preview server.
Nothing about the site build touches Go, an HSM or a database.

`make docs-serve` renders the *staged* tree, so re-run it after editing a page
under `docs/` to pick the change up.

## How a page reaches the site

`scripts/build-docs.py` stages the repository's Markdown into `dist/docs-src/`,
mirroring the repository layout so that the ~900 relative links between pages
keep resolving untouched. It rewrites only what cannot survive the move:

* **Links to files the site does not carry** — Go packages, the Helm chart,
  scripts, `config.yaml`, the `Makefile` — become links to that file on GitHub
  (branch `enterprise`; override with `DOCS_REF`). Readers land on the real
  source instead of a 404.
* **Links to a directory** (`examples/ssh-pki/`) become links to its
  `README.md`, because a static site has no directory listing.
* **The project README** is staged as `overview.md` — `index.md` is the landing
  page — and the ~19 links that pointed at it are retargeted.

Everything else is copied byte for byte.

### The navigation is derived, not maintained

The site's menu is generated from the indexes
[`scripts/check-docs.sh`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/scripts/check-docs.sh)
already enforces:

* [`docs/README.md`](../README.md) gives the **section order** and the short,
  curated page titles (`Cloud KMS backend (AWS / Azure / Google)` rather than
  the page's longer `H1`);
* each section's own `README.md` gives the **pages in that section**, in the
  order they are listed.

So a new guide joins the site's menu the moment it is added to its section
index — which the docs gate requires anyway. There is no third list to keep in
sync, and no way to publish a page that the repository's own indexes do not
mention. A page found in a section folder but missing from its index is
appended rather than dropped, and reported on stderr.

### A second link gate

The site is built with `mkdocs --strict` and MkDocs' link validation turned up,
which fails the build on:

* a relative link that does not resolve **in the rendered site**;
* a `#heading-anchor` that no heading produces (anchors use GitHub-compatible
  slugs, so the links written for GitHub keep working);
* a page that exists but is missing from the navigation.

`make docs-check` (structure, no dependencies) and `make docs-site` (rendering)
therefore check different things, and both run in CI.

## Publishing

[`.github/workflows/docs.yaml`](https://github.com/blechschmidt/secsy-pki/blob/enterprise/.github/workflows/docs.yaml)
builds the site on every push to `enterprise` that touches documentation, and
deploys it to GitHub Pages with `actions/deploy-pages`. Pull requests build the
site too — the same strict build — but do not deploy, so a broken link is
caught in review rather than in production. The workflow needs no secrets: it
authenticates to Pages with the run's OIDC token (`id-token: write`).

### What the repository has to allow

!!! warning "Pages is not available for private repositories on the Free plan"

    `blechschmidt/secsy-pki` is private, and GitHub answers
    `Your current plan does not support GitHub Pages for this repository`.
    **Until the repository is made public** (or the account moves to a plan that
    includes Pages for private repositories), nothing is published at the URL
    above. No change to this workflow is needed when that happens — the next
    push publishes.

The deploy job treats that as a skip rather than a failure: `configure-pages`
runs with `continue-on-error`, and if it does not succeed the job emits a notice
explaining why and finishes green. The strict build still gates the change, and
the rendered site is still attached to the run as the **`github-pages`
artifact**, so it can be downloaded and opened locally in the meantime.

Two more settings matter once Pages *is* available:

* **Settings → Pages → Build and deployment → Source: GitHub Actions.** The
  workflow calls `actions/configure-pages` with `enablement: true`, which turns
  this on by itself if the token is allowed to.
* If the `github-pages` environment restricts deployments to protected
  branches, add `enterprise` to its deployment-branch rules — otherwise the
  deploy step fails while the build step stays green.

## Changing the look

Everything visual lives in `website/`:

* `mkdocs.yml` — theme palette (indigo, with a light/dark/system toggle), the
  enabled Material features, and the Markdown extensions available to pages.
* `assets/extra.css` — the landing-page hero plus small readability fixes for
  the wide index tables and long inline `code` spans the guides use.
* `index.md` — the landing page, written with Material's
  [grid cards](https://squidfunk.github.io/mkdocs-material/reference/grids/).
  Its links are relative to the repository root, because that is where it is
  staged.

Bump `mkdocs-material` in `website/requirements.txt` deliberately and re-run
`make docs-site`; the strict build is what tells you whether a theme change
broke anything.

---

↩ Back to the [development index](README.md) · [documentation map](../README.md)
