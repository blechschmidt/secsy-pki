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
| Theme, extensions, validation policy | [`website/mkdocs.yml`](https://github.com/blechschmidt/secsy-pki/blob/main/website/mkdocs.yml) (base config; the build appends the generated `nav:`) |
| Landing page | [`website/index.md`](https://github.com/blechschmidt/secsy-pki/blob/main/website/index.md) — the only page written for the site |
| Styling, favicon | [`website/assets/`](https://github.com/blechschmidt/secsy-pki/tree/main/website/assets) |
| Edit-link fix-ups for the two synthesized pages | [`website/hooks.py`](https://github.com/blechschmidt/secsy-pki/blob/main/website/hooks.py) |
| Pinned toolchain | [`website/requirements.txt`](https://github.com/blechschmidt/secsy-pki/blob/main/website/requirements.txt) |
| Staging + navigation generator | [`scripts/build-docs.py`](https://github.com/blechschmidt/secsy-pki/blob/main/scripts/build-docs.py) |
| Publishing workflow | [`.github/workflows/docs.yaml`](https://github.com/blechschmidt/secsy-pki/blob/main/.github/workflows/docs.yaml) |

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
  (branch `main`; override with `DOCS_REF`). Readers land on the real
  source instead of a 404.
* **Links to a directory** (`examples/ssh-pki/`) become links to its
  `README.md`, because a static site has no directory listing.
* **The project README** is staged as `overview.md` — `index.md` is the landing
  page — and the ~19 links that pointed at it are retargeted.

Everything else is copied byte for byte.

### The navigation is derived, not maintained

The site's menu is generated from the indexes
[`scripts/check-docs.sh`](https://github.com/blechschmidt/secsy-pki/blob/main/scripts/check-docs.sh)
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

[`.github/workflows/docs.yaml`](https://github.com/blechschmidt/secsy-pki/blob/main/.github/workflows/docs.yaml)
builds the site on every push to `main` that touches documentation, and
deploys it to GitHub Pages with `actions/deploy-pages`. Pull requests build the
site too — the same strict build — but do not deploy, so a broken link is
caught in review rather than in production. The workflow needs no secrets: it
authenticates to Pages with the run's OIDC token (`id-token: write`).

### What the repository has to allow

Two repository settings gate publishing. Both are one-time, both need a
repository **admin**, and neither can be done by the workflow itself:

* **Settings → Pages → Build and deployment → Source: GitHub Actions.** The
  workflow calls `actions/configure-pages` with `enablement: true`, but that
  only re-asserts the source on a site that already exists. *Creating* the site
  requires the repository-administration permission, which `GITHUB_TOKEN` does
  not carry however `permissions:` is written — the step fails with
  `Create Pages site failed: Resource not accessible by integration`. Enable it
  in the settings UI, or once via the REST API:

    ```bash
    gh api -X POST repos/blechschmidt/secsy-pki/pages -f build_type=workflow
    ```

* **The `github-pages` environment must allow the publishing branch to deploy.**
  The environment GitHub creates for Pages permits only the default branch, and
  a branch it does not permit is rejected with `Branch is not allowed to deploy
  to github-pages due to environment protection rules`. This workflow publishes
  from `main`, which *is* the default branch, so nothing has to be added today —
  but move the deploy to any other branch and it must be added under Settings →
  Environments → github-pages → deployment branches.

!!! warning "A deploy that does not deploy is a failed deploy"

    The deploy job used to run `configure-pages` under `continue-on-error` and
    downgrade a failure to a green run with an explanatory notice, on the
    premise that the repository was private and Pages was out of reach on the
    Free plan. The repository is public and that premise is gone — but the
    masking outlived it, and the site sat empty behind **eight consecutive
    successful runs**, because nobody reads a notice attached to a green check.

    Both steps now fail the job. If the site stops updating, the run is red and
    says which of the two settings above regressed.

The rendered site is attached to every run — deploying or not — as the
**`github-pages` artifact**, so it can always be downloaded and opened locally.

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
