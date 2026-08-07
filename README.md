# Decky Plugins Extended (zany130 fork)

A custom Decky Loader plugin repository that merges community and custom
plugins into a single compatible store.  This is a fork maintained by
[zany130](https://github.com/zany130) and is deployed to Cloudflare Pages at:

**<https://zany130-decky-plugins-extended.pages.dev>**

## How to use on your Steam Deck

To install plugins from this extended repository, point Decky Loader to its
custom store URL.

1. **Set the Custom Store URL.**
   - Open the Quick Access Menu and select the Decky Loader plug icon.
   - Open **Settings** using the gear icon.
   - Open the **General** tab in Decky settings.
   - Find **Store Channel** and set it to `Custom`
   - Set **Custom Store** to:

  ```text
  https://zany130-decky-plugins-extended.pages.dev/plugins.json
  ```

2. **Browse plugins.**
   - Return to the Decky Store using the shopping bag icon. It will populate
     with the extended plugin catalog.

## View the catalogs

The generated JSON files are hosted on Cloudflare Pages and can be viewed in your browser:

- **Stable plugins:** [https://zany130-decky-plugins-extended.pages.dev/plugins.json](https://zany130-decky-plugins-extended.pages.dev/plugins.json)
- **Testing plugins:** [https://zany130-decky-plugins-extended.pages.dev/testing_plugins.json](https://zany130-decky-plugins-extended.pages.dev/testing_plugins.json)

## Developer guide

The generator fetches, hashes, and merges custom GitHub releases into the
upstream Deckbrew stable and testing catalogs. This is a minimal repository;
do not create or store planning artifacts in a `docs/` directory.

### Add a plugin

Add the plugin repository URL to `additional_plugins.txt`, one URL per line:

```text
https://github.com/beallio/SDH-Ludusavi
```

Each repository must have:

- A `plugin.json` file on its default branch with a `name` field. Decky
  identifies an installed plugin by that name, so the catalog entry has to use
  it or the store will never match the plugin you have installed and will never
  offer updates. A repository without `plugin.json` falls back to the
  `package.json` name, which usually differs (`sdh-ludusavi` vs
  `SDH-Ludusavi`) and has that consequence.
- A `package.json` file on its default branch, used for the author and as the
  fallback source for the description and tags.
- At least one GitHub release.
- Exactly one `.zip` asset on every release that should appear in the catalogs.

Tags and the description come from `plugin.json`'s `publish` block, matching
the official store; `package.json` `keywords` and `description` are only the
fallback. A plugin that declares `"flags": ["root"]` also gets a `root` tag,
because that is how the store card decides to show its "runs as root" warning.

Store card images come from `plugin.json`'s `publish.image`, the same field the
official store ingests. Cards are 320x200 and cropped with `object-fit: cover`,
so a wide banner works better than a tall icon. A repository that has no image,
still carries the template's placeholder (which points at the loader's own
repo), or whose image URL is gone falls back to the GitHub repository card at
`https://opengraph.githubassets.com/1/<owner>/<repo>`. To give a plugin a proper
image, get its author to set `publish.image` upstream.

Release tags are reduced to the version they contain, so `Release-0.7.1` and
`decky-romm-sync-v0.30.1` become `0.7.1` and `0.30.1`. Decky validates store
versions as semver before offering an update and silently ignores anything
else. Tags with no version in them at all (`nightly`, `dev-build`) are passed
through unchanged; keep those as GitHub prereleases so they stay out of the
stable catalog.

Stable releases are included in both catalogs. GitHub prereleases are included
only in the testing catalog. Releases with zero or multiple `.zip` assets are
skipped.

### Landing page

`static/index.html` is copied into `public/` on every build and served at the
site root. `public/` is build output and gitignored, so anything that should be
published has to live in `static/`, not `public/`.

### Store sorting

Decky Loader sorts the store server-side: the frontend appends
`?sort_by=<name|date|downloads>&sort_direction=<asc|desc>` to the store URL and
renders the returned array in order. Static files ignore query strings, so the
Cloudflare Pages Function in `functions/_middleware.js` reorders
`plugins.json` and `testing_plugins.json` per request, matching what
`plugins.deckbrew.xyz` returns for the same query (code-point name comparison,
`created` for date, `downloads` for downloads). Requests without a recognized
`sort_by` are passed through untouched.

Versions within a plugin are ordered by semver, highest first, not by release
date. Decky only ever reads `versions[0]`, so a late hotfix to an old branch or
a rolling tag would otherwise sit on top and suppress update detection. Versions
with no parseable number (`nightly`, `dev-build`) sort last.

### Install counts

Counts live in a D1 database rather than in the catalogs, which are rebuilt from
scratch on every deploy. The Pages Function folds them into the response before
sorting, so `sort_by=downloads` sees real numbers, and records a row when Decky
POSTs its increment after an install. Counts are *added* to whatever the entry
already carries, so plugins merged with an upstream entry keep Deckbrew's totals
and gain the installs made through this store. Without the binding everything
still works; custom entries just stay at zero.

Setup:

```sh
npx wrangler d1 create decky-plugin-counts
npx wrangler d1 execute decky-plugin-counts --remote --file=schema.sql
```

Then bind it in the Cloudflare Pages project under Settings -> Bindings as a D1
database with the variable name `DB`, for both Production and Preview.

The endpoint is unauthenticated, so anyone can POST to inflate a number. That is
acceptable for a personal store; do not read these as trustworthy statistics.

### Local development

This project uses [uv](https://docs.astral.sh/uv/) for Python dependency
management. Install `uv`, provide a GitHub token, and run the generator:

```sh
export GITHUB_TOKEN="your_personal_access_token"
uv run generate_json.py
```

`uv` installs the dependencies from `pyproject.toml` into an isolated virtual
environment. The generated catalogs are written to `public/plugins.json` and
`public/testing_plugins.json`.

Run the store unit tests with:

```sh
GITHUB_TOKEN=test-token uv run python -m unittest discover -s tests -v
```

The token must be able to read the configured repositories; the GitHub Actions
workflow uses its built-in `GITHUB_TOKEN`.

## Automation

Cloudflare Pages is connected to this repository and deploys on every push to
`main`. It runs `generate_json.py` as its build step, so the catalogs are
regenerated from upstream Deckbrew and GitHub at deploy time rather than being
committed — `public/` is gitignored and holds only local build output. The
build reads a `GITHUB_TOKEN` configured as an environment variable in the
Cloudflare Pages dashboard, and the same deploy publishes `functions/`.

The GitHub Actions workflow has two jobs, neither of which publishes anything.

`build` runs when generator inputs change and on manual dispatch. It generates
both catalogs with `uv` and validates their plugin IDs, names, version lists and
SHA-256 hashes, so a bad `additional_plugins.txt` entry surfaces as a failed
check instead of a failed Cloudflare build.

`refresh` runs every 6 hours and on manual dispatch. Because Cloudflare only
rebuilds on push, the catalog would otherwise stay frozen at whatever upstream
looked like at the last deploy. `check_for_updates.py` compares the live catalog
against the upstream catalog and the latest release of every configured
repository, and only when something is missing does the job POST the Cloudflare
deploy hook. The check asks whether a version is *absent* from the live entry
rather than whether the newest versions match, because merging GitHub releases
into upstream entries regularly leaves this catalog ahead of Deckbrew's.

To enable it, create a deploy hook under Pages -> Settings -> Builds &
deployments -> Deploy hooks, and store the URL as the repository secret
`CLOUDFLARE_DEPLOY_HOOK`. Without the secret the job fails loudly rather than silently
skipping the rebuild.

## Cloudflare Pages deployment

This fork is deployed via Cloudflare Pages Git integration.  The production
hostname is always **<https://zany130-decky-plugins-extended.pages.dev>**.

### Production configuration

| Setting | Value |
|---|---|
| Cloudflare project | `zany130-decky-plugins-extended` |
| Production branch | `main` |
| Framework preset | None |
| Build command | `python -m pip install uv && python -m uv run --frozen python generate_json.py` |
| Build output directory | `public` |
| Root directory | repository root (blank) |

### Required Cloudflare environment variable

`GITHUB_TOKEN` must be stored as an **encrypted** environment variable in the
Cloudflare Pages project (Settings → Environment variables).  It is used by
`generate_json.py` to read release information from GitHub.

- The token only needs the minimum access necessary to read public GitHub
  repository information.
- It must **never** be committed to Git or printed in build logs.
- Cloudflare automatically re-deploys `main` to the production hostname on
  every push.
- Pull requests receive temporary **preview** deployment URLs.  Preview URLs
  must not be used as permanent store URLs — they change with every commit.

### Optional GitHub Actions secret: `CLOUDFLARE_DEPLOY_HOOK`

The `refresh` workflow job uses this secret to trigger a Cloudflare rebuild
when upstream content may have changed without a commit to this repository.
Create a deploy hook under Pages → Settings → Builds & deployments → Deploy
hooks, and store the URL as the `CLOUDFLARE_DEPLOY_HOOK` repository secret.
The URL is never printed in logs.

## Security auditing

Security auditing is provided by the standalone
[Decky Plugin Auditor](https://github.com/zany130/decky-plugin-auditor).
This store owns the consumer-side inputs and workflow policy:

- `additional_plugins.txt` — repositories to audit
- `security-policy.yml` — classification and enforcement policy
- `security-allowlist.yml` — artifact-scoped review exceptions
- `.github/workflows/plugin-security-audit.yml` — pull-request/manual audits
- `.github/workflows/scheduled-security-audit.yml` — recurring full-store audits

The workflows install the auditor from an immutable commit SHA and pass every
store-owned input explicitly. The auditor repository owns scanner
implementation, packaged rules, report generation, and scanner-specific tests.
No plugin code is imported or executed during an audit.

See the standalone auditor README for the current scanner inventory, report
schema, threat model, and implementation details.

### Classifications and enforcement

| Classification | Meaning |
|---|---|
| `PASS` | No blocking or review-required findings. |
| `PASS_WITH_WARNINGS` | Non-blocking findings or optional scanner limitations. |
| `MANUAL_REVIEW` | Findings that require a human decision before acceptance. |
| `BLOCK` | Findings that policy considers unacceptable. |
| `AUDIT_ERROR` | The audit could not reach a conclusion. |

The store currently controls enforcement through `security-policy.yml`. In
report-only mode, review/block classifications are surfaced without blocking a
merge; internal audit failures still fail CI.

### Running the standalone auditor locally

Install `decky-plugin-auditor` according to its README, then run it with this
store's configuration:

```sh
export GITHUB_TOKEN="your_personal_access_token"

# Audit every configured repository:
decky-audit \
  --all \
  --plugins-file additional_plugins.txt \
  --policy security-policy.yml \
  --allowlist security-allowlist.yml \
  --output-dir security-reports

# Audit plugin-list changes relative to main:
decky-audit \
  --changed \
  --base-ref origin/main \
  --plugins-file additional_plugins.txt \
  --policy security-policy.yml \
  --allowlist security-allowlist.yml \
  --output-dir security-reports

# Audit one repository using the store policy:
decky-audit \
  --repository https://github.com/owner/repo \
  --policy security-policy.yml \
  --allowlist security-allowlist.yml \
  --output-dir security-reports
```

Reports are written to `security-reports/security-report.json` and
`security-reports/security-report.md`. Generated reports are gitignored.

### Adding a narrow allowlist exception

Exceptions belong in `security-allowlist.yml` and should be scoped to the exact
artifact hash whenever possible:

```yaml
exceptions:
  - repository: owner/plugin-name
    release: "1.2.3"
    artifact_sha256: "exact-64-character-hex-sha256-of-the-release-zip"
    rule: ROOT_ACCESS
    reason: >
      Hardware-control plugin requires a documented privileged helper.
    approved_by: zany130
    expires: "2027-01-01"
```

Allowlist decisions remain store-owned; the standalone auditor only evaluates
them against the supplied report inputs.

### Scheduled audits

`scheduled-security-audit.yml` runs every six hours and audits the newest
eligible release of every configured repository. The store owns cache and
artifact retention. Cache invalidation includes the immutable auditor revision
plus the store configuration, so a new auditor revision or policy/list change
cannot silently reuse incompatible cached reports.

## Attribution

This repository is a fork of the original
[decky-plugins-extended](https://github.com/beallio/decky-plugins-extended)
project created and maintained by [beallio](https://github.com/beallio).

| | |
|---|---|
| **Original upstream project** | <https://github.com/beallio/decky-plugins-extended> |
| **This fork's source repository** | <https://github.com/zany130/decky-plugins-extended> |
| **This fork's live Cloudflare Pages deployment** | <https://zany130-decky-plugins-extended.pages.dev> |

This fork is independently maintained by [zany130](https://github.com/zany130)
and is not affiliated with or endorsed by the upstream project owner.  It does
not control or maintain `decky-extended-plugins.beallio.com`.