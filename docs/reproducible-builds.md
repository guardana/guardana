---
title: "Reproducible builds"
nav_order: 325
summary: "rebuild a release from its tag and check, file by file, that it matches what PyPI serves byte for byte"
status: beta
---

# Reproducible builds

`scripts/reproduce_release.py` rebuilds a release from its tag and compares every file
with PyPI byte for byte. Each release publishes a wheel and a source distribution for
every package under `packages/`, and for the reference pack (`examples/reference_pack`)
when configured to publish it. A match means the published file is exactly what the
tagged source builds into. You need not trust the machine that built it.

## Run the check yourself

You need `git`, [uv](https://docs.astral.sh/uv/) and network access to `pypi.org` and
`files.pythonhosted.org`.

Run the script from a current checkout and point it at a clean checkout of the release
tag. A tag released before the script existed has no copy of it, so the script always
comes from the current checkout:

```bash
git clone https://github.com/guardana/guardana
cd guardana
git worktree add --detach ../guardana-v1.0.0rc2 v1.0.0rc2
uv run --no-project python scripts/reproduce_release.py 1.0.0rc2 --source ../guardana-v1.0.0rc2
```

Given no source checkout, the script builds the checkout it runs from, so in a checkout
of a tag that carries the script this is enough:

```bash
uv run --no-project python scripts/reproduce_release.py VERSION
```

The script rejects a checkout whose packages carry another version. Build from a clean
checkout: a source distribution includes every file in the package directory that git
does not ignore. A stray local file makes it differ.

## How the rebuild matches the release

The release workflow runs `uv build packages/<name>/ --out-dir dist/` for every directory
under `packages/`, and `uv build examples/reference_pack`, from the checkout root under
Python 3.12. The script finds the packages the same way and uses the same commands and
interpreter. Before building, it removes `SOURCE_DATE_EPOCH` and any `UV_*` setting from
your shell because the release sets neither. Without `SOURCE_DATE_EPOCH`, hatchling gives
every archive member one fixed date. Each package pins its build backend exactly
(`hatchling==<version>` in `[build-system]`), so rebuilds use the release's backend.
A tag whose packages name hatchling without a version uses the newest hatchling uv
resolves. It reproduces only while that version matches the one its wheels name in their
`WHEEL` file.

## What it compares

For each package, the script reads the release's file list from PyPI's JSON API
(`https://pypi.org/pypi/<name>/<version>/json`). It uses the name and version in the
package's `pyproject.toml`. It downloads each file and checks its sha256 against the API's
digest before comparing anything.

Equal bytes mean the file reproduces. Otherwise, the script opens both archives: wheels
as zip files and source distributions as gzip-compressed tar files. It names the first
difference:

- differing member lists: members published but not rebuilt, members rebuilt but not
  published, or the same members in another order;
- the first member with differing bytes, with both sizes; for a wheel's `RECORD`, entries
  with differing hashes or sizes; for its `WHEEL`, the two build backends;
- differing member metadata: timestamp, permissions, owner, compression method or another
  header field;
- for a source distribution, a differing gzip header timestamp;
- identical members and metadata with differing compressed bytes, as another zlib build
  produces from the same data.

## Reading the result

Each file gets one line, followed by a count:

| Result | It means |
|---|---|
| `REPRODUCES` | the rebuilt and published files have identical bytes |
| `DIFFERS` | the bytes differ; the next line names the first difference found |
| `NOT CHECKED` | the file was not compared: PyPI could not be read or lists no files, a download did not match its digest, the build failed, a published file was not rebuilt, or a rebuilt file is not published |
| `NOT PUBLISHED` | PyPI has no reference pack release at the tag's version because this release did not publish it; this does not change the exit status |

`NOT CHECKED` is never a pass. The script could not establish whether the file reproduces
and states why.

The exit status is `0` when every published file reproduces, `1` when any file differs, and
`2` when any file is not checked and none differs. It is also `2` when the check cannot
start: the checkout carries another version, a package directory has no readable
`pyproject.toml`, or the script stops on an unexpected error.

## In CI

`.github/workflows/reproducibility.yml` runs the check after each successful release
workflow run and on demand for any version from the Actions tab (`Run workflow`, with
the version). It checks out `v<version>`, takes the script from the commit the workflow
runs from, and has read-only repository access. It does not run on a push because PyPI
has no files for a version until its release publishes them. If the check runs before
PyPI lists the version, each package is `NOT CHECKED` and the job fails with exit status
`2`. Run it again by hand once the files are on PyPI.

## What a match does not prove

A match shows that the tagged source builds into the published files. It does not show
that the source is safe. Build provenance, SBOMs and review of each change serve that
purpose; see
[What a release publishes, and how to check it yourself](../SECURITY.md#what-a-release-publishes-and-how-to-check-it-yourself).
The build backend's dependencies are resolved at build time. A change in one could change
a rebuild; the check would report the difference.
