---
title: "Security runbook drill (#142)"
date: 2026-10-25
summary: "The maintainer exercised private intake, coordination, a fix, TestPyPI release and withdrawal, disclosure on paper, and cleanup on a made-up report."
---
The maintainer ran this drill of `SECURITY.md` end to end on a made-up report about [`guardana-drill` on TestPyPI](https://test.pypi.org/project/guardana-drill/). This throwaway package is not a Guardana distribution. No real Guardana release was touched. All times below are UTC.

## Intake and coordination

The simulated e-mailed report arrived on 2026-10-22 at 07:56:05. It described `guardana-drill` `0.0.1` printing a placeholder instead of its version. The maintainer moved it into a draft advisory at 07:56:07, within seconds and inside the 14-day first-response promise.

The simulated first response at 07:56:15 recorded receipt, private coordination and the default 90-day disclosure window. No CVE was requested because the report was low severity and made up. The simulated reporter declined credit.

## The fix

The maintainer prepared the fix on the advisory's temporary private fork. The branch changed one drill file and no product code. Nothing appeared in a public branch, issue or pull request.

Disclosure was exercised on paper. The advisory fields were prepared and checked: affected `<= 0.0.1`, patched `0.0.2`, severity low, no CVE. A `### Security` changelog line was also prepared and checked. Neither was published because the report was made up.

## Release and withdrawal on TestPyPI

The first build named a private draft in its public package metadata. It was rebuilt without that reference before publication. Nothing published named a private draft.

On 2026-10-25 at 19:02, the maintainer uploaded `0.0.1`, then `0.0.2`, with a wheel and sdist for each, to TestPyPI only:

```console
$ uv publish --publish-url https://test.pypi.org/legacy/
```

The uploaded hashes matched the build. Before withdrawal, checks used Python `3.12` in a fresh environment with the TestPyPI index. The exact pin `guardana-drill==0.0.1` printed the made-up defect:

```console
version: <placeholder>
```

An unpinned install of `guardana-drill` got `0.0.2` and printed the fix:

```console
version: 0.0.2
```

At about 19:10, the maintainer yanked `0.0.1` on TestPyPI with the reason `Security runbook drill: made-up defect, fixed in 0.0.2.` The API showed `0.0.1` yanked with that reason and `0.0.2` live.

Checks at 19:13 used `pip` and `uv` in fresh environments. An exact pin `==0.0.1` still installed the release with a yank warning in both. An unpinned install got `0.0.2`. For the range `<0.0.2`, `pip` refused installation and reported:

```console
Ignored the following yanked versions: 0.0.1
```

The first `uv` resolution of `<0.0.2`, minutes after the yank, still selected `0.0.1`. A rerun at about 19:15 refused it and reported:

```console
guardana-drill==0.0.1 was yanked
```

## The dry withdrawal path

The remaining steps in “If a release is withdrawn” would have touched real releases. The maintainer wrote out these commands and checked their required credentials, but did not run them:

```console
$ gh api -X DELETE /orgs/guardana/packages/container/<image>/versions/<id>
$ docker buildx imagetools create -t ghcr.io/guardana/<image>:X.Y ghcr.io/guardana/<image>@<last good digest>
$ git -c tag.gpgSign=false tag -f vX.Y <previous vX.Y.Z>^{commit} && git push -f origin vX.Y
$ gh release edit vX.Y.Z --prerelease --notes-file <reason>
```

These covered deleting ghcr image versions, moving the `X.Y` image tag and `vX.Y` Action tag back, and marking the GitHub Release pre-release with a reason. Package write access was still missing for the image-tag step.

## Cleanup

At 19:17 on 2026-10-25, the draft advisory was closed without publication, the advisory's temporary private fork was deleted, and the account-wide TestPyPI token was removed. The TestPyPI project stayed as evidence, with `0.0.1` yanked and `0.0.2` live.

## Lessons

1. No TestPyPI credential is kept on the release machine; the maintainer creates one for a drill and removes it afterward.
2. The GitHub CLI token now has `read:packages`, `delete:packages` and `delete_repo`, added after the drill exposed their absence. It still lacks `write:packages`; the maintainer must grant it before a real withdrawal.
3. The advisory's temporary private fork fills asynchronously, taking about a minute. The maintainer waits for it to fill before reading git refs, which fail until then.
4. A project-scoped token cannot exist before the project's first upload. The maintainer uses an account-wide token for a new name's first release and removes it after use.
5. The project treats any credential copied outside the keychain as exposed and removes it after use.
6. The project checks public package metadata for private draft references and rebuilds without them before publication.
7. An exact pin still installs a yanked release. The advisory and release notes tell those users to move.
8. A resolver can briefly see a yanked release as live. The maintainer checks withdrawal again before announcing completion.
