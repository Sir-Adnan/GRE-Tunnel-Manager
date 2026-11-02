# Releasing

Publish only when requested. Each release contains matching terminal, panel, frontend and installer versions. Keep previous tags and assets intact.

## Prepare the source

1. Review the full diff, including work completed before the release task. Update affected guides, both quick-start READMEs and `docs/CHANGELOG.md`.
2. Set the version in `src/core.sh` (`GTM_VERSION`). Copy it to `panel/internal/version/version.go`, `panel/web/src/lib/version.ts`, the frontend package and lock, `panel-install.sh` and `node-install.sh`, then update versioned test fixtures. `python3 tools/build.py --check` fails when a version copy differs. Go code and frontend text import those constants rather than repeating the number. Do not renumber historical changelog/archive entries.
3. Run `python3 tools/build.py`; do not edit generated `gre.sh`. Write the release notes in `panel/RELEASE.md`.
4. Confirm archived scripts and `gre-stable.sh` are unchanged. Check Markdown links and distinguish shipped features from proposals.

## Verify

Run the [development checks](DEVELOPMENT.md), including Python, modern ShellCheck, frontend clean build/lint/tests, Go race/vet and isolated namespace tests. Check both UI locales and mobile/desktop flows when the interface changes. CI also runs dependency/security checks; inspect failures before publication.

Build the frontend before packaging, then from the repository root:

```bash
python3 tools/package_panel.py
```

This creates Linux amd64/arm64 archives and `SHA256SUMS` in `panel/bin`. Each archive contains the executable with embedded frontend, matching `gre.sh`, project license and dependency notices. Binaries/build output are ignored by Git. Validate the archive contents, checksums and executable/helper version; run the amd64 binary on Linux. Cross-building arm64 does not prove execution on an arm64 host.

For disposable offline installation tests, use `sudo bash panel-install.sh --package-dir /path/to/packages --quick`. Never overwrite earlier release assets with a development archive.

## Publish

Commit reviewed source and fast-forward `main` without force pushing. Verify branch CI before pushing the matching annotated `vMAJOR.MINOR.PATCH` tag. The [release workflow](../.github/workflows/panel-release.yml) builds from that tag, reruns panel checks, creates both archives and publishes the release with `panel/RELEASE.md`. Dispatching against a source branch is refused.

After completion, verify:

- Remote `main`, the peeled tag and the release target point to the intended commit.
- The release is published, with both architecture archives and `SHA256SUMS`.
- Downloaded assets match the published checksums, contain the matching helper and report the requested version.
- The public installers select that same version; a package upgrade, followed by a browser refresh, is required to load the new embedded UI.

Report the commit, release link, test evidence and outstanding deployment checks. Do not claim a VPS deployment, reboot test or performance benchmark from local/CI results.
