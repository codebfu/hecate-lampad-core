# CI versioning

Master builds auto-increment the semver **patch** segment using git tags `vX.Y.Z` as the source of truth. Agent package versions stay **aligned** across `hecate-lampad-core` and the OS installer repos.

## How it works

1. `ci/resolve-version.sh` reads `MAJOR.MINOR` from `Cargo.toml` (bump those manually when needed).
2. On **master**, every CI pipeline creates and pushes a new `vX.Y.Z` whose patch is `max(tags across core/linux/macos/windows) + 1` (even if the commit already has older semver tags).
3. Core triggers OS installer pipelines **sequentially** and passes `AGENT_VERSION` so linux/macos/windows publish the same `X.Y.Z` into the feature repository.
4. Platform packaging scripts export `HECATE_AGENT_VERSION` (same semver as the installer `VERSION`) before `cargo build`, so the agent binary reports the package version rather than the core crate version alone.
5. That covers re-runs and downstream triggers so rebuilt artifacts never reuse a package version when dependencies changed.
6. Tag pipelines (`CI_COMMIT_TAG`) and branch builds on non-`master` branches use the resolved tag or the static `Cargo.toml` version without creating tags.

Git tags use the resolved version (`v1.0.0`). Downstream OS agent repos publish to Package Registry `hecate-lampad/latest/` and to the hecate-repo feature repository.

## GitLab project settings (required)

Configure these once per GitLab project:

| Setting | Value |
|---------|-------|
| **CI/CD → Token Access → Allow CI job token to push to repository** | Enabled (`write_repository`) |
| **CI/CD → Variables** (optional) | `GIT_DEPTH=0` is already set in `.gitlab-ci.yml` |

Without `write_repository`, the `resolve_version` job cannot push tags and master builds will fail when creating a new version.

## Scripts

| Script | Purpose |
|--------|---------|
| `ci/resolve-version.sh` | Resolve or create `vX.Y.Z`, write `version.env` |
| `ci/require-version-tag-on-commit.sh` | Fail when the current commit has no semver tag (used by platform repos and hecate publish/push gates) |
| `ci/apply-version.sh` | Patch `Cargo.toml` before build |

## Publish / push gate

This repo has no package publish or registry push stage. Platform agent repos (`hecate-lampad-linux`, `hecate-lampad-macos`, `hecate-lampad-windows`) and `hecate` gate their `publish` / `push` jobs with `check_version_tag`, which runs `ci/require-version-tag-on-commit.sh` after `resolve_version`.

## Downstream installer builds

Pushes to **master** run `test` and `build`, then trigger downstream pipelines on the platform agent repos (linux → macos → windows) so installers pick up the latest `hecate-lampad-core` from `master` and share `AGENT_VERSION`.

GitLab must allow `hecate-lampad-core` to trigger those projects and allow job tokens to **read** sibling agent repos when listing tags (**Settings → CI/CD → Job token permissions**).

## Local use

```bash
bash ci/resolve-version.sh
source version.env
echo "$VERSION"
```

Local runs compute the next version but do not push git tags.
