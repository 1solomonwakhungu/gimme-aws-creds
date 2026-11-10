# Release readiness and PyPI publication

This document describes how `.github/workflows/cicd.yml` builds, verifies, and
publishes gimme-aws-creds, and the steps a maintainer must finish before PyPI
publication can be turned on.

**Publication is off by default.** A published GitHub release runs every check,
then stops at the **Release Readiness Gate** job. The gate fails, and nothing is
uploaded, until a maintainer completes every step in
[Prerequisites](#prerequisites-for-enabling-publication).

## Pipeline overview

| Job | Runs on | Token permissions | Purpose |
|---|---|---|---|
| `test` | push, PR, release | `contents: read` | Unit tests on Python 3.10–3.14 from source |
| `code-scan` | push, PR, release | `actions: read`, `contents: read`, `security-events: write` | CodeQL |
| `release-tooling` | push, PR, release | `contents: read` | Tests for the workflow policy and the scripts in `ci/release/` |
| `build` | push, PR, release | `contents: read` | Builds the sdist and wheel **once** with hash-locked tools, checks them, writes `SHA256SUMS`, and uploads them as the `release-dist` artifact |
| `verify-artifacts` | push, PR, release | `contents: read` | On each of Python 3.10–3.14: checks hashes, installs the built wheel into a clean environment, runs `pip check`, audits the resolved dependencies, runs the Content-Encoding bound check, and runs the unit tests against the installed wheel |
| `release-gate` | release only | `actions: read`, `contents: read` | Fails closed unless publication is enabled and the protected environment is verified |
| `publish` | release only, after the gate | `id-token: write` | Re-checks hashes and uploads exactly the verified files with Trusted Publishing |

The workflow-level default is `permissions: {}`, so a new job has no token
permissions until it declares them. No job references repository secrets.
Pull requests from forks run with a read-only token, and the `release-gate` and
`publish` jobs never run for them.

### Build once, test, then upload the same bytes

1. `build` installs `ci/release/requirements/build.txt` with `--require-hashes`
   and runs `python -m build --no-isolation`. Only the reviewed versions of
   `build`, `setuptools`, and `setuptools-rust` are used. `SOURCE_DATE_EPOCH` is
   set from the commit time.
2. `ci/release/verify_dist.py` inspects both archives without installing them.
   It checks for exactly one pure-Python wheel and one sdist, safe member
   paths, no links or devices in the sdist, and no top-level packages other than
   `gimme_aws_creds`. It also checks that `LICENSE` and `NOTICE` ship in both
   archives, that wheel `RECORD` digests match, and that the wheel and sdist
   agree on name and version. `Requires-Python` must admit 3.10–3.14 and reject
   3.9. Runtime `Requires-Dist` must equal `requirements.txt`, and urllib3 must be
   unconditional with a floor of **2.6.3 or newer**. For a release, the tag must
   equal `v<version>` and the version must not be a dev or local version. Only
   when every check passes does it write `dist/SHA256SUMS`.
3. The SHA-256 of `SHA256SUMS` is passed from `build` as a job output. Each
   downstream job compares the downloaded `SHA256SUMS` with that digest, then
   checks each artifact against `SHA256SUMS`.
4. `verify-artifacts` tests the downloaded wheel on Python 3.10–3.14:
   * installs `gimme_aws_creds-*.whl[alicloud]` into a new virtual environment
     and runs `pip check`;
   * runs `pip-audit --strict` (hash-locked from
     `ci/release/requirements/audit.txt`) against the exact resolved set;
   * runs `ci/release/check_encoding_chain.py` from that environment. A
     loopback-only server must have a 5-layer gzip chain decoded, and a 6-layer
     chain rejected within time and allocation budgets. This is the
     GHSA-gm62-xv2j-4w53 / CVE-2025-66418 bound, and it fails on urllib3 1.26.x;
   * runs the unit tests from a copy of `tests/` outside the source tree, so they
     import the installed wheel. It sets a null keyring backend and
     `AWS_EC2_METADATA_DISABLED=true`.
5. `publish` downloads the same artifact, checks the hashes again, copies only
   the files listed in `SHA256SUMS`, and uploads them with
   `pypa/gh-action-pypi-publish`. That action uses Trusted Publishing and
   generates PEP 740 attestations. `publish` does not check out or run
   repository code.

The release trigger is `release: published`, so saving a draft release does not
start a build.

### Action pins

Every action is pinned to a full commit SHA. The trailing comment names the tag
it was resolved from. The SHAs were resolved through the GitHub API on
2026-11-09, with annotated tags dereferenced to commits. GitHub reported each
commit as verified. Where a newer release in the same major line was less than
two weeks old, the pin uses the previous release.

| Action | Tag | Commit |
|---|---|---|
| `actions/checkout` | v6.1.0 | `d23441a48e516b6c34aea4fa41551a30e30af803` |
| `actions/setup-python` | v6.3.0 | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| `github/codeql-action` (init, autobuild, analyze) | v4.39.1 | `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| `pypa/gh-action-pypi-publish` | v1.14.3 | `7245906fb61fa33a13554f9d5fb856fe61758086` |

`ci/release/tests/test_workflow_policy.py` holds the same table and fails if the
workflow uses an action, SHA, or tag comment that is not in it. To update a pin,
resolve the new tag to its commit and confirm the commit belongs to the
upstream repository. Then update the workflow, this table, and the test in one
reviewed change.

### Hash-locked tool inputs

`ci/release/requirements/*.in` list the tools. `*.txt` are the hash-locked,
cross-platform lock files generated from them:

| File | Used by |
|---|---|
| `build.txt` | `build` job |
| `check.txt` | `release-tooling` job and artifact verification |
| `audit.txt` | `pip-audit` in `verify-artifacts` |
| `unit.txt` | pytest and responses, added to the wheel environment after auditing. It omits packages shared with the runtime set, so the tested environment keeps the versions the wheel resolved |

Regenerate them with uv. Use a cutoff at least 14 days old so new uploads are
not adopted right away:

```sh
EXCLUDE_NEWER=2026-10-26T00:00:00Z ci/release/requirements/compile.sh
```

Review the resulting diff like any other dependency change.

## Prerequisites for enabling publication

Complete these in order. Each must be done by someone with the required access.
The workflow cannot perform or fully confirm any of them.

1. **Create the `pypi` deployment environment**
   (*Settings → Environments → New environment*, name `pypi`) and configure it:
   * **Required reviewers:** at least one maintainer or team other than the
     person who usually creates releases. Enable **Prevent self-review**.
   * **Deployment branches and tags:** choose *Selected branches and tags* and
     add a single **tag** rule, `v*`. Do not add branch rules or use *Protected
     branches only*.
   * Disable **Allow administrators to bypass configured protection rules**.
     The GitHub API does not report this setting, so the gate cannot check it.
   * Do not store any secrets in this environment.
2. **Register the Trusted Publisher on PyPI** for the `gimme-aws-creds`
   project (*Manage → Publishing → Add a new publisher → GitHub*):
   * Owner: the GitHub organization or user that owns the repository
   * Repository: `gimme-aws-creds`
   * Workflow name: `cicd.yml`
   * Environment name: `pypi`

   Require 2FA for every PyPI project owner and maintainer.
3. **Remove the legacy credentials.** Delete the `PYPI_USERNAME` and
   `PYPI_PASSWORD` repository or organization secrets. Revoke any PyPI API
   token or password they held. The workflow no longer reads them.
4. **Protect release tags and the default branch.** Add a tag ruleset for `v*`
   that limits who can create, update, or delete release tags. Add a branch
   ruleset that requires review for the default branch. The gate also checks
   that the release commit is reachable from the default branch.
5. **Verify** with a release candidate tag on a fork or on TestPyPI (see
   below) that the gate passes, that the `publish` job waits for reviewer
   approval, and that PyPI accepts the OIDC exchange.
6. **Enable publication** by creating the repository variable
   `PYPI_PUBLISH_ENABLED` with the exact value `true`
   (*Settings → Secrets and variables → Actions → Variables*). To stop
   publication, delete the variable or change its value.

### What the gate checks

`ci/release/check_publish_readiness.py` runs in `release-gate`. Any error, an
unexpected API response, or a missing value makes it fail. It requires:

* `PYPI_PUBLISH_ENABLED` is exactly `true`;
* the event is `release` and the tag is non-empty;
* `GET /repos/{repo}/environments/pypi` succeeds, includes a required-reviewers
  rule with at least one reviewer, and has `prevent_self_review: true`;
* the environment uses custom deployment policies (not *protected branches*),
  every policy is a **tag** policy in the allowed set (`v*`), and the release
  tag matches one of them.

An earlier step requires the release commit to be an ancestor of the default
branch.

The gate cannot see PyPI's publisher registration or the admin-bypass setting.
PyPI enforces the publisher tuple of repository, workflow, and environment when
the `publish` job exchanges its OIDC token. A misconfigured publisher fails at
upload, before anything is published.

### Dry run against TestPyPI

To rehearse without touching the production project, do this on a personal
fork. Register a TestPyPI Trusted Publisher for the fork and a `testpypi`
environment configured as above. Then temporarily add
`repository-url: https://test.pypi.org/legacy/` and that environment name in a
fork-only branch. Do not merge that change. The policy test
rejects `repository-url` in the main workflow on purpose.

## Local reproduction

The checks run offline except for package downloads and `pip-audit`'s
vulnerability lookups. Use a temporary HOME, a null keyring backend, and
disabled cloud metadata:

```sh
export HOME="$(mktemp -d)" PIP_CONFIG_FILE=/dev/null \
  PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring AWS_EC2_METADATA_DISABLED=true
python3 -m venv "$HOME/build" && "$HOME/build/bin/pip" install --require-hashes --no-deps -r ci/release/requirements/build.txt
"$HOME/build/bin/python" -m build --no-isolation --outdir "$HOME/dist" .
"$HOME/build/bin/python" ci/release/verify_dist.py "$HOME/dist" --requirements requirements.txt
python3 -m venv "$HOME/check" && "$HOME/check/bin/pip" install --require-hashes --no-deps -r ci/release/requirements/check.txt
"$HOME/check/bin/python" -m pytest ci/release/tests
```
