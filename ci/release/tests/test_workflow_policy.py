"""Static policy checks for .github/workflows/cicd.yml."""
import re

import pytest
import yaml

from conftest import REPO_ROOT

WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "cicd.yml"

# Provenance: each SHA was resolved from the named tag through the GitHub API
# (annotated tags dereferenced) and reported as a verified commit; see
# docs/release-readiness.md. Changing a pin requires updating this table.
PINNED_ACTIONS = {
    "actions/checkout": ("d23441a48e516b6c34aea4fa41551a30e30af803", "v6.1.0"),
    "actions/setup-python": ("ece7cb06caefa5fff74198d8649806c4678c61a1", "v6.3.0"),
    "github/codeql-action/init": ("9b3254085494b55a0f7c4c2b3d2d52cc712ce370", "v4.39.1"),
    "github/codeql-action/autobuild": ("9b3254085494b55a0f7c4c2b3d2d52cc712ce370", "v4.39.1"),
    "github/codeql-action/analyze": ("9b3254085494b55a0f7c4c2b3d2d52cc712ce370", "v4.39.1"),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"),
    "actions/download-artifact": ("9000827ccba6bdab643e8b6fd33ac0654aef8333", "v8.0.2"),
    "pypa/gh-action-pypi-publish": ("7245906fb61fa33a13554f9d5fb856fe61758086", "v1.14.3"),
}
SUPPORTED_PYTHONS = ["3.10", "3.11", "3.12", "3.13", "3.14"]
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")


@pytest.fixture(scope="module")
def raw():
    return WORKFLOW_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow(raw):
    return yaml.safe_load(raw)


@pytest.fixture(scope="module")
def jobs(workflow):
    return workflow["jobs"]


def triggers(workflow):
    # PyYAML (YAML 1.1) loads the bare key `on` as boolean True.
    return workflow.get("on", workflow.get(True))


def all_steps(jobs):
    for job_id, job in jobs.items():
        for step in job.get("steps", []):
            yield job_id, step


def test_triggers_exclude_privileged_events(workflow):
    on = triggers(workflow)
    assert set(on) == {"push", "pull_request", "release"}
    assert on["release"] == {"types": ["published"]}
    for forbidden in ("pull_request_target", "workflow_run", "issue_comment"):
        assert forbidden not in on


def test_default_token_permissions_are_empty(workflow):
    assert workflow["permissions"] == {}


def test_every_job_declares_minimal_permissions(jobs):
    expected = {
        "test": {"contents": "read"},
        "code-scan": {"actions": "read", "contents": "read", "security-events": "write"},
        "release-tooling": {"contents": "read"},
        "build": {"contents": "read"},
        "verify-artifacts": {"contents": "read"},
        "release-gate": {"actions": "read", "contents": "read"},
        "publish": {"id-token": "write"},
    }
    assert set(jobs) == set(expected)
    for job_id, permissions in expected.items():
        assert jobs[job_id].get("permissions") == permissions, job_id


def test_only_publish_can_mint_oidc_tokens_or_use_an_environment(jobs):
    for job_id, job in jobs.items():
        has_oidc = (job.get("permissions") or {}).get("id-token") == "write"
        assert has_oidc == (job_id == "publish"), job_id
        assert ("environment" in job) == (job_id == "publish"), job_id


def test_actions_are_pinned_to_reviewed_full_shas(raw):
    seen = set()
    for line in raw.splitlines():
        match = USES_LINE.match(line)
        if not match:
            continue
        ref, comment = match.groups()
        action, _, sha = ref.partition("@")
        assert action in PINNED_ACTIONS, f"unreviewed action {action}"
        expected_sha, expected_tag = PINNED_ACTIONS[action]
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"{action} not pinned to a full SHA"
        assert sha == expected_sha, f"{action} pin differs from reviewed provenance"
        assert comment.strip() == f"# {expected_tag}", f"{action} pin comment must name {expected_tag}"
        seen.add(action)
    assert seen == set(PINNED_ACTIONS)


def test_no_stored_secrets_are_referenced(raw):
    assert "secrets." not in raw
    for legacy in ("PYPI_USERNAME", "PYPI_PASSWORD", "TWINE_USERNAME", "TWINE_PASSWORD", "twine upload"):
        assert legacy not in raw


def test_run_steps_do_not_interpolate_expressions(jobs):
    for job_id, step in all_steps(jobs):
        if "run" in step:
            assert "${{" not in step["run"], f"{job_id}: pass expressions through env, not inline"


def test_checkouts_do_not_persist_credentials(jobs):
    for job_id, step in all_steps(jobs):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, job_id


def test_test_matrices_cover_supported_pythons(jobs):
    assert jobs["test"]["strategy"]["matrix"]["python-version"] == SUPPORTED_PYTHONS
    assert jobs["verify-artifacts"]["strategy"]["matrix"]["python-version"] == SUPPORTED_PYTHONS


def test_build_uses_locked_tools_and_records_hashes(jobs):
    build = jobs["build"]
    runs = "\n".join(s.get("run", "") for s in build["steps"])
    assert "--require-hashes" in runs and "ci/release/requirements/build.txt" in runs
    assert "python -m build --no-isolation" in runs
    assert "verify_dist.py" in runs and "--write-sums dist/SHA256SUMS" in runs and "--expected-tag" in runs
    upload = [s for s in build["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(upload) == 1 and upload[0]["with"]["if-no-files-found"] == "error"
    assert build["outputs"]["sums-sha256"]


def test_verification_tests_the_built_wheel(jobs):
    verify = jobs["verify-artifacts"]
    assert verify["needs"] == "build"
    assert verify["env"]["AWS_EC2_METADATA_DISABLED"] == "true"
    assert verify["env"]["PYTHON_KEYRING_BACKEND"] == "keyring.backends.null.Keyring"
    runs = "\n".join(s.get("run", "") for s in verify["steps"])
    for required in (
        'echo "${SUMS_SHA256}  dist/SHA256SUMS" | sha256sum --check --strict',
        "--check-sums dist/SHA256SUMS",
        'pip install "${WHEEL}[alicloud]"',
        "pip check",
        "pip-audit",
        "check_encoding_chain.py",
        "-m pytest",
    ):
        assert required in runs, required


def test_release_gate_fails_closed_before_publication(jobs):
    gate = jobs["release-gate"]
    assert gate["if"] == "github.event_name == 'release'"
    assert set(gate["needs"]) == {"test", "code-scan", "release-tooling", "build", "verify-artifacts"}
    readiness = [s for s in gate["steps"] if "check_publish_readiness.py" in s.get("run", "")]
    assert len(readiness) == 1
    env = readiness[0]["env"]
    assert env["PYPI_PUBLISH_ENABLED"] == "${{ vars.PYPI_PUBLISH_ENABLED }}"
    assert env["PUBLISH_ENVIRONMENT"] == jobs["publish"]["environment"]["name"]
    assert any("merge-base --is-ancestor" in s.get("run", "") for s in gate["steps"])


def test_publish_uploads_only_verified_artifacts_via_oidc(jobs):
    publish = jobs["publish"]
    assert publish["if"] == "github.event_name == 'release'"
    assert set(publish["needs"]) == {"build", "release-gate"}
    assert publish["environment"]["name"] == "pypi"
    steps = publish["steps"]
    assert not any(s.get("uses", "").startswith("actions/checkout@") for s in steps), \
        "the OIDC-capable job must not check out or run repository code"
    hash_step = next(s for s in steps if "sha256sum --check" in s.get("run", ""))
    assert 'echo "${SUMS_SHA256}  verified/SHA256SUMS"' in hash_step["run"]
    pypi = [s for s in steps if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")]
    assert len(pypi) == 1
    assert steps[-1] is pypi[0]
    inputs = pypi[0]["with"]
    assert inputs["packages-dir"] == "dist/"
    assert inputs["attestations"] is True
    assert not {"user", "password", "repository-url"} & set(inputs)
