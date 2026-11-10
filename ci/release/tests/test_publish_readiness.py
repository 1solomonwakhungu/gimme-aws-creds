"""Tests for the fail-closed publication gate, using a loopback fake GitHub API."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import check_publish_readiness as gate

REPO = "example-owner/gimme-aws-creds"


def protected_environment():
    return {
        "name": "pypi",
        "protection_rules": [
            {"type": "required_reviewers", "prevent_self_review": True,
             "reviewers": [{"type": "User", "reviewer": {"login": "maintainer"}}]},
        ],
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }


def tag_policies(*names, kind="tag"):
    return {"total_count": len(names), "branch_policies": [{"name": n, "type": kind} for n in names]}


def evaluate(environment=None, policies=None, tag="v2.9.0"):
    return gate.evaluate_environment(
        protected_environment() if environment is None else environment,
        tag_policies("v*") if policies is None else policies,
        tag,
        {"v*"},
    )


def test_protected_environment_passes():
    assert evaluate() == []


def test_missing_reviewers_fails():
    environment = protected_environment()
    environment["protection_rules"] = [{"type": "wait_timer", "wait_timer": 5}]
    assert any("required-reviewers" in f for f in evaluate(environment))


def test_empty_reviewer_list_fails():
    environment = protected_environment()
    environment["protection_rules"][0]["reviewers"] = []
    assert any("lists no reviewers" in f for f in evaluate(environment))


def test_self_review_must_be_prevented():
    environment = protected_environment()
    environment["protection_rules"][0]["prevent_self_review"] = False
    assert any("self-review" in f for f in evaluate(environment))


@pytest.mark.parametrize("branch_policy", [
    None,
    {"protected_branches": True, "custom_branch_policies": False},
    {"protected_branches": False, "custom_branch_policies": False},
])
def test_unrestricted_deployment_sources_fail(branch_policy):
    environment = protected_environment()
    environment["deployment_branch_policy"] = branch_policy
    assert evaluate(environment)


def test_branch_policies_are_rejected():
    assert any("only tag policies" in f for f in evaluate(policies=tag_policies("main", kind="branch")))


def test_unexpected_tag_patterns_are_rejected():
    assert any("not in the allowed set" in f for f in evaluate(policies=tag_policies("v*", "*")))


def test_release_tag_must_match_policy():
    assert any("does not match" in f for f in evaluate(tag="release-1"))


def test_incomplete_or_malformed_policy_lists_fail():
    assert any("incomplete" in f for f in evaluate(policies={"total_count": 3, "branch_policies": [{"name": "v*", "type": "tag"}]}))
    assert any("malformed" in f for f in evaluate(policies={"unexpected": True}))
    assert any("no deployment tag policies" in f for f in evaluate(policies=tag_policies()))


class FakeGitHub(BaseHTTPRequestHandler):
    responses = {}
    seen_auth = []

    def do_GET(self):  # noqa: N802
        FakeGitHub.seen_auth.append(self.headers.get("Authorization"))
        status, body = FakeGitHub.responses.get(self.path, (404, b'{"message":"Not Found"}'))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        return


@pytest.fixture
def fake_api():
    FakeGitHub.responses = {}
    FakeGitHub.seen_auth = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def serve(environment, policies):
    base = f"/repos/{REPO}/environments/pypi"
    FakeGitHub.responses = {
        base: (200, json.dumps(environment).encode()),
        f"{base}/deployment-branch-policies?per_page=100": (200, json.dumps(policies).encode()),
    }


def gate_env(api_url, **overrides):
    env = {
        "PYPI_PUBLISH_ENABLED": "true",
        "GITHUB_EVENT_NAME": "release",
        "RELEASE_TAG": "v2.9.0",
        "PUBLISH_ENVIRONMENT": "pypi",
        "ALLOWED_TAG_POLICIES": "v*",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_API_URL": api_url,
        "GITHUB_TOKEN": "synthetic-token-not-real",
    }
    env.update(overrides)
    return env


def test_gate_passes_with_verified_configuration(fake_api):
    serve(protected_environment(), tag_policies("v*"))
    report, failures = gate.run(gate_env(fake_api))
    assert failures == []
    assert FakeGitHub.seen_auth == ["Bearer synthetic-token-not-real"] * 2
    assert "synthetic-token-not-real" not in json.dumps(report)


@pytest.mark.parametrize("value", ["", "false", "TRUE", "yes", "1"])
def test_gate_is_disabled_unless_explicitly_enabled(fake_api, value):
    serve(protected_environment(), tag_policies("v*"))
    _, failures = gate.run(gate_env(fake_api, PYPI_PUBLISH_ENABLED=value))
    assert any("publication is disabled" in f for f in failures)
    assert FakeGitHub.seen_auth == []


def test_gate_rejects_non_release_events(fake_api):
    _, failures = gate.run(gate_env(fake_api, GITHUB_EVENT_NAME="push"))
    assert any("release events" in f for f in failures)


def test_gate_requires_token_and_tag(fake_api):
    _, failures = gate.run(gate_env(fake_api, GITHUB_TOKEN="", RELEASE_TAG=""))
    assert any("GITHUB_TOKEN" in f for f in failures)
    assert any("RELEASE_TAG" in f for f in failures)


def test_gate_fails_closed_when_environment_missing(fake_api):
    _, failures = gate.run(gate_env(fake_api))
    assert any("HTTP 404" in f for f in failures)


def test_gate_fails_closed_on_unprotected_environment(fake_api):
    environment = protected_environment()
    environment["protection_rules"] = []
    serve(environment, tag_policies("v*"))
    _, failures = gate.run(gate_env(fake_api))
    assert any("required-reviewers" in f for f in failures)


def test_gate_fails_closed_on_oversized_or_invalid_responses(fake_api, monkeypatch):
    base = f"/repos/{REPO}/environments/pypi"
    FakeGitHub.responses = {base: (200, b"not json")}
    _, failures = gate.run(gate_env(fake_api))
    assert any("invalid JSON" in f for f in failures)
    monkeypatch.setattr(gate, "MAX_RESPONSE_BYTES", 10)
    serve(protected_environment(), tag_policies("v*"))
    _, failures = gate.run(gate_env(fake_api))
    assert any("exceeded" in f for f in failures)


def test_gate_refuses_plain_http_to_remote_hosts():
    with pytest.raises(gate.GateError):
        gate.fetch_json("http://api.example.invalid", "/x", "token")


def test_gate_fails_closed_when_api_unreachable():
    _, failures = gate.run(gate_env("http://127.0.0.1:9"))
    assert any("request failed" in f for f in failures)
