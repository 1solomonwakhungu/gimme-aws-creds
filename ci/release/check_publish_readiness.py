#!/usr/bin/env python3
"""Fail-closed gate that must pass before the release workflow may publish to PyPI.

Publication is disabled unless a maintainer has completed every prerequisite in
docs/release-readiness.md and then set the repository variable
PYPI_PUBLISH_ENABLED to "true". Even then, this gate independently confirms,
through the GitHub REST API, that the deployment environment used by the
publish job exists and is protected:

* at least one required reviewer, with self-review prevented;
* deployments restricted to custom policies that only allow release tags
  (no branch policies, no "protected branches" shortcut);
* the release tag matches one of those tag policies.

Configuration (environment variables):
    PYPI_PUBLISH_ENABLED   must be exactly "true"
    GITHUB_EVENT_NAME      must be "release"
    RELEASE_TAG            tag of the release being published
    PUBLISH_ENVIRONMENT    deployment environment name (default "pypi")
    ALLOWED_TAG_POLICIES   comma-separated tag patterns accepted (default "v*")
    GITHUB_REPOSITORY, GITHUB_API_URL, GITHUB_TOKEN  supplied by GitHub Actions

PyPI's Trusted Publisher registration cannot be read from GitHub; PyPI enforces
it when the publish job exchanges its OIDC token. Any API error, missing value,
or unexpected response fails the gate.
"""
import fnmatch
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 15
DEFAULT_ENVIRONMENT = "pypi"
DEFAULT_TAG_POLICIES = "v*"


class GateError(Exception):
    """Raised when readiness cannot be established."""


def fetch_json(api_url, path, token):
    """GET a GitHub API path and return decoded JSON, failing closed on any problem."""
    parsed = urllib.parse.urlsplit(api_url)
    loopback = parsed.hostname in ("127.0.0.1", "::1", "localhost")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise GateError(f"refusing non-HTTPS API URL {api_url!r}")
    request = urllib.request.Request(
        api_url.rstrip("/") + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "gimme-aws-creds-release-gate",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise GateError(f"GitHub API {path} returned HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise GateError(f"GitHub API {path} request failed: {exc}") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise GateError(f"GitHub API {path} response exceeded {MAX_RESPONSE_BYTES} bytes")
    try:
        return json.loads(body)
    except ValueError:
        raise GateError(f"GitHub API {path} returned invalid JSON") from None


def evaluate_environment(environment, policies, release_tag, allowed_patterns):
    """Return a list of failures for the environment protection settings."""
    failures = []
    if not isinstance(environment, dict):
        return ["environment response is not an object"]

    rules = environment.get("protection_rules") or []
    reviewer_rules = [r for r in rules if isinstance(r, dict) and r.get("type") == "required_reviewers"]
    if not reviewer_rules:
        failures.append("environment has no required-reviewers protection rule")
    else:
        if not any(r.get("reviewers") for r in reviewer_rules):
            failures.append("required-reviewers rule lists no reviewers")
        if not all(r.get("prevent_self_review") is True for r in reviewer_rules):
            failures.append("required-reviewers rule must prevent self-review")

    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, dict):
        failures.append("environment allows deployments from any branch or tag")
    else:
        if branch_policy.get("protected_branches") is not False:
            failures.append("environment must not use the protected-branches deployment policy")
        if branch_policy.get("custom_branch_policies") is not True:
            failures.append("environment must use custom tag deployment policies")

    if not isinstance(policies, dict) or not isinstance(policies.get("branch_policies"), list):
        failures.append("deployment policy list is missing or malformed")
        return failures
    entries = policies["branch_policies"]
    if policies.get("total_count", len(entries)) != len(entries):
        failures.append("deployment policy list is incomplete")
    if not entries:
        failures.append("environment has no deployment tag policies")
    for entry in entries:
        kind = entry.get("type") if isinstance(entry, dict) else None
        name = entry.get("name") if isinstance(entry, dict) else None
        if kind != "tag":
            failures.append(f"deployment policy {name!r} is a {kind!r} policy; only tag policies are allowed")
        elif name not in allowed_patterns:
            failures.append(f"deployment tag policy {name!r} is not in the allowed set {sorted(allowed_patterns)}")
    tag_patterns = [e.get("name") for e in entries if isinstance(e, dict) and e.get("type") == "tag"]
    if not release_tag or not any(fnmatch.fnmatchcase(release_tag, p) for p in tag_patterns if p):
        failures.append(f"release tag {release_tag!r} does not match any deployment tag policy")
    return failures


def run(env):
    """Evaluate the gate from an environment mapping. Returns (report, failures)."""
    failures = []
    report = {}
    enabled = env.get("PYPI_PUBLISH_ENABLED", "")
    event = env.get("GITHUB_EVENT_NAME", "")
    release_tag = env.get("RELEASE_TAG", "")
    environment_name = env.get("PUBLISH_ENVIRONMENT") or DEFAULT_ENVIRONMENT
    allowed = {p.strip() for p in (env.get("ALLOWED_TAG_POLICIES") or DEFAULT_TAG_POLICIES).split(",") if p.strip()}
    repository = env.get("GITHUB_REPOSITORY", "")
    api_url = env.get("GITHUB_API_URL", "")
    token = env.get("GITHUB_TOKEN", "")
    report.update(environment=environment_name, release_tag=release_tag, repository=repository)

    if enabled != "true":
        failures.append(
            "PyPI publication is disabled: repository variable PYPI_PUBLISH_ENABLED is not 'true'. "
            "Complete docs/release-readiness.md before enabling it."
        )
    if event != "release":
        failures.append(f"publication is only allowed from release events, not {event!r}")
    if not release_tag:
        failures.append("RELEASE_TAG is empty")
    if not repository or repository.count("/") != 1:
        failures.append("GITHUB_REPOSITORY is missing or malformed")
    if not api_url or not token:
        failures.append("GITHUB_API_URL or GITHUB_TOKEN is missing")
    if failures:
        return report, failures

    quoted_env = urllib.parse.quote(environment_name, safe="")
    base = f"/repos/{repository}/environments/{quoted_env}"
    try:
        environment = fetch_json(api_url, base, token)
        policies = fetch_json(api_url, f"{base}/deployment-branch-policies?per_page=100", token)
    except GateError as exc:
        failures.append(f"could not verify environment {environment_name!r}: {exc}")
        return report, failures
    failures.extend(evaluate_environment(environment, policies, release_tag, allowed))
    return report, failures


def main():
    report, failures = run(os.environ)
    report["ok"] = not failures
    print(json.dumps(report, indent=2, sort_keys=True))
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
