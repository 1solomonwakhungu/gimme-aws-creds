# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public GitHub issues, pull
requests, or discussions. Do not attach real passwords, session tokens, OAuth
codes, MFA codes, device tokens, SAML assertions, or AWS/Alibaba credentials to
any report.

A monitored security mailbox and response commitments are not documented here.
Private-reporting settings have not been verified.

For defects in this fork, open
[this fork's Security tab](https://github.com/1solomonwakhungu/gimme-aws-creds/security).
If **Report a vulnerability** is available, use that private GitHub reporting
route; access follows GitHub's advisory permissions. Otherwise, ask this fork's
maintainer for a private contact in an issue containing no vulnerability details.

For defects affecting upstream, check the
[upstream Security tab](https://github.com/Nike-Inc/gimme-aws-creds/security)
for its private reporting route. The upstream general contact,
[opensource@nike.com](mailto:opensource@nike.com), is listed in the inherited
[CONTRIBUTING.md](CONTRIBUTING.md); it is not identified there as a security
inbox or a contact for this fork. If using that contact, ask only where to send
an upstream security report privately. Do not include vulnerability details
until a private channel is agreed.

No response time or report-handling commitment is established by this document.

### What to include

Once you have a private channel, a useful report includes:

- the affected version (`gimme-aws-creds --version`), or the commit SHA if you
  installed from source;
- the Python version, operating system, and Okta platform (Classic or Identity
  Engine);
- the configuration options involved, with secret values removed;
- the impact, and the conditions an attacker needs;
- reproduction steps that use synthetic or revoked credentials and a test
  identity provider or local mock, never a production account.

### Logs and debug output

Treat `--debug` output and verbose logs as sensitive. They can contain
authentication material. If a log is needed, review it and replace every
password, token, code, cookie, `Authorization` header, assertion, and
credential value before sending it, even over a private channel. If you believe
a real secret has already been exposed, revoke or rotate it with your identity
provider or cloud administrator first.

## Supported versions

A security-support, release, and backport policy has not been established in
the documentation reviewed for this change. The fork owner must define those
commitments before any version is represented as receiving security updates.
The Python installation constraint for this source is declared in
[setup.py](setup.py); it is separate from a security-support commitment.

A source fix may not yet be available in a published package. Check the release
notes and dependency metadata for the version installed; upgrading to the
latest published version does not by itself establish that a particular fix
is included.

The sample code in [`lambda/`](lambda/README.md) is unsupported reference code.
It is not installed as a Python package module and has no sample-specific tests
in this repository. Its runtime and deployment gaps are listed in its README.

## Scope

In scope: the `gimme-aws-creds` Python package and command-line tool in this
repository, including how it handles credentials, configuration files, and
responses from the identity provider and STS.

Out of scope, report to the relevant vendor instead: vulnerabilities in Okta,
Duo, AWS, Alibaba Cloud, or third-party Python dependencies themselves, and
misconfiguration of a specific organization's identity provider or IAM roles.
If a dependency vulnerability is reachable through gimme-aws-creds, a report
here is still welcome.

## Items for the owner to confirm

These operational controls have not been verified. The owner should confirm
and document:

- whether private vulnerability reporting is enabled for this repository;
- a monitored private security contact and its scope;
- supported versions, backport policy, and release responsibility;
- any response targets for acknowledgement and fixes;
- how advisories and reporter credit are handled;
- whether the `lambda/` sample will be removed or brought under support.
