# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public GitHub issues, pull
requests, or discussions. Do not attach real passwords, session tokens, OAuth
codes, MFA codes, device tokens, SAML assertions, or AWS/Alibaba credentials to
any report.

This project does not yet have a dedicated, monitored security mailbox, and
private vulnerability reporting may not be enabled for this repository. Use the
first route below that is available to you:

1. **GitHub private vulnerability reporting.** Open the repository's
   [Security tab](https://github.com/Nike-Inc/gimme-aws-creds/security). If a
   **Report a vulnerability** button is shown, use it. That form is visible only
   to you and the repository maintainers. If the button is not shown, private
   reporting is not enabled; go to step 2.
2. **Ask for a private channel.** Email
   [opensource@nike.com](mailto:opensource@nike.com), the general contact
   listed in [CONTRIBUTING.md](CONTRIBUTING.md). It is not a dedicated security
   inbox. In the first message, say only that you have a security report for
   gimme-aws-creds and ask where to send it privately. Do not include
   vulnerability details until a private channel is agreed.
3. **No response.** If neither route works, you may open a public issue that
   says only that you need a private security contact. Do not describe the
   vulnerability, the affected code, or how to reproduce it in that issue.

There is no committed response time. Reports are handled on a best-effort basis
by the project maintainers.

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

| Version | Security fixes |
|---|---|
| Latest release published on [PyPI](https://pypi.org/project/gimme-aws-creds/) | Fixes are made on `master` and shipped in a later release |
| `master` (unreleased) | Fixes land here first; it may contain changes not yet reviewed for release |
| Older releases | Upgrade to the latest release |

The project maintains no long-term-support or backport branches. Python versions
outside `python_requires` in [setup.py](setup.py) are not supported.

The sample code in [`lambda/`](lambda/README.md) is unsupported reference code.
It is not part of the published package, is not tested, and is not covered by
this policy's fix process. See that directory's README for its known gaps.

## Scope

In scope: the `gimme-aws-creds` Python package and command-line tool in this
repository, including how it handles credentials, configuration files, and
responses from the identity provider and STS.

Out of scope, report to the relevant vendor instead: vulnerabilities in Okta,
Duo, AWS, Alibaba Cloud, or third-party Python dependencies themselves, and
misconfiguration of a specific organization's identity provider or IAM roles.
If a dependency vulnerability is reachable through gimme-aws-creds, a report
here is still welcome.

## Maintainer setup still pending

This policy describes interim routes. The following owner actions have not been
performed, and the reporting section above should be updated as each one is
done:

- enable GitHub private vulnerability reporting for this repository;
- designate and monitor a security contact or alias, and list it here;
- decide whether to publish response targets for acknowledgement and fixes;
- decide how advisories are published (for example, GitHub Security
  Advisories and CVE requests) and how reporters are credited;
- decide whether the `lambda/` sample is removed or brought under support.
