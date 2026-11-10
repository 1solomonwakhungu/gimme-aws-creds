# Lambda Service for gimme-aws-creds

> **Status: unsupported reference code.** This sample is kept for history and
> as a starting point only. It is not maintained, tested, packaged, or covered
> by the project's [security policy](../SECURITY.md) fix process. It targets a
> retired Python runtime and an Okta SDK API that the CLI no longer uses, and
> the repository contains no authorizer or deployment for it. Do not deploy it
> as-is. For most setups, `gimme_creds_server = appurl` is an alternative that
> needs neither this service nor an Okta API key.

### Summary
This service interacts with the Okta User and App APIs on behalf of the gimme-aws-creds CLI client.  It removes the need for an Okta API key within the gimme-aws-creds client and filters the API results to just the data necessary for requesting AWS credentials.

### Dependencies
These are the original requirements. Both are obsolete; see [Known gaps](#known-gaps).
- Python 2.7 (https://www.python.org)
- okta-sdk-python v0.4+ (https://github.com/okta/okta-sdk-python)

### Environmental Variables
To run the lambda, you'll need to pass in two environment variables:
- `OKTA_API_KEY` A read-only Okta API key that will be used for the User and Apps APIs
- `OKTA_ORG_URL` The Okta domain URL to use for API calls (e.g. https://example.okta.com)

### OAuth Token Authorizer
Developing the OAuth Token authorizer and deployment process for the Lambda is left up to you.  For an example of how to write an Authorizer and deploy an API using the [Serverless](https://serverless.com/) framework, take a look at this [Github repo](https://github.com/pmcdowell-okta/oauth-jwt-serverless-aws-apigateway).

## Contract with the CLI

When `gimme_creds_server` is set to a URL, the CLI:

1. obtains an Okta OAuth access token from the configured `okta_auth_server`
   using `client_id` (Okta Classic requests only the `openid` scope);
2. sends `GET <gimme_creds_server>` with `Authorization: Bearer <access token>`;
3. expects a JSON array of objects shaped like
   `{"id": ..., "name": ..., "links": {"appLink": ..., "appLogo": ...}}`, and
   fails if the array is empty.

The handler itself never sees or checks the bearer token. It reads
`event['requestContext']['authorizer']['principalId']` and uses that value as
the Okta user ID or login. Every security property of the service therefore
depends on an API Gateway authorizer that is not part of this repository.

## Known gaps

These gaps are why the sample is unsupported. Anyone adopting it owns closing
them. None of them describes a known deployment; the repository contains none.

### Runtime and dependencies

- **Runtime.** The code and docs target Python 2.7, which reached end of life
  on 2020-01-01 and is no longer offered as an AWS Lambda runtime.
- **Okta SDK.** `lambda_handler.py` imports `okta.framework.ApiClient` and
  `okta.framework.OktaError`, which exist only in the legacy 0.x
  `okta` SDK. The CLI now requires `okta>=3.4.2,<4.0.0` (see
  [requirements.txt](../requirements.txt)), whose client is asynchronous and
  has a different API. The handler will not import against the SDK the CLI
  uses.
- **No pinned dependencies.** There is no requirements or lock file for the
  Lambda, so a build cannot be reproduced or audited.

### Authorizer and identity mapping

- **No authorizer.** The sample delegates authentication entirely to an
  external authorizer. A replacement must verify the token signature against
  the authorization server's keys, and check issuer, audience, expiry, and
  required scopes, before setting `principalId`.
- **Principal mapping.** The authorizer must set `principalId` from the
  verified token's subject or login claim, never from request headers, query
  parameters, or the body. The handler places the value into
  `/api/v1/users/{principalId}` without URL encoding, so the authorizer should
  also reject values that are not a canonical Okta user ID or login.
- **No tests.** There are no tests for principal, issuer, audience, expiry, or
  scope handling.

### Okta API key

- **Key scope.** Okta API tokens act with the permissions of the administrator
  who created them. "Read-only" holds only if that administrator has a
  read-only role. The key can read every user and app assignment in the org.
  Consider an Okta OAuth 2.0 service app limited to the user and app read
  scopes the handler needs.
- **Key storage.** The key is read from a plain Lambda environment variable.
  There is no guidance on storing it in a secrets service, encrypting it,
  limiting who can read the function configuration, or rotating it.

### Deployment and infrastructure

- **No infrastructure as code.** There is no template for API Gateway, the
  authorizer, the Lambda execution role, logging, throttling, or alarms.
- **Unbounded pagination.** The handler follows Okta `next` links with no page
  or response-size limit. A `params` dictionary with a `limit` is built but
  never sent.
- **Response details.** Error responses return Okta's error summary as plain
  text under a JSON content type. Responses send
  `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials:
  true`, a combination browsers reject for credentialed requests; the CLI does
  not need CORS headers.
- **Local entry point.** `main()` builds a test event but no longer calls the
  handler, so running the file directly does nothing.

### Ownership

- **No owner.** No maintainer is assigned to this directory, and nothing tests
  or releases it. The last change to `lambda_handler.py` was in 2022 and
  removed a debug print; the design dates from 2018.

## Paths forward

Either remove this directory, or bring it under support with: a currently
supported Python runtime; the current Okta SDK and a pinned, audited dependency
set; a least-privilege, rotated Okta credential held in a secrets service; a
deployable authorizer and infrastructure template; tests for token validation
and principal mapping; response-size and pagination limits; and a named owner.
Until one of those happens, treat this directory as reference material only.
