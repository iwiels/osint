# Security Policy

## Supported Versions

Only the latest published release receives security fixes.

| Version | Support |
|---|---|
| Latest release (vX.Y.Z) | Supported |
| Earlier releases | Not supported |

## Reporting a Vulnerability

**Do not open a public issue.** Use GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
feature: open the repository's **Security** tab and select **Report a
vulnerability**.

If private reporting is unavailable, contact the repository maintainers
privately through GitHub. Do not disclose vulnerability details in a public
issue.

When possible, include:

- The impact and attack vector.
- Minimal reproduction steps, including the affected version, platform, and
  configuration.
- A proof of concept, if one is available.
- A suggested mitigation, if you have one.

### Response Expectations

This is a solo-maintained project with no funding and no service-level
agreement. The target is to acknowledge a report within seven days and provide
an initial assessment within 30 days. If a report is valid, a GitHub Security
Advisory will be published, and the reporter will be credited unless they
prefer otherwise.

## Scope

**In scope:**

- The Python engine (engine/) and HTTP API, including Bearer authentication,
  the permission gate, the SSRF guard (netguard.py), filesystem paths, and
  secret handling.
- The Electron app (desktop/), including contextBridge, IPC, and renderer
  isolation.
- The TypeScript SDK (packages/sdk/).
- The chain-of-custody ledger and its HMAC verification.
- Execution of untrusted code through collectors or the agent.

**Out of scope:**

- Vulnerabilities in third-party dependencies. Report those upstream; Dependabot
  monitors this repository's dependencies.
- The engine's ability to query public sources; that is intended behavior. See
  [LEGAL.md](LEGAL.md).
- Social engineering against the maintainer.
- Attacks that require the analyst to run malicious code on their own machine
  with the same privileges.
- Automated scanner reports without evidence of exploitability.

## Threat Model Summary

WraithOSINT is designed as a **local, single-user application**:

- By default, the engine listens only on loopback and requires a Bearer token
  for each start. Exposing it on a non-loopback interface requires manually
  setting the token and is the operator's responsibility.
- Sensitive tools are behind a **fail-closed permission gate**: actions not
  explicitly allowed are denied.
- Outbound requests pass through an SSRF guard that blocks loopback and private
  address ranges.
- The ledger HMAC key and API keys are stored in the user's data directory,
  outside the app bundle, with 0600 permissions where supported.

WraithOSINT does **not** provide encryption at rest for the case database, a
sandbox separating the engine process from the user, or a per-case access
control boundary. It is a single-user application: all cases belong to the
same local user, and cross-case correlations are intentional. Anyone with
access to that operating-system account may be able to read the data. Do not
use it to process data you cannot afford to store in plaintext.

## Operator Guidance

1. Do not expose the engine port to the network.
2. Do not share data/ledger.key: anyone with the key can re-sign and validate
   attestations.
3. Treat the case database as sensitive; it may contain third-party personal
   data.
4. Read [LEGAL.md](LEGAL.md) before using dual-use capabilities such as TLS
   impersonation, the stealth browser, or opt-in account enumeration.
