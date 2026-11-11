# Security policy

UniPhish is a security tool that parses hostile input all day, so we take vulnerabilities in
it seriously. Thank you for reporting responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 2.0.x (current, beta) | yes |
| 1.x (the original byte-CNN demo, `api/`, legacy top-level modules) | no, superseded; the legacy `/scan` and `/stix` shims remain for compatibility only |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Use GitHub's private vulnerability reporting: on the repository
(<https://github.com/jeevithg090/UniPhish>) open the **Security** tab and choose **Report a
vulnerability**. That creates a private advisory visible only to the maintainers and you.
If that option is not available to you, open a minimal public issue that says only "I would
like to report a security issue privately" (no details) and a maintainer will arrange a
private channel.

Please include:

* the affected component and version (`uniphish version`) and how you installed it;
* what an attacker can do and what they need (network position, privileges, a crafted
  input, an API key);
* a minimal reproduction: the input or request and the observed versus expected behaviour. Use
  **inert, synthetic** inputs (reserved domains such as `.test` / `.example`); do not send us
  live malware, real credentials or personal data;
* any suggested fix.

We aim to acknowledge a report within a few days, to confirm or dispute it and agree a
disclosure timeline, and to ship a fix for confirmed issues as quickly as their severity
warrants. This is a small volunteer project, so these are targets, not contractual
guarantees. We will credit reporters who want credit.

## What is in scope

Vulnerabilities in UniPhish code and bundled data, for example:

* **SSRF or network-policy bypass**: any way to make the server, the fetch or infra
  analyzers, the sinks, or the detonation sandbox reach a private, loopback, link-local or
  metadata address, or go online when policy forbids it (`uniphish/core/net.py` is the one
  sanctioned gateway).
* **Authentication or authorization bypass** on the API, including the routes listed under
  "known gaps" below if you find *additional* ones or a more severe impact.
* **Parser and file-analysis issues**: crashes, memory or CPU exhaustion (zip bombs, XML
  entity expansion, ReDoS, pathological HTML/MIME/URL), path traversal, or any execution or
  rendering of analysed content.
* **Sandbox / detonation escape** or harmful side effects of detonating a hostile page.
* **Injection into outputs**: XSS in the console, terminal-escape injection in the CLI, rule
  injection in Sigma, Suricata, YARA, STIX or MISP exports (a crafted artifact that makes an
  exported rule match something broader than intended or inject rule syntax), link
  auto-follow in the bot.
* **Secret exposure**: API keys, tokens or IMAP credentials leaking through logs, errors,
  responses or the extension/console storage.
* **Verdict-integrity bypasses that are bugs rather than evasions** (see below), for example
  a way to make the legitimacy logic grant credit it is documented to withhold.
* **Supply-chain concerns** in the repository: a malicious or unsafe asset, rule or
  dependency.

## What is not a vulnerability

* **Detection evasion.** Phishing that UniPhish scores benign, or benign content it flags, is
  a detection-quality issue, not a security vulnerability. The weights are public and the
  engine is not adversarially robust; the evaluation page documents known evasions
  (percent-encoding, leet-speak, bidi controls). Please report these as normal issues, ideally
  with a defanged sample and the verdict, so we can improve data and rules. A bypass of a
  documented *security control* (for example making the legitimacy logic ignore a living-off-
  trusted-sites host) is in scope; a clever URL that merely scores low is not.
* Findings that require a compromised host, a malicious operator, or a malicious API-key
  holder acting within their permissions.
* Denial of service by volumetric traffic, or by an authenticated client within the documented
  limits.
* Issues in third-party dependencies with no UniPhish-specific impact (report upstream).
* Missing hardening that is documented as the operator's job (TLS termination, proxy auth).
* The documented, open items below.

## Known gaps (already documented, not 0-days)

These are described in detail in [docs/threat-model.md](docs/threat-model.md#known-gaps):
the TAXII routes and the legacy `POST /scan` and `POST /stix` are not behind API-key auth; the
API is open when no keys are configured; the rate limiter is naive and in-memory; detonation
cannot pin DNS answers for hostnames; a timed-out CPU-bound analyzer is abandoned rather than
killed. Reports that add a new exploitation path or a worse impact for these are welcome, as
are fixes.

## Safe harbour

We will not pursue or support legal action against anyone who makes a good-faith effort to
follow this policy: test only against your own installation, never against third parties or
real phishing infrastructure, do not access or retain other people's data, do not degrade
services, and give us reasonable time to fix before public disclosure.

## Hardening guidance

Deployment advice (reverse proxy, API keys, container isolation, egress restrictions, running
the sandbox in a disposable VM, leaving online and AI features off for sensitive data) is in
[docs/threat-model.md](docs/threat-model.md#deployment-guidance).
