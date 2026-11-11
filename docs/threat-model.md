# Threat model

A security tool is itself a target. This page covers two things: **what UniPhish defends
against**, and **how UniPhish itself can be attacked**, with the controls that exist today and
the gaps that remain. It is written from the code as it stands (2.0.0, beta); where something
is unverified or unfixed it says so. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

Contents: [Scope](#scope-and-assumptions) | [Part 1: what we detect](#part-1-the-threats-uniphish-detects) |
[Part 2: attacks on UniPhish](#part-2-attacks-on-uniphish-itself) | [Known gaps](#known-gaps) |
[Deployment guidance](#deployment-guidance)

## Scope and assumptions

**Assets to protect**

* Users and agents relying on a verdict (integrity of the decision).
* The host running UniPhish and the networks it can reach (it fetches hostile URLs, parses
  hostile files, and can launch a browser).
* Operator data: the verdict store, reputation allow/deny lists, API keys, third-party feed
  keys, the Anthropic key, the Telegram token, IMAP credentials.
* Privacy of what users scan (URLs and messages can be sensitive).

**Adversaries**

* A phishing operator who wants to evade detection (knows UniPhish exists, may read this repo).
* A phishing page or email that attacks the *scanner* (SSRF, parser bugs, resource exhaustion,
  prompt injection of the LLM analyst or of an agent).
* A network attacker or unauthenticated client reaching the API.
* A malicious contributor or supply-chain attacker (data files, dependencies, rules).

**Out of scope**: compromise of the host OS, the Python runtime or the browser engine; zero-day
vulnerabilities in third-party libraries (we depend on `lxml`, `httpx`, `cryptography`,
Playwright and others); physical access; denial of service by a party with raw network
capacity; defending a user who ignores a warning.

**Trust assumptions**: the operator is trusted and the API key holder is trusted. Every
analysed input, every fetched byte and every header value is untrusted. Operator-supplied
configuration (IMAP host, webhook URLs) is trusted but sinks still apply SSRF filtering.

# Part 1: the threats UniPhish detects

| Threat | How it is addressed | Honest limit |
|---|---|---|
| **Homoglyph / IDN spoofing** across scripts | UTS #39 skeleton, script mixing, whole-script confusables, invisible, bidi and combining-mark abuse, IDN display policy, brand skeleton matching | strong on known constructions; novel constructions and native-script brand in a *path* are weaker (42.9 % recall on that sub-group) |
| **Brand impersonation** (typo, bit-flip, combo, sub-domain, path) | 680-brand KB, official and user-content host awareness | typosquats without other cues: 50 % recall in the benchmark |
| **AiTM / MFA bypass** (Evilginx style proxies) | kit signatures on page structure and config artefacts, cross-origin credential forms | detects fingerprints in HTML it is given; a proxy serving a pixel-perfect clone with no fingerprint is not caught by content rules, and the online path is unevaluated |
| **ClickFix / fake CAPTCHA** | clipboard-write and "paste into Run" lure signatures; runtime clipboard capture under detonation | static text variants are caught by pattern; obfuscated JS needs detonation |
| **Browser-in-the-Browser, OAuth consent, device-code phishing, callback (TOAD), wallet drainers** | kit signatures, callback-number and urgency NLP | pattern based |
| **HTML / SVG smuggling, double extensions, RTLO names, macros, encrypted archives** | static file analysis with bounded extraction | no dynamic execution of attachments, by design |
| **QR-code phishing** | QR decoded from images (including inside emails and attachments) and the payload is analysed as a child | needs the `vision` extra (OpenCV); heavily distorted codes may not decode |
| **Smishing / BEC / vishing lures** (multilingual) | 30-language lure lexicons, OTP / payment / callback detection | recall 61.8 % on the small benchmark; no-link scams and several languages are weak |
| **Email authentication abuse** | SPF/DKIM/DMARC from `Authentication-Results`, display-name and Reply-To spoofing | reads the *receiving server's* headers; does **no DNS lookup** of SPF/DMARC itself, so a message without those headers gives no auth evidence |
| **Living-off-trusted-sites hosting** | LOTS list (`pages.dev`, `sites.google.com`, ...) withholds reputation credit | list is curated, not exhaustive |
| **Prompt injection against AI agents** (direct, indirect, hidden, obfuscated; MITRE ATLAS AML.T0051) | injection analyzer plus AgentGuard quarantine and tool-call vetting | recall 77.3 %; leet-speak and bidi evasions beat it; see [agentguard.md](agentguard.md#what-it-misses) |
| **Agent data exfiltration via tool calls** | credential-path, data-parameter and exfil-sink signatures in tool arguments | signature based; a novel sink is unknown |

## Detection evasion (what an adaptive attacker will try)

Measured by the scripted red-team ([evaluation.md](evaluation.md#red-team-results-scripted-evasions-offline)):

* **Percent-encoding** and double encoding are the strongest URL evasion (fusion misses up to
  16 % of previously caught URLs) because the CNN reads the encoded form as benign and its
  evidence outweighs the rules.
* **Path padding** blinds the CNN entirely (100 %); rules and fusion hold.
* **Leet-speak and bidi isolates** defeat prompt-injection patterns (94 % and 65 %).
* **Reply-to swap** from a compromised but authenticated vendor mailbox scores about 43, below
  the warn line.
* **Brand-new infrastructure with no lexical tell** is invisible offline; online signals
  (domain age, certificate freshness) are meant to cover it but were not benchmarked.
* The weights are public. An attacker can search for URLs that score under 0.50. Nothing in
  the design assumes security through obscurity; defence is layered evidence plus online and
  reputation signals, and it is **not adversarially robust** against an adaptive adversary,
  which has not been evaluated.

Treat UniPhish as one layer. Do not make it the only control between a user and a payload.

# Part 2: attacks on UniPhish itself

## Attack surface

```text
  hostile input ---> parsers (URL, HTML, email, MIME, files, archives, Office, PDF, images, QR)
  hostile host  ---> fetch / infra / feeds / detonation (network egress)
  API clients   ---> FastAPI (auth, rate limit, size caps, SSE, TAXII, legacy routes)
  agents / MCP  ---> AgentGuard (stdio)
  rules / data  ---> YAML assets, kit signatures, brand lists (supply chain)
  LLM analyst   ---> third-party API (data egress)
  browser ext.  ---> content script on every page, optional API endpoint
```

## Threats and controls

| # | Threat | Control in the code | Residual risk |
|---|---|---|---|
| 1 | **SSRF**: a scanned URL (or redirect, or DNS answer) points at cloud metadata, loopback or internal hosts | single gateway `core.net.safe_fetch`: resolve once, validate every IP against a full non-public blocklist (private, loopback, link-local incl. 169.254.169.254, CGNAT, multicast, reserved, and every IPv6 embedding), **pin the validated IP** for the connection while keeping Host, SNI and cert verification, manual redirect following with per-hop checks, numeric and hex/octal IP rejection, port allow-list, proxies ignored | the gateway is only as good as the discipline of using it; a code path that bypasses it is a vulnerability. **Detonation is weaker**: the browser resolves names itself, so a hostname whose DNS answer is private is not caught (literal IPs and a name list are); this is a documented residual risk. |
| 2 | **Resource exhaustion**: huge inputs, decompression bombs, deep recursion, slow responses | size caps at artifact construction, streaming body cap plus a decompressed-size cap, bounded archive extraction, child depth/fan-out/cycle limits, per-analyzer and global timeouts, bounded SSE queues, rate limiting | analyzers run in-process threads: a timed-out CPU-bound analyzer is *abandoned*, not killed, and may keep a worker thread busy. No process-level sandboxing or memory limit. |
| 3 | **ReDoS** in rules fed by attacker text | regexes precompiled; kit-signature regexes are linted at load (no unbounded repeats, back-references, nested variable repeats or alternation in a repeat); inputs truncated before matching; Hypothesis tests on parsers | contributed rules must pass the linter; third-party libraries' regexes are out of our control |
| 4 | **Parser exploits** (XML bombs, HTML nesting, malformed MIME, hostile archives, Office, PDF, images) | `defusedxml` for XML/SVG, bounded HTML parsing, bounded MIME depth, archive extraction caps, files are never executed or opened by path from input contents, QR decoding via OpenCV on size-bounded images | native libraries (OpenCV, lxml, Pillow) have their own CVE history; keep them updated, and consider process isolation for untrusted bulk scanning |
| 5 | **Unauthenticated API use** | API-key auth (constant-time compare), rate limit, size cap, option clamps, strict security headers, no CORS by default | **see Known gaps**: auth is off by default; TAXII and legacy routes bypass it |
| 6 | **Forcing the server online** (SSRF amplification or egress abuse) | `online` is honoured only if the operator enabled it; `fetch_pages` and `detonate` forced off when offline | an operator who enables online accepts the egress risk |
| 7 | **Malicious page runs in the sandbox browser** | headless Chromium, JavaScript only inside the page, sub-resources blocked by default, downloads off, service workers blocked, file:/chrome: and private IP literals aborted, hard timeouts, only observations returned | the browser is a high-value attack surface. Flags include `--disable-features=site-per-process` and the context ignores HTTPS errors (to see invalid-cert phishing). **Run detonation only in a disposable, egress-restricted container or VM, never on a workstation.** `--no-sandbox` exists as a CI escape hatch; do not use it on hosts you care about. |
| 8 | **Prompt injection of the LLM analyst** | prompts present artifacts as defanged, size-bounded quoted data inside delimiters with an explicit guard; only a compact digest of the verdict (top signals, indicators, brand) is sent, never raw content; output limited to prose and a fixed-schema tool call; **the analyst never changes the score** | an LLM can still be influenced by quoted text; its narrative is advisory. Defanged strings and indicators (domains, hashes) do leave the machine when `ANTHROPIC_API_KEY` is set; leave it unset to stay fully local (a template is used). |
| 9 | **Prompt injection reaching an agent via UniPhish output** | MCP and AgentGuard return defanged, structured data; sanitized content is fenced and marked untrusted | the quarantine is best effort and partial removal can leave fragments |
| 10 | **Data egress of user content to third parties** | offline by default; reputation feeds only when online **and** keyed, and non-public hosts are never sent; extension is on-device and its only optional network call goes to a server *you* configure | enabling feeds sends the scanned URL or its domain to Google Safe Browsing, VirusTotal or urlscan.io (lookups and searches, not scan submissions), which can itself leak that someone is investigating a link; review before enabling for sensitive URLs |
| 11 | **Rules and data supply chain** (poisoned brand list, rule, TLD weight; compromised dependency) | detection data are plain YAML reviewed in PRs; `extension/tools/build_data.py --check` verifies the extension's generated data matches the canonical assets; provenance recorded in `assets/README.md` | no signing of assets; no dependency pinning or SBOM yet; Tranco and disposable lists are point-in-time snapshots. A malicious allow-list entry is the worst case (it grants legitimacy), so review any change that adds official domains. |
| 12 | **Allowlist abuse / reputation laundering** | top-site and official-brand credit withheld for LOTS, shortener, dynamic-DNS, open-redirect and `user@host` cases; local allow entries for email are honoured only with aligned DMARC | still depends on the curated lists above |
| 13 | **Output injection** (XSS, terminal escape, link auto-follow) | CLI and bot defang URLs and strip control characters; the API never reflects raw input unescaped in errors; console uses relative URLs, no external requests, strict CSP; exports escape Suricata/YARA/Sigma strings | exports are generated from attacker-influenced strings: review rules before pushing to production sensors |
| 14 | **Poisoned verdict store / TAXII feed** (a scanned artifact planting indicators that later block legitimate things) | exporters drop brands' legitimate hosts and never emit domain-level rules for shared platforms; benign verdicts are not exported by default; private addresses dropped | an attacker who can submit scans (open API) can influence which IOCs appear in the feed and the "never seen before" novelty signal. Authenticate the API and review feeds before automatic blocking. |
| 15 | **Extension abuse** | MV3, strict extension CSP, no remote code, on-device scoring, optional host permissions requested only on demand; the content script only reads link hrefs and annotates | the extension reads link targets on every page you visit (it does not send them anywhere unless you configure a server) |
| 16 | **Credential exposure** (IMAP, API keys, tokens) | secrets from environment; IMAP password never logged and scrubbed from errors; IMAP requires TLS and is off unless enabled; console keeps API keys in `sessionStorage` only | keys in the environment are visible to anything on the host that can read the process environment; no secret manager integration |

## Safe-by-default summary

Offline analysis, no execution of any analysed content, one network gateway, bounded
everything, fault-isolated analyzers, defanged output, conservative exports. These are
*defaults*; several can be relaxed by the operator and each relaxation moves risk onto the
deployment.

# Known gaps

These are real, current and unfixed at the time of writing. They are listed so that an
operator can compensate, and so that nobody discovers them the hard way.

1. **Authentication does not cover every route.** With `UNIPHISH_API_KEYS` set, `/v1/scan*`,
   `/v1/verdicts*`, `/v1/stats`, `/v1/indicators`, `/v1/export/*` and `/v1/stream` require a
   key (verified). `/taxii2/*` (which serves every stored malicious indicator), the legacy
   `POST /scan` and `POST /stix`, `/v1/health` and `/v1/meta/*` do **not**. The legacy scan
   routes run the offline engine for anyone who can reach the port and the TAXII routes
   expose the IOC store. **Mitigation**: bind to loopback, or put a reverse proxy with its own
   auth in front and block those paths; do not expose the server directly.
2. **Auth is off by default.** With no keys configured the whole API is open (it says so with
   `X-UniPhish-Auth: disabled`, and `uniphish serve` warns when binding a non-loopback address
   without keys).
3. **Rate limiting is naive.** In-memory, per process; keyed by whatever key string a client
   presents (including invalid ones, so a client can mint new buckets) or by the socket peer
   address (the proxy's, behind a reverse proxy). The size cap checks `Content-Length` only.
   Enforce limits and body caps at the proxy.
4. **The CNN raises false alarms** (25 % FPR on the synthetic URL set; alone it lands at about
   88/100) and the fused score is poorly calibrated (ECE 0.145). Do not auto-block on the
   Python engine's ML signal alone without corroboration.
5. **Cold-start timeout.** The first scan in a process can time out the `url` analyzer while
   the brand data loads, silently dropping its evidence for that call. Warm the engine at
   start-up. A timed-out analyzer is visible only in `verdict.analyzers`.
6. **Detonation DNS residual risk** (threat 7 and 1) and the abandoned-thread behaviour on
   analyzer timeouts (threat 2).
7. **No adaptive-adversary evaluation, no real-traffic false-positive rate, and the online
   path has no benchmark.**
8. **Event stream is per process**, and the SSE endpoint cannot be authenticated from a plain
   browser `EventSource`.
9. **`uniphish hunt` CLI wrapper is broken**; the CT hunter works as a Python API. It consumes
   a public WebSocket firehose, so apply the same input-hostility assumptions to its data.
10. **Legacy TensorFlow modules** at the top level of `uniphish/` are research code, not
    hardened; they are not imported by the runtime engine.

# Deployment guidance

* **Personal or desktop use**: install the extension (fully on-device) and use the CLI offline.
  Nothing leaves your machine.
* **Team API**: run `uniphish serve` on loopback behind a TLS-terminating reverse proxy that
  adds authentication, rate limits, body size caps and blocks `/taxii2/`, `/scan` and `/stix` if
  you do not need them; set `UNIPHISH_API_KEYS`; leave `UNIPHISH_ONLINE` off unless you need
  enrichment; run as an unprivileged user in a container with a read-only filesystem except
  `UNIPHISH_DATA_DIR`; restrict egress to DNS and HTTPS.
* **Online enrichment and fetch**: egress through a network where private ranges are
  unreachable regardless of the gateway (defence in depth against SSRF bugs).
* **Detonation**: dedicated disposable VM or container, no secrets, no route to internal
  networks, no persistent volume, resource limits, short lifetime. Treat the sandbox as
  compromised after each hostile page.
* **Agent use (MCP)**: keep `UNIPHISH_MCP_ONLINE` off unless needed; keep human approval for
  consequential tool calls; remember that AgentGuard output is evidence, not a guarantee.
* **Feeds and sinks**: review exported rules before automated deployment to blocking
  controls; start in alert-only mode.
* **LLM analyst**: leave `ANTHROPIC_API_KEY` unset if scanned content is confidential.
* **Keep dependencies and the Playwright browser patched**, and re-run the test suite after
  upgrades.
