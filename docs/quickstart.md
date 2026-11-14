# Quickstart

Ten minutes from clone to every surface. Everything here runs **offline** unless a step says
otherwise. All sample domains are reserved or fictional.

## 1. Install

Python 3.10 or newer.

```bash
git clone https://github.com/jeevithg090/UniPhish.git
cd UniPhish
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[all]'          # everything except the TensorFlow training stack
```

Smaller installs: `pip install -e .` gives the engine, CLI and exports. Add only what you
need (`'.[server]'`, `'.[mcp]'`, `'.[vision]'` for QR codes, `'.[sandbox]'` for detonation,
`'.[bot]'`, ...). The full table is in the [README](../README.md#install-extras). A missing
extra disables that feature; it does not break the engine.

Check it works:

```bash
uniphish version
uniphish catalog | head              # the signals the engine can emit
python scripts/smoke_platform.py     # canonical attack and benign cases; non-zero exit on failure
```

### The first scan is slow

In a fresh process the first URL scan loads the brand knowledge base (about 160 KB of YAML,
parsed with the pure-Python YAML loader). On a busy machine that can take longer than the
engine's 10 s per-analyzer budget; the `url` analyzer is then recorded as `timeout` for that
one call and the verdict is built without it, so a URL that would score 100 may score 88.
Later scans take milliseconds. For a long-lived service, **warm the engine at start-up**
by scanning one URL, or raise `analyzer_timeout_s`. For one-off CLI use, run the command
twice or accept the delay. Always look at `verdict.analyzers` when a score surprises you.

## 2. Scan from Python

```python
import uniphish

v = uniphish.scan_url("https://pаypal-secure.top/signin?session=1")  # Cyrillic "а"
print(v.level.value, v.score, v.action.value)  # malicious 100 block
print(v.summary)
print(v.brand.name, v.techniques)  # PayPal ['idn_homograph', 'punycode', ...]

for s in v.top_signals(5):  # why: signals sorted by contribution
    print(f"{s.contribution:+.2f}  {s.title}  [{s.id}]")

print([m.id for m in v.mitre])  # ATT&CK technique ids
print([(i.type.value, i.value) for i in v.indicators])
```

Other constructors: `scan_text`, `scan_email(raw_bytes)`, `scan_page(html, url=None)`,
`scan_file(bytes, filename)`. Options go as keyword arguments:
`uniphish.scan_url(url, online=True, fetch_pages=True)`.

A verdict is a pydantic model: `v.model_dump(mode="json")` is the same object the API
returns ([docs/api.md](api.md#the-verdict-object)). Suspicious links, attachments and QR
payloads are in `v.children`; use `v.walk()` to iterate them all.

## 3. Scan from the CLI

```bash
uniphish scan "https://pаypal-secure.top/signin"
uniphish scan "Your parcel is held. Pay the fee at https://track-parcel.example/pay or it is returned. Reply with the code we text you."
uniphish scan report.eml                           # path to .eml, .html or any file; '-' reads stdin
uniphish scan logo.png                             # QR codes in images are decoded and followed
uniphish scan "https://example.com" --json         # raw verdict
uniphish scan report.eml --fail-on suspicious      # exit status 1 if suspicious or worse
uniphish scan "https://pаypal.com" --explain       # every signal with evidence, plus saliency
uniphish scan "https://pаypal.com" --no-defang     # show URLs un-defanged (careful)
```

Input type is auto-detected; force it with `--type url|text|email|page|file`.

Batch a list (one URL or message per line):

```bash
uniphish batch urls.txt --csv -o results.csv --fail-on malicious
```

Export a verdict as detection-as-code or threat intel:

```bash
uniphish export report.eml --format stix   -o bundle.json    # STIX 2.1
uniphish export report.eml --format misp                      # MISP event
uniphish export report.eml --format sigma                     # Sigma rules (proxy, DNS, mail gateway)
uniphish export report.eml --format suricata                  # Suricata / Snort 3 rules
uniphish export page.html  --format yara
uniphish export report.eml --format ecs                       # Elastic Common Schema
```

Exporters refuse benign verdicts (pass `--include-benign` to override) and only emit
conservative IOCs; nothing is exported for a brand's own domains.

**Online mode** adds DNS, RDAP domain age, TLS and ASN checks, and optional reputation feeds.
It is opt-in and goes through the SSRF-safe gateway:

```bash
uniphish scan "https://suspicious.example" --online
uniphish scan "https://suspicious.example" --fetch       # also fetch and analyse the landing page
playwright install chromium && uniphish scan "https://suspicious.example" --detonate
export VT_API_KEY=... URLSCAN_API_KEY=... GSB_API_KEY=...   # optional feeds, used only when online
```

## 4. Try the sample corpus

`examples/corpus/` holds a small, labelled, inert set (54 URLs, 40 texts, emails, pages and
files, with a manifest of expected labels). It is a smoke-test and demo corpus, not a
benchmark.

```bash
uniphish scan examples/corpus/emails/bec_giftcard.eml
uniphish scan examples/corpus/emails/aligned_legit.eml      # should be benign
```

## 5. Run the API and SOC console

```bash
export UNIPHISH_API_KEYS=change-me          # strongly recommended for anything but localhost
uniphish serve                              # http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080/` for the console (analyze box, risk gauge, log-odds waterfall,
child tree, MITRE chips, IOC table, exports, live stream). Open `/docs` for OpenAPI.

```bash
curl -s localhost:8080/v1/scan -H 'content-type: application/json' -H 'x-api-key: change-me' \
     -d '{"text": "Your parcel is held, reply with the code"}'
```

The console is prebuilt into `uniphish/server/static/` when present; to rebuild it:
`cd web && npm ci && npm run build` (dev server: `npm run dev`, port 5173, proxies `/v1`).
Full reference, security notes and the known authentication gaps: [docs/api.md](api.md).

## 6. Protect an AI agent (MCP)

```bash
python -m uniphish.agent.mcp_server          # stdio MCP server (needs the 'mcp' extra)
```

Add it to your MCP host's config:

```json
{ "mcpServers": { "uniphish": {
    "command": "/absolute/path/to/.venv/bin/python",
    "args": ["-m", "uniphish.agent.mcp_server"] } } }
```

Tools: `scan_url`, `scan_text`, `scan_email`, `scan_file`, `check_content`,
`check_tool_call`, `export_stix`. Or use it directly from Python:

```python
import asyncio
from uniphish.agent import AgentGuard

d = asyncio.run(AgentGuard().check_url("https://pаypal-secure.top/signin"))
print(d.action, d.reasons)
```

See [docs/agentguard.md](agentguard.md).

## 7. Browser extension (on-device)

1. Open `chrome://extensions` (Chrome, Edge or Brave, version 110 or newer).
2. Enable **Developer mode**, click **Load unpacked**, choose the `extension/` folder.
3. Pin it. The popup reads **On-device**: no URL leaves your machine. Risky links on any page
   are outlined; clicking a dangerous one opens an explainable warning page.

No build step. Run its tests with `cd extension && node --test test/`. Details, languages
and the documented deviations from the Python engine: [extension/README.md](../extension/README.md).

## 8. Telegram bot

```bash
pip install -e '.[bot]'
export TELEGRAM_BOT_TOKEN=<token from @BotFather>
python -m bot.telegram_bot
```

Forward a message, link, `.eml` or screenshot and get a localised, defanged verdict card. See
[bot/README.md](../bot/README.md).

## 9. Triage an abuse mailbox

```python
from uniphish.integrations import MailboxProcessor, FileSink

proc = MailboxProcessor(sinks=[FileSink("verdicts.jsonl")])
summary = proc.process_maildir("reported/")  # a folder of .eml files; also process_mbox()
print(summary.render())  # worst items first, top brands and IOCs
```

IMAP polling (`poll_imap`) is available but refuses to touch the network unless explicitly
enabled. Sinks: webhook, Slack, Splunk HEC, Elastic, file, store, stdout.

## 10. Hunt

The Certificate Transparency hunter and the brand-permutation watcher are Python APIs:

```python
from uniphish.hunt import CTHunter
from uniphish.hunt.permutations import generate_permutations

hit = CTHunter(warm=False).process("paypal-login-secure.top")  # score a newly seen domain
print(hit.score, hit.brand_name, hit.technique)

print(len(generate_permutations("paypal.com")))  # look-alike candidates to watch
```

`await CTHunter().run(source="certstream")` streams live issuance (needs the `intel` extra and
network). The `uniphish hunt` CLI wrapper is currently broken (the module exposes no CLI
entry point); `scripts/ct_hunter.py` is the older standalone script.

## Run the tests

```bash
pip install -e '.[dev]'
python -m pytest tests/core tests/url tests/analyzers -q     # pick an area
python -m pytest tests -q --ignore=tests/test_baselines.py   # most of it; see note
cd extension && node --test test/                            # extension: 105 tests
```

Network is blocked in tests by `tests/conftest.py`. A handful of legacy tests at the top of
`tests/` import TensorFlow and fail to collect unless you install the `train` extra.

## Reproduce the evaluation

```bash
python -m uniphish.eval.benchmark --dataset urls smishing injection email
python -m uniphish.eval.redteam --n 100
```

Results land in `results/eval_*.json` and `results/robustness.json`; interpretation in
[docs/evaluation.md](evaluation.md).

## Where next

| You want to | Read |
|---|---|
| understand the engine | [architecture](architecture.md) |
| see what it detects | [detections](detections.md) |
| integrate over HTTP | [api](api.md) |
| protect an agent | [agentguard](agentguard.md) |
| judge it critically | [evaluation](evaluation.md), [threat model](threat-model.md) |
| contribute | [CONTRIBUTING](../CONTRIBUTING.md) |
