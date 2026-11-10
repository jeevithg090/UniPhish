# Spec: labelled sample corpus
OWN: everything under examples/corpus/ (data + a README + a manifest.yaml), and a loader
uniphish/eval/corpus.py, tests/eval/test_corpus.py. Coordinate with eval (c10) — corpus.py
feeds datasets.py style loaders.

Build a documented, labelled, SYNTHETIC/defanged corpus for demos, tests and the README
gallery: examples/corpus/urls.jsonl (phishing-style + benign URLs across scripts + attack
techniques, each {input, label, note, expected_techniques?}), texts.jsonl (smishing + BEC
+ benign + prompt-injection messages, multilingual), emails/ (synthetic .eml: spoofed
display name, DMARC-fail, BEC gift-card, aligned legit, forwarded-phish, with a README
mapping file->label), pages/ (synthetic HTML: cross-origin cred form, ClickFix lure,
brand-content mismatch, benign login — defanged, inert), files/ (inert synthetic samples:
double-extension name, svg-with-script, a QR PNG that encodes a defanged phishing URL, an
html-smuggling stub with benign magic — NO real malware), manifest.yaml indexing every item
with its label + the headline signal it should trigger. EVERYTHING must be inert and use
reserved/example domains; this is a teaching/benchmark corpus, not live threats.
corpus.py: load_corpus() -> iterator of (kind, payload, label, meta); helpers to materialise
each item as an Artifact spec for the engine.
TESTS: the corpus loads; every item has a label + the file exists; a smoke run of the engine
over a few items gives the expected level direction (phishing->not benign, benign->benign)
offline; counts per category reported.
