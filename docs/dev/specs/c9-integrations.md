# Spec: inbound mailbox + outbound sinks
OWN: uniphish/integrations/__init__.py, uniphish/integrations/mailbox.py,
uniphish/integrations/sinks.py, tests/integrations/test_mailbox.py,
tests/integrations/test_sinks.py. Depends on the engine (scan_email), store, export.*,
core.net (for webhooks, SSRF-guarded), core.events.bus.

mailbox.py: an abuse-inbox processor — class MailboxProcessor(engine, store, sinks=()):
process_eml_bytes(raw) -> Verdict (scan_email + persist + fan to sinks); process_maildir
(dir) / process_mbox(path) for offline batch triage of a folder of reported phish.
Optional IMAP poller: async poll_imap(host, user, password, folder='INBOX', *, move_to=
None, since=None) using imaplib/aioimaplib-if-present — fetch unseen, scan, act; all
network gated + off in tests. Produce a triage summary (counts by level, top brands/IOCs).
sinks.py: a Sink protocol (async send(verdict)). Implementations: WebhookSink(url, *,
min_level) POSTs the Verdict JSON via core.net.safe_fetch (SSRF-guarded, so a sink URL
can't be used for SSRF); SlackSink(webhook_url) posts a formatted (defanged) message;
SplunkHECSink(url, token) + ElasticSink(url, index, api_key) send ECS docs
(export.ecs.to_ecs); StoreSink(store); FileSink(path) appends JSONL; StdoutSink. A
fan_out(verdict, sinks) helper respecting each sink's min_level. All sinks defang and never
leak secrets; failures are isolated/logged.
TESTS (offline): process a synthetic phishing .eml -> verdict persisted + a FileSink/
StoreSink receives it; WebhookSink uses safe_fetch (mock it; assert it would block a
private URL); Slack/ECS payload shape; min_level filtering. No real IMAP/network.
