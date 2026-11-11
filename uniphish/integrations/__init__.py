"""Integrations: the abuse-inbox processor and outbound verdict sinks.

* :mod:`uniphish.integrations.mailbox` - scan reported e-mail (single message, Maildir,
  mbox, IMAP) and produce a triage summary.
* :mod:`uniphish.integrations.sinks` - webhook, Slack, Splunk HEC, Elasticsearch, store,
  JSONL file and stdout sinks plus :func:`fan_out`.
"""

from __future__ import annotations

from uniphish.integrations.mailbox import (
    MailboxError,
    MailboxNetworkDisabled,
    MailboxProcessor,
    TriageItem,
    TriageSummary,
)
from uniphish.integrations.sinks import (
    BaseSink,
    ElasticSink,
    FileSink,
    Sink,
    SinkError,
    SinkResult,
    SlackSink,
    SplunkHECSink,
    StdoutSink,
    StoreSink,
    WebhookSink,
    fan_out,
)

__all__ = [
    "BaseSink",
    "ElasticSink",
    "FileSink",
    "MailboxError",
    "MailboxNetworkDisabled",
    "MailboxProcessor",
    "Sink",
    "SinkError",
    "SinkResult",
    "SlackSink",
    "SplunkHECSink",
    "StdoutSink",
    "StoreSink",
    "TriageItem",
    "TriageSummary",
    "WebhookSink",
    "fan_out",
]
