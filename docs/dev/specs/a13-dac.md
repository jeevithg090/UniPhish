# Spec: detection-as-code export (Sigma / Suricata / YARA / Elastic ECS)
OWN: uniphish/export/sigma.py, uniphish/export/suricata.py, uniphish/export/yara.py,
uniphish/export/ecs.py, tests/export/test_dac.py.

PURPOSE: let a defender deploy UniPhish findings into their own stack — this is what makes
SOC teams care. Build valid, loadable rules from a Verdict's IOCs.

sigma.py: to_sigma(verdict) -> dict (valid Sigma rule YAML structure: title, id (uuid5),
status, description, references, tags (attack.t1566 etc from verdict.mitre), logsource
(category: proxy / product: zeek or email), detection selection on url|domain|dest host,
condition, falsepositives, level). to_sigma_yaml(verdict)->str. Produce proxy/web-proxy
rules for URL/domain IOCs and an email rule for sender/domain.

suricata.py: to_suricata_rules(verdict) -> list[str]: emit valid Suricata/Snort rules —
a TLS SNI / HTTP Host rule for the phishing domain and an HTTP uri/content rule, with
msg (incl. brand+technique), classtype, a stable sid range (document the range; keep sids
deterministic from a hash), rev, metadata (mitre, created). Escape content properly.

yara.py: to_yara(verdict) -> str: a valid YARA rule matching the phishing URL/domain
strings + any kit fingerprint strings present, with meta (author, description, mitre,
score) and a condition. Sanitise identifiers (valid rule name) and escape strings.

ecs.py: to_ecs(verdict) -> dict: an Elastic Common Schema document (event.kind=alert,
event.category=[threat], threat.indicator.* [type,url.full,url.domain,ip,file.hash.sha256],
threat.technique.id/name, threat.tactic, rule.name, url.*, related.hosts, risk.score,
message). to_ndjson(verdicts).

Keep all generators pure (no engine run). Validate YAML/JSON parses; validate Sigma has
required keys; validate Suricata rule strings have balanced parens/semicolons. Tests build
synthetic Verdicts and assert the rule content + IOC presence + MITRE tagging.
