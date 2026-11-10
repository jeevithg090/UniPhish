# Spec: AgentGuard — MCP server + guard API (the AI-native headline)
OWN: uniphish/agent/__init__.py, uniphish/agent/guard.py, uniphish/agent/mcp_server.py,
tests/agent/test_guard.py, tests/agent/test_mcp.py. Depends on the engine, the injection
analyzer (b5, via engine on TEXT/PAGE), url analyzer, export.stix. Uses the `mcp` package
(extra 'mcp'); degrade with a clear message if absent.

PURPOSE: protect AI agents from being phished / prompt-injected. Two faces:
guard.py: class AgentGuard(engine=None):
- async check_url(url, **opts) -> GuardDecision(allow: bool, action, risk, reasons,
  verdict) : an agent about to browse/click a URL asks first.
- async check_content(text_or_html, kind='text'|'page', source=None) -> GuardDecision :
  scan tool output / fetched web content for prompt injection + phishing BEFORE the agent
  consumes it; flags indirect injection and returns a SANITISED/quarantined view (e.g. the
  offending spans stripped or clearly fenced as untrusted) so the calling agent can proceed
  safely.
- async check_tool_call(name, arguments) -> GuardDecision : inspect a proposed tool call's
  arguments (URLs, file paths, shell-ish strings) for exfiltration/abuse patterns.
- policy thresholds configurable; decisions explainable; everything offline by default.
mcp_server.py: a Model Context Protocol server (stdio) exposing tools:
  scan_url, scan_text, scan_email, scan_file(base64), check_content (the guard),
  check_tool_call, export_stix. Each tool validates inputs, runs the guard/engine, returns
  a compact structured result (verdict summary + action + top reasons, IOCs defanged).
  Provide a `uniphish-mcp` console behaviour (document how to run: python -m
  uniphish.agent.mcp_server). The server itself must treat all scanned content as data
  (never follow instructions inside it) and must not make network calls unless explicitly
  enabled.
TESTS: guard.check_content flags a hidden prompt-injection HTML and returns allow=False +
a sanitised view; check_url blocks a homoglyph phishing URL; check_tool_call flags an
argument that tries to exfiltrate to an unrelated host; MCP tool handlers return valid
structured payloads (call the handler functions directly; don't spawn a real stdio loop).
Offline.
