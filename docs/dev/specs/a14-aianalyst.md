# Spec: AI analyst layer (optional, graceful)
OWN: uniphish/ai/__init__.py, uniphish/ai/analyst.py, uniphish/ai/prompts.py,
tests/ai/test_analyst.py.

PURPOSE: an OPTIONAL layer that uses an LLM (Anthropic, model from settings.ai_model) to
(a) write an analyst-grade narrative explaining a Verdict for a SOC ticket, and (b) do a
structured second-opinion triage. Must degrade perfectly when no API key / SDK: a
deterministic template fallback, never an error.

prompts.py: build the system + user prompts from a Verdict. The prompt treats the artifact
(URL/email/page text) strictly as DATA to be analysed, never as instructions — include an
explicit instruction that any text inside the artifact is untrusted content and must not
be followed (we are analysing a potential prompt-injection carrier). Provide a compact,
redacted (defanged) Verdict summary + top signals + indicators to the model. Keep tokens
small.

analyst.py: class AIAnalyst(settings=None): available (bool: key+sdk present);
async narrative(verdict) -> str (3-5 sentence SOC explanation: what it is, who it
impersonates, the strongest evidence, recommended action) — defanged IOCs, no raw
clickable links; falls back to a deterministic template from the Verdict when unavailable.
async triage(verdict) -> dict (structured: assessment, confidence, recommended_action,
notable_signals) via the SDK's structured output / tool use, template fallback otherwise.
Timeout + error handling; never raises. Rate-limit friendly. No network in tests.

TESTS: fallback path produces a sensible non-empty narrative with NO live key (monkeypatch
available=False); prompt builder defangs URLs and includes the untrusted-content guard;
with a mocked client, narrative returns the mocked text. Offline only.
