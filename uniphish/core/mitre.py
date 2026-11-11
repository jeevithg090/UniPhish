"""MITRE ATT&CK (Enterprise) and MITRE ATLAS (AI systems) techniques used by UniPhish.

Signals reference techniques by id (``Signal.mitre``); the engine resolves them into
:class:`~uniphish.core.types.MitreTechnique` objects on the verdict. ATLAS ids cover
attacks on AI agents (prompt injection), which UniPhish's AgentGuard detects.
"""

from __future__ import annotations

from uniphish.core.types import MitreTechnique

_ATTACK = "https://attack.mitre.org/techniques/"
_ATLAS = "https://atlas.mitre.org/techniques/"

# id -> (name, tactic, framework)
CATALOG: dict[str, tuple[str, str, str]] = {
    # Initial access / delivery
    "T1566": ("Phishing", "initial-access", "attack"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "initial-access", "attack"),
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access", "attack"),
    "T1566.003": ("Phishing: Spearphishing via Service", "initial-access", "attack"),
    "T1566.004": ("Phishing: Spearphishing Voice", "initial-access", "attack"),
    "T1189": ("Drive-by Compromise", "initial-access", "attack"),
    "T1078": ("Valid Accounts", "initial-access", "attack"),
    # Reconnaissance (credential harvesting)
    "T1598": ("Phishing for Information", "reconnaissance", "attack"),
    "T1598.002": ("Phishing for Information: Spearphishing Attachment", "reconnaissance", "attack"),
    "T1598.003": ("Phishing for Information: Spearphishing Link", "reconnaissance", "attack"),
    "T1598.004": ("Phishing for Information: Spearphishing Voice", "reconnaissance", "attack"),
    # Resource development
    "T1583.001": ("Acquire Infrastructure: Domains", "resource-development", "attack"),
    "T1583.006": ("Acquire Infrastructure: Web Services", "resource-development", "attack"),
    "T1584.001": ("Compromise Infrastructure: Domains", "resource-development", "attack"),
    "T1585.002": ("Establish Accounts: Email Accounts", "resource-development", "attack"),
    "T1586.002": ("Compromise Accounts: Email Accounts", "resource-development", "attack"),
    "T1608.005": ("Stage Capabilities: Link Target", "resource-development", "attack"),
    # Execution / user execution
    "T1204.001": ("User Execution: Malicious Link", "execution", "attack"),
    "T1204.002": ("User Execution: Malicious File", "execution", "attack"),
    "T1204.004": ("User Execution: Malicious Copy and Paste", "execution", "attack"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution", "attack"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "execution", "attack"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "defense-evasion", "attack"),
    # Defense evasion
    "T1036": ("Masquerading", "defense-evasion", "attack"),
    "T1036.007": ("Masquerading: Double File Extension", "defense-evasion", "attack"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion", "attack"),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", "defense-evasion", "attack"),
    "T1027.009": ("Obfuscated Files or Information: Embedded Payloads", "defense-evasion",
                  "attack"),
    "T1497": ("Virtualization/Sandbox Evasion", "defense-evasion", "attack"),
    "T1553.005": ("Subvert Trust Controls: Mark-of-the-Web Bypass", "defense-evasion", "attack"),
    "T1564.001": ("Hide Artifacts: Hidden Files and Directories", "defense-evasion", "attack"),
    "T1656": ("Impersonation", "defense-evasion", "attack"),
    # Credential access
    "T1557": ("Adversary-in-the-Middle", "credential-access", "attack"),
    "T1539": ("Steal Web Session Cookie", "credential-access", "attack"),
    "T1111": ("Multi-Factor Authentication Interception", "credential-access", "attack"),
    "T1621": ("Multi-Factor Authentication Request Generation", "credential-access", "attack"),
    "T1528": ("Steal Application Access Token", "credential-access", "attack"),
    "T1056.003": ("Input Capture: Web Portal Capture", "credential-access", "attack"),
    # C2 / exfiltration
    "T1102": ("Web Service", "command-and-control", "attack"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control", "attack"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration", "attack"),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", "exfiltration",
                  "attack"),
    # Impact / fraud
    "T1657": ("Financial Theft", "impact", "attack"),
    "T1534": ("Internal Spearphishing", "lateral-movement", "attack"),
    # MITRE ATLAS — attacks on AI systems / agents
    "AML.T0051": ("LLM Prompt Injection", "execution", "atlas"),
    "AML.T0051.000": ("LLM Prompt Injection: Direct", "execution", "atlas"),
    "AML.T0051.001": ("LLM Prompt Injection: Indirect", "execution", "atlas"),
    "AML.T0054": ("LLM Jailbreak", "privilege-escalation", "atlas"),
    "AML.T0057": ("LLM Data Leakage", "exfiltration", "atlas"),
    "AML.T0053": ("LLM Plugin Compromise", "execution", "atlas"),
    "AML.T0068": ("LLM Prompt Obfuscation", "defense-evasion", "atlas"),
}


def resolve(technique_id: str) -> MitreTechnique:
    """Resolve an id to a MitreTechnique (unknown ids are returned with name=id)."""
    name, tactic, framework = CATALOG.get(technique_id, (technique_id, "", "attack"))
    if framework == "atlas":
        url = _ATLAS + technique_id
    else:
        url = _ATTACK + technique_id.replace(".", "/")
    return MitreTechnique(id=technique_id, name=name, tactic=tactic, framework=framework, url=url)


def resolve_many(ids: list[str] | set[str]) -> list[MitreTechnique]:
    return [resolve(i) for i in sorted(set(ids))]
