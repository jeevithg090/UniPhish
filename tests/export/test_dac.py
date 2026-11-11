"""Tests for detection-as-code exports (Sigma / Suricata / YARA / ECS) from synthetic verdicts."""

from __future__ import annotations

import json
import uuid

import pytest
import yaml
import yara as yara_lib

from uniphish.core.types import (
    Action,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Signal,
    Verdict,
)
from uniphish.export.ecs import to_ecs, to_ndjson
from uniphish.export.sigma import (
    NoIndicatorsError,
    collect_iocs,
    to_sigma,
    to_sigma_rules,
    to_sigma_yaml,
    validate_sigma,
)
from uniphish.export.suricata import (
    SID_BASE,
    SID_SPAN,
    escape_content,
    to_suricata_rules,
    validate_suricata_rule,
)
from uniphish.export.yara import escape_string, rule_name, to_yara

URL = "https://login.paypa1-secure.test/signin/verify?id=7&x=a;b"
KIT = "evilginx-style-marker-0001"


def make(target=URL, kind=ArtifactKind.URL, level=Level.MALICIOUS, score=97, indicators=None,
         signals=None, brand=True, children=None, **kw) -> Verdict:
    return Verdict(
        kind=kind, target=target, artifact_id="a" * 24, risk=score / 100, score=score,
        logit=3.0, level=level, action=Action.BLOCK if level is Level.MALICIOUS else Action.WARN,
        confidence=0.9,
        brand=BrandMatch(brand="paypal", name="PayPal", technique="homoglyph", confidence=0.9,
                         legit_domains=["paypal.com"]) if brand else None,
        indicators=indicators if indicators is not None else [
            Indicator(type=IndicatorType.DOMAIN, value="login.paypa1-secure.test",
                      role="landing", malicious=True),
            Indicator(type=IndicatorType.IPV4, value="198.51.100.7", malicious=True),
            Indicator(type=IndicatorType.IPV4, value="10.0.0.5", malicious=True),
            Indicator(type=IndicatorType.EMAIL, value="Billing@Paypa1-Secure.test",
                      role="sender"),
            Indicator(type=IndicatorType.DOMAIN, value="paypal.com", malicious=True),
            Indicator(type=IndicatorType.SHA256, value="ab" * 32, malicious=True),
        ],
        signals=signals if signals is not None else [
            Signal(id="url.brand.homoglyph", title="t", weight=4, category="url",
                   mitre=["T1566.002", "T1656"]),
            Signal(id="kit.aitm.fingerprint", title="k", weight=7, category="kit",
                   mitre=["T1557"], evidence={"fingerprints": [KIT, "x"]}),
        ],
        children=children or [],
        **{"summary": "Homoglyph PayPal login on a lookalike domain.", **kw})


def _split_opts(rule: str) -> str:
    return rule[rule.index("(") + 1:]


# ------------------------------------------------------------------ IOC selection
def test_collect_iocs_filters_unsafe():
    i = collect_iocs(make())
    assert "login.paypa1-secure.test" in i.domains
    assert "paypal.com" not in i.domains          # brand legit domain dropped
    assert i.ips == ["198.51.100.7"]              # RFC1918 dropped
    assert i.emails == ["billing@paypa1-secure.test"]
    assert i.sha256 == ["ab" * 32]
    assert i.kit_strings == [KIT]                 # too-short string dropped
    assert i.urls and i.urls[0].host == "login.paypa1-secure.test"


def test_benign_verdict_yields_nothing():
    v = make(level=Level.BENIGN, score=3)
    assert collect_iocs(v).empty()
    assert to_suricata_rules(v) == []
    with pytest.raises(NoIndicatorsError):
        to_sigma(v)
    with pytest.raises(NoIndicatorsError):
        to_yara(v)
    assert "indicator" not in to_ecs(v).get("threat", {})
    assert to_ecs(v)["event"]["kind"] == "event"


def test_benign_child_not_blocked():
    benign_child = make(target="https://good.example/", level=Level.BENIGN, score=2,
                        indicators=[], signals=[], brand=False)
    v = make(children=[benign_child])
    assert "good.example" not in collect_iocs(v).domains


def test_shared_host_never_domain_level():
    v = make(target="https://evil1.pages.dev/login", indicators=[], signals=[])
    i = collect_iocs(v)
    assert i.domains == [] and i.shared_hosts == ["evil1.pages.dev"]
    sig = to_sigma(v)
    assert "selection_host_exact" not in sig["detection"]
    assert sig["detection"]["selection_url_1"] == {"cs-host": "evil1.pages.dev",
                                                   "c-uri|startswith": "/login"}
    assert not any("tls.sni" in r for r in to_suricata_rules(v))
    assert any("http.uri" in r for r in to_suricata_rules(v))
    assert to_ecs(v)["threat"]["indicator"]["type"] == "url"


def test_defanged_indicator_refanged():
    v = make(target="hxxps://bad[.]example/x", indicators=[], signals=[])
    assert collect_iocs(v).domains == ["bad.example"]


def test_idn_domain_ascii():
    v = make(target="https://bücher.example/a", indicators=[], signals=[])
    assert "xn--bcher-kva.example" in collect_iocs(v).domains


# ------------------------------------------------------------------ Sigma
def test_sigma_proxy_rule_structure():
    rule = to_sigma(make())
    assert validate_sigma(rule) == []
    uuid.UUID(rule["id"])
    assert rule["logsource"] == {"category": "proxy"}
    assert "login.paypa1-secure.test" in rule["detection"]["selection_host_exact"]["cs-host"]
    assert ".login.paypa1-secure.test" in \
        rule["detection"]["selection_host_subdomain"]["cs-host|endswith"]
    assert rule["detection"]["selection_ip"] == {"dst_ip": ["198.51.100.7"]}
    assert rule["level"] == "critical"
    assert rule["falsepositives"]


def test_sigma_mitre_tags():
    tags = to_sigma(make())["tags"]
    assert "attack.t1566.002" in tags and "attack.initial_access" in tags
    assert "attack.t1557" in tags and "attack.credential_access" in tags


def test_sigma_multiple_rules_and_yaml_roundtrip():
    rules = to_sigma_rules(make())
    kinds = [r["logsource"] for r in rules]
    assert {"category": "proxy"} in kinds
    assert {"product": "zeek", "service": "dns"} in kinds
    assert {"category": "email"} in kinds
    docs = list(yaml.safe_load_all(to_sigma_yaml(make())))
    assert docs == rules
    assert all(validate_sigma(d) == [] for d in docs)


def test_sigma_deterministic_ids():
    a, b = to_sigma(make()), to_sigma(make())
    assert a["id"] == b["id"]
    assert to_sigma(make(target="https://other.test/x", indicators=[], signals=[]))["id"] != a["id"]


def test_sigma_email_only():
    v = make(target="spam", kind=ArtifactKind.EMAIL, signals=[],
             indicators=[Indicator(type=IndicatorType.EMAIL, value="a@bad.test", role="sender")])
    r = to_sigma(v)
    assert r["logsource"] == {"category": "email"}
    assert r["detection"]["selection"] == {"sender_address": ["a@bad.test"]}
    assert validate_sigma(r) == []


def test_validate_sigma_catches_problems():
    assert validate_sigma({}) != []
    r = to_sigma(make())
    r["detection"]["condition"] = "nope"
    assert any("unknown selection" in p for p in validate_sigma(r))
    r2 = to_sigma(make())
    r2["id"] = "x"
    assert "id is not a UUID" in validate_sigma(r2)


# ------------------------------------------------------------------ Suricata
def test_suricata_rules_valid_and_complete():
    rules = to_suricata_rules(make())
    assert rules
    for r in rules:
        assert validate_suricata_rule(r) == [], r
        joined = "\n".join(rules)
    assert "tls.sni; dotprefix; content:\".login.paypa1-secure.test\"" in joined
    assert "http.host; dotprefix;" in joined
    assert "dns.query; dotprefix;" in joined
    assert "alert ip $HOME_NET any -> 198.51.100.7 any" in joined
    assert "classtype:social-engineering" in joined
    assert "mitre_technique_id T1566.002" in joined
    assert "mitre_tactic_name Initial_Access" in joined
    assert "PayPal" in joined and "T1566" in joined.split("msg:")[1]


def test_suricata_uri_rule_escapes_semicolon():
    rules = to_suricata_rules(make())
    uri = next(r for r in rules if "http.uri" in r)
    assert "|3B|" in uri                      # the ';' in the query is hex escaped
    assert 'content:"/signin/verify?id=7&x=a|3B|b"; startswith' in uri
    assert validate_suricata_rule(uri) == []


def test_suricata_sids_deterministic_unique_in_range():
    a, b = to_suricata_rules(make()), to_suricata_rules(make())
    assert a == b
    sids = [int(r.split("sid:")[1].split(";")[0]) for r in a]
    assert len(set(sids)) == len(sids)
    assert all(SID_BASE <= s < SID_BASE + SID_SPAN for s in sids)


def test_escape_content():
    assert escape_content('a;b"c\\d|e:f') == "a|3B|b|22|c|5C|d|7C|e|3A|f"
    assert escape_content("ü") == "|C3 BC|"
    assert escape_content("a.b-c/d") == "a.b-c/d"


def test_suricata_msg_injection_safe():
    v = make()
    v.brand.name = 'Evil"; sid:1; (x)'
    for r in to_suricata_rules(v):
        assert validate_suricata_rule(r) == []
        assert r.count("sid:") == 1


def test_validate_suricata_rejects_bad():
    assert validate_suricata_rule("garbage") == ["bad header"]
    good = to_suricata_rules(make())[0]
    assert validate_suricata_rule(good[:-1]) != []                     # missing ')'
    assert validate_suricata_rule(good.replace("sid:", "xsid:")) != []
    bad = 'alert http any any -> any any (msg:"x"; content:"a;b"; sid:1; rev:1; classtype:x;)'
    assert any("unescaped" in p or "malformed" in p for p in validate_suricata_rule(bad))


# ------------------------------------------------------------------ YARA
def test_yara_compiles_and_matches():
    src = to_yara(make())
    rule = yara_lib.compile(source=src)
    hit = "<a href='https://login.paypa1-secure.test/signin/verify?id=7&x=a;b'>".encode("utf-16-le")
    assert rule.match(data=hit)
    assert rule.match(data=b"see LOGIN.PAYPA1-SECURE.TEST today")
    assert rule.match(data=b"X " + KIT.encode())
    assert not rule.match(data=b"hello benign world paypal.com")
    assert 'mitre_attack = "T1557,T1566.002,T1656"' in src
    assert "score = 97" in src and 'author = "UniPhish"' in src


def test_yara_hash_clause():
    src = to_yara(make())
    assert 'import "hash"' in src
    assert yara_lib.compile(source=src).match(data=b"nothing here") == []


def test_yara_name_and_escape():
    n = rule_name("PayPal / Evil-é!", "deadbeefcafe")
    assert n.startswith("UniPhish_PayPal_Evil_") and n.endswith("deadbeef")
    assert rule_name("", "ab").isidentifier()
    assert escape_string('a"b\\c\né') == 'a\\"b\\\\c\\n\\xc3\\xa9'


def test_yara_hostile_strings_still_compile():
    v = make(signals=[Signal(id="kit.x", title="t", weight=7, category="kit", evidence={
        "strings": ['"; } rule pwn { condition: true', "line\nbreak\\x", "‮\u0000nul!"]})])
    src = to_yara(v)
    yara_lib.compile(source=src)
    assert "\nrule pwn" not in src


def test_yara_no_iocs():
    with pytest.raises(NoIndicatorsError):
        to_yara(make(level=Level.BENIGN, score=1))


# ------------------------------------------------------------------ ECS
def test_ecs_document():
    d = to_ecs(make())
    json.dumps(d)
    assert d["event"]["kind"] == "alert" and d["event"]["category"] == ["threat"]
    assert d["event"]["action"] == "block"
    ind = d["threat"]["indicator"]
    assert ind["type"] == "url"
    assert ind["url"]["full"].startswith("https://login.paypa1-secure.test/signin/verify")
    assert ind["url"]["domain"] == "login.paypa1-secure.test"
    assert d["url"]["domain"] == "login.paypa1-secure.test"
    assert d["url"]["scheme"] == "https" and d["url"]["path"] == "/signin/verify"
    assert "T1566.002" in d["threat"]["technique"]["id"]
    assert "Phishing: Spearphishing Link" in d["threat"]["technique"]["name"]
    assert "TA0001" in d["threat"]["tactic"]["id"]
    assert d["rule"]["name"] and d["risk"]["score"] == 97
    assert "login.paypa1-secure.test" in d["related"]["hosts"]
    assert d["related"]["ip"] == ["198.51.100.7"]
    assert d["related"]["hash"] == ["ab" * 32]
    assert "hxxps://" in d["message"] and "https://" not in d["message"]
    assert d["@timestamp"].endswith("Z")


def test_ecs_ip_and_hash_primary():
    v = make(target="x", kind=ArtifactKind.FILE, signals=[], indicators=[
        Indicator(type=IndicatorType.SHA256, value="cd" * 32, malicious=True)])
    d = to_ecs(v)
    assert d["threat"]["indicator"]["type"] == "file"
    assert d["threat"]["indicator"]["file"]["hash"]["sha256"] == "cd" * 32
    v2 = make(target="x", kind=ArtifactKind.TEXT, signals=[], indicators=[
        Indicator(type=IndicatorType.IPV6, value="2001:db8::1", malicious=True)])
    assert to_ecs(v2)["threat"]["indicator"]["type"] == "ipv6-addr"


def test_ndjson():
    out = to_ndjson([make(), make(target="https://b.test/", indicators=[], signals=[])])
    lines = out.splitlines()
    assert out.endswith("\n") and len(lines) == 2
    assert all(json.loads(x)["event"]["kind"] == "alert" for x in lines)
    assert to_ndjson([]) == ""
    assert len(to_ndjson(make()).splitlines()) == 1


def test_unicode_ecs_is_ascii_json():
    v = make(summary="café ‮")
    assert to_ndjson(v).isascii()
