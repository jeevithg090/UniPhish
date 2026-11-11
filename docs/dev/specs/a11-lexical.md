# Spec: URL lexical features + attack-technique classification
OWN: uniphish/url/lexical.py, uniphish/url/techniques.py, uniphish/url/brands.py (new
brand-impersonation module replacing the legacy top-level one), tests/url/test_lexical.py,
tests/url/test_techniques.py, tests/url/test_brands.py.

Depends on: uniphish.url.parse (done), uniphish.url.confusables + scripts + idn_policy
(a1), uniphish.url.brandkb (a2), uniphish.assets.lists (a3). Import them normally; if a
symbol is missing at runtime, fail soft.

lexical.py: features(parsed: ParsedURL) -> LexicalFeatures dataclass of explainable
structural measures: url_len, host_len, path_len, query_len, num_dots, num_hyphens,
num_subdomains, num_digits_in_host, digit_ratio_host, has_at, has_port, non_std_port,
is_ip, ip_obfuscated, punycode, tld, tld_risk (via lists), is_shortener, is_dyndns,
lots (LotsEntry|None), open_redirect (dest|None), sensitive_words_in_host/path (lure
hits via lists.find_lures), brand_keyword_in_subdomain/path/sld, many_subdomains,
deep_path, encoded_chars (%xx count), double_encoding, data_or_js_scheme, raw_entropy of
host, suspicious_file_ext_in_path (.exe/.scr/.zip/.apk/.hta/.js), has_atsign_redirect,
mixed_script_host, confusable_host, vowelless/random-looking label heuristic. Pure,
fast, deterministic.

brands.py: brand_impersonation(url_or_parsed) -> BrandMatch|None (uses parse + brandkb +
confusables): decide official (exact official/login/cdn host -> BrandMatch(official=True))
vs impersonation via technique:
- homoglyph (non-ASCII host whose brand_skeleton == a brand skeleton),
- idn (punycode host decoding to a brand look-alike),
- typosquat (edit distance 1-2 on the sld skeleton vs a brand, length-aware),
- combosquat (brand keyword inside the sld with extra tokens, e.g. brand-secure),
- subdomain (brand as a non-registrable label; real domain differs),
- path (brand keyword in path of an unrelated domain),
- bitsquat (single-bit-flip of a brand domain, optional),
- content handled elsewhere. Return brand, name, technique, confidence (calibrated),
legit_domains, evidence, official. Respect ambiguous brands (need stronger evidence).
Must NOT flag a brand's own official/login/cdn/user-content hosts as impersonation.

techniques.py: classify(url) -> TechniqueResult(techniques: list[str] from a fixed
taxonomy [homoglyph, idn_homograph, typosquat, combosquat, subdomain_stuffing,
path_deception, ip_host, ip_obfuscation, url_shortener, open_redirect_abuse,
lots_hosting, dynamic_dns, at_redirect, punycode, suspicious_tld, excessive_subdomains,
data_uri, credential_path], primary, target_brand, descriptions, mitre: list[str] via
uniphish.core.mitre). Map each technique to ATT&CK/ATLAS ids.

TESTS: feature correctness across crafted URLs; brand_impersonation homoglyph/typo/
combosquat/subdomain/official cases incl. must-not-flag official & user-content hosts;
technique classification + MITRE mapping; ambiguous-brand restraint.
