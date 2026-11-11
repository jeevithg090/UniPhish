# Spec: Unicode security core (homoglyph defense)
OWN: uniphish/url/confusables.py, uniphish/url/scripts.py, uniphish/url/idn_policy.py,
uniphish/assets/unicode/ (generated gzip-JSON data), scripts/gen_unicode_data.py,
tests/url/test_unicode.py.

PURPOSE: detect when a domain/label uses Unicode look-alike characters to imitate a
trusted name — the core multilingual capability of UniPhish. Based on Unicode UTS #39
(security mechanisms) and Chromium's published IDN display policy.

BUILD-TIME DATA (download with curl, convert to compact gzip-JSON via the generator
script, commit the generated asset, record the Unicode version in a VERSION file):
- https://www.unicode.org/Public/security/latest/confusables.txt
- https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
- https://www.unicode.org/Public/UCD/latest/ucd/Scripts.txt
- https://www.unicode.org/Public/UCD/latest/ucd/ScriptExtensions.txt
Keep assets small (range-compress codepoint tables). Load lazily via uniphish.assets.

confusables.py:
- skeleton(s) per UTS#39 (NFD -> confusable prototype mapping -> NFD).
- are_confusable(a, b) -> bool.
- ascii_fold(s) -> str: skeleton + extra squatting folds (leet 0->o 1->l 3->e 4->a
  5->s 7->t 8->b, multi-char rn->m vv->w cl->d, '@'->a). brand_skeleton(s) =
  lowercase(ascii_fold(...)) — the canonical form for brand matching.
- lookalikes_of(ascii_char) -> list[str] (for defensive permutation/testing).
- confusable_chars_in(s) -> list[(index, char, looks_like_ascii)].

scripts.py:
- script_of(ch), script_extensions(ch), resolved_script_set(s) with UTS#39 augmented
  sets (Jpan/Kore/Hanb so legitimate Japanese/Korean mixes count as single-script),
  is_mixed_script(s), restriction_level(s) -> ASCII_ONLY | SINGLE_SCRIPT |
  HIGHLY_RESTRICTIVE | MODERATELY_RESTRICTIVE | MINIMALLY_RESTRICTIVE | UNRESTRICTED.
- identifier_status(ch) (allowed/restricted).
- find_invisible(s): zero-width spaces/joiners, variation selectors, soft hyphen,
  word joiner, Hangul fillers -> list of (index, codepoint, name).
- find_bidi_controls(s): RLO/LRO/RLI/PDI etc. ('Trojan Source'/RTLO reordering).
- decode_tag_chars(s) -> str|None: Unicode Tags block U+E0000..E007F ('ASCII
  smuggling' used to hide instructions) -> the decoded hidden ASCII, if present.
- whole_script_confusable(label) -> bool: e.g. an all-Cyrillic label that renders as
  Latin.

idn_policy.py:
- assess_host(host_unicode, *, tld=None, top_domain_skeletons=None) -> IdnAssessment
  dataclass(host, labels, display_as_unicode: bool (what Chromium would show as
  Unicode vs punycode), reasons: list[str] codes [mixed_script, whole_script_confusable,
  dangerous_char, invisible_char, bidi_control, combining_mark_on_latin, digit_lookalike,
  skeleton_matches_top_domain, disallowed_identifier_char], restriction_level, scripts,
  skeleton). Implement the main rules of Chromium's IDN policy: highly-restrictive
  mixing, Latin+Cyrillic/Greek mixing, whole-script-confusable labels with ccTLD
  allow-exceptions (Cyrillic allowed under .ru/.рф/.bg/.by/.kz/.mk/.mn/.rs/.su/.ua/.uz),
  dangerous-character set, invisible chars, combining marks on Latin, skeleton match
  against a caller-supplied set of top-domain skeletons.

TESTS: real homoglyph cases that MUST flag (Cyrillic 'а' in apple, xn--80ak6aa92e.com,
Greek omicron, Armenian օ, whole-Cyrillic paypal, Latin+Cyrillic mix, RTLO, zero-width
joiner, tag-smuggled text round-trip) AND legitimate IDNs that must NOT flag
(bücher.de, münchen.de, Han .cn, Hangul .kr, kana+kanji .jp, Greek-only .gr, Cyrillic
.рф). Keep fast.
