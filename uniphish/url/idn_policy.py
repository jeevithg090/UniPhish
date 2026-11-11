"""Chromium-style IDN spoof assessment for a hostname.

A hostile IDN is only dangerous if a *browser* displays it in its spoofy Unicode form
rather than as neutral ``xn--`` punycode. Chromium (and, with variations, the other
browsers) therefore runs a published policy that decides, label by label, whether a
Unicode host is safe to show as-is. :func:`assess_host` reproduces the security-relevant
core of that policy on top of :mod:`uniphish.url.scripts` and
:mod:`uniphish.url.confusables`, and reports *why* a host is spoofy so the verdict is
explainable.

The rules implemented (see https://chromium.googlesource.com/chromium/src/+/HEAD/docs/idn.md
and UTS #39):

* reject dangerous cross-script mixing — anything not single-script or a Latin+CJK
  (Japanese / Korean / Han+Bopomofo) combination, which specifically catches
  Latin+Cyrillic and Latin+Greek homographs;
* reject whole-script-confusable labels (an all-Cyrillic/all-Greek label that reads as
  Latin), **except** under the script's own country-code TLDs (Cyrillic is expected under
  ``.ru``/``.рф``/``.bg``/… and Greek under ``.gr``);
* reject labels containing invisible characters, bidi overrides, dangerous delimiter
  look-alikes, combining marks on Latin bases, digit look-alikes, or Restricted
  (UTS #39 Identifier_Status) characters;
* reject a label whose confusable skeleton matches a caller-supplied set of top-domain
  skeletons (the "looks like google.com" check) — regardless of TLD.

The function never raises and never needs the network.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from uniphish.url import scripts
from uniphish.url.confusables import brand_skeleton, confusable_chars_in

# Country-code TLDs under which a whole-script label of the given script is expected and
# therefore shown as Unicode by browsers (Chromium's IDN allow-exceptions).
_CYRILLIC_CCTLDS = frozenset({
    "ru", "xn--p1ai",  # .рф
    "рф", "bg", "by", "kz", "kg", "mk", "mn", "rs", "su", "ua", "uz", "tj",
})
_GREEK_CCTLDS = frozenset({"gr", "cy"})

# Characters that imitate URL/label delimiters (. : / @ -) or are otherwise dangerous in
# a hostname. IDNA/UTS-46 already maps the full-width and ideographic stops onto real
# dots, so those never reach here; this set covers the residue a browser would reject.
_DANGEROUS_CHARS = frozenset(
    "ǀ"  # LATIN LETTER DENTAL CLICK (|)
    "̷"  # COMBINING SHORT SOLIDUS OVERLAY (/)
    "̸"  # COMBINING LONG SOLIDUS OVERLAY (/)
    "։"  # ARMENIAN FULL STOP (:)
    "׃"  # HEBREW PUNCTUATION SOF PASUQ (:)
    "؉"  # ARABIC-INDIC PER MILLE SIGN
    "؊"  # ARABIC-INDIC PER TEN THOUSAND SIGN
    "٪"  # ARABIC PERCENT SIGN
    "۔"  # ARABIC FULL STOP
    "܁"  # SYRIAC SUPRALINEAR FULL STOP
    "܂"  # SYRIAC SUBLINEAR FULL STOP
    "․"  # ONE DOT LEADER (.)
    "‧"  # HYPHENATION POINT (.)
    "‹"  # SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    "›"  # SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    "⁄"  # FRACTION SLASH (/)
    "∕"  # DIVISION SLASH (/)
    "꞉"  # MODIFIER LETTER COLON (:)
    "／"  # FULLWIDTH SOLIDUS (/)
)

_ASCII_DIGITS = frozenset("0123456789")

# Reason codes an assessment may report.
REASON_CODES = (
    "mixed_script",
    "whole_script_confusable",
    "dangerous_char",
    "invisible_char",
    "bidi_control",
    "combining_mark_on_latin",
    "digit_lookalike",
    "skeleton_matches_top_domain",
    "disallowed_identifier_char",
)

# Reasons that make a browser fall back to displaying punycode instead of Unicode.
_PUNYCODE_REASONS = frozenset(REASON_CODES)


@dataclass(frozen=True)
class IdnAssessment:
    """The result of assessing one hostname for IDN spoofing.

    Attributes:
        host: the normalised Unicode host that was assessed.
        labels: its dot-separated labels.
        display_as_unicode: what a browser would show — ``True`` for the Unicode form,
            ``False`` if it would fall back to ``xn--`` punycode because the host is spoofy.
        reasons: sorted spoof reason codes (see :data:`REASON_CODES`); empty when clean.
        restriction_level: the UTS #39 restriction level of the host.
        scripts: sorted short script codes present in the host.
        skeleton: the confusable brand skeleton of the host (for brand matching / logging).
    """

    host: str
    labels: tuple[str, ...]
    display_as_unicode: bool
    reasons: tuple[str, ...]
    restriction_level: scripts.RestrictionLevel
    scripts: tuple[str, ...]
    skeleton: str

    @property
    def is_spoof(self) -> bool:
        """True if the host carries any spoof reason (would be shown as punycode)."""
        return bool(self.reasons)


def _has_digit_lookalike(label: str) -> bool:
    """A non-ASCII character that imitates an ASCII digit (letter-as-digit spoof)."""
    return any(len(looks_like) == 1 and looks_like in _ASCII_DIGITS
               for _, _, looks_like in confusable_chars_in(label))


def _assess_label(label: str, tld: str | None, reasons: set[str]) -> None:
    """Add spoof reason codes for a single U-label to ``reasons`` (in place)."""
    if not label:
        return
    if scripts.find_invisible(label):
        reasons.add("invisible_char")
    if scripts.find_bidi_controls(label):
        reasons.add("bidi_control")
    if any(ch in _DANGEROUS_CHARS for ch in label):
        reasons.add("dangerous_char")
    for ch in label:
        if ord(ch) >= 0x80 and scripts.identifier_status(ch) == "restricted":
            reasons.add("disallowed_identifier_char")
            break

    if label.isascii():
        return  # the remaining checks concern the Unicode rendering of an IDN label

    if scripts.has_combining_on_latin(label):
        reasons.add("combining_mark_on_latin")
    if _has_digit_lookalike(label):
        reasons.add("digit_lookalike")

    if scripts.is_mixed_script(label):
        # Chromium allows single-script and Latin+CJK (Highly Restrictive) mixtures only.
        if scripts.restriction_level(label) is not scripts.RestrictionLevel.HIGHLY_RESTRICTIVE:
            reasons.add("mixed_script")
    elif scripts.whole_script_confusable(label):
        resolved = scripts.resolved_script_set(label)
        script = next(iter(resolved)) if resolved else ""
        if script == "Cyrl" and tld in _CYRILLIC_CCTLDS:
            return
        if script == "Grek" and tld in _GREEK_CCTLDS:
            return
        reasons.add("whole_script_confusable")


def assess_host(host_unicode: str, *, tld: str | None = None,
                top_domain_skeletons: Iterable[str] | None = None) -> IdnAssessment:
    """Assess ``host_unicode`` for IDN spoofing and return an :class:`IdnAssessment`.

    Args:
        host_unicode: the Unicode (U-label) host, e.g. ``"pаypal.com"`` (already
            IDNA-decoded, as produced by :func:`uniphish.url.parse.parse_url`).
        tld: the effective TLD for the whole-script ccTLD exceptions; defaults to the
            host's last label. Pass the punycode or Unicode form of an IDN ccTLD.
        top_domain_skeletons: optional set of brand skeletons of popular domains
            (e.g. ``{"google", "paypal", "microsoft"}``); a label whose skeleton matches
            one but which is not that domain is flagged ``skeleton_matches_top_domain``.
    """
    host = (host_unicode or "").strip().rstrip(".").lower()
    labels = tuple(lbl for lbl in host.split(".") if lbl) if host else ()
    if tld is None and labels:
        tld = labels[-1]

    top_skeletons: frozenset[str] = frozenset(top_domain_skeletons or ())
    reasons: set[str] = set()
    present_scripts: set[str] = set()
    unicode_present = False

    for i, label in enumerate(labels):
        if not label.isascii():
            unicode_present = True
        for ch in label:
            sc = scripts.script_of(ch)
            if sc not in (scripts.COMMON, scripts.INHERITED, scripts.UNKNOWN):
                present_scripts.add(sc)
        _assess_label(label, tld, reasons)

        # "Looks like a top domain" check: compare each non-suffix label's skeleton
        # (skip the public-suffix label itself when the host has more than one label).
        if top_skeletons and (len(labels) == 1 or i < len(labels) - 1):
            ls = brand_skeleton(label)
            if ls in top_skeletons and ls != label.lower():
                reasons.add("skeleton_matches_top_domain")

    restriction = scripts.restriction_level(host.replace(".", ""))
    assessment_skeleton = brand_skeleton(host)

    display_as_unicode = True if not unicode_present else not (reasons & _PUNYCODE_REASONS)

    return IdnAssessment(
        host=host,
        labels=labels,
        display_as_unicode=display_as_unicode,
        reasons=tuple(sorted(reasons)),
        restriction_level=restriction,
        scripts=tuple(sorted(present_scripts)),
        skeleton=assessment_skeleton,
    )


def host_skeleton(host_unicode: str) -> str:
    """Confusable brand skeleton of a whole host (convenience for brand matching)."""
    return brand_skeleton((host_unicode or "").strip().rstrip(".").lower())


def confusable_report(host_unicode: str) -> list[tuple[int, str, str]]:
    """Per-character confusable report for a host (index, char, ASCII look-alike)."""
    return confusable_chars_in((host_unicode or "").strip().rstrip("."))
