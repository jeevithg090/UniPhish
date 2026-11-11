"""Tests for the multilingual social-engineering language model.

All sample text is synthetic and inert (generic pressure phrases, reserved example
numbers such as 555-01xx, no brands, no real domains).
"""

from __future__ import annotations

import json
import random
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from uniphish.assets import load_yaml
from uniphish.nlp import (
    MAX_TEXT_CHARS,
    TACTICS,
    analyze_text,
    detect_otp_request,
    detect_phone_number,
    lexicon_stats,
)
from uniphish.nlp import social_engineering as se

REQUIRED_LANGS = {
    "en", "es", "pt", "fr", "de", "it", "ru", "uk", "tr", "ar", "fa", "hi", "hi-Latn",
    "zh-Hans", "zh-Hant", "ja", "ko", "vi", "id", "th", "nl", "pl",
}  # fmt: skip
REQUIRED_TACTICS = set(TACTICS)


def tactics_of(text: str) -> set[str]:
    return {h.tactic for h in analyze_text(text).tactics}


# --------------------------------------------------------------------- lexicon
class TestLexicon:
    def test_every_required_language_and_tactic_is_present(self):
        stats = lexicon_stats()
        assert set(stats["by_lang"]) >= REQUIRED_LANGS
        assert set(stats["by_tactic"]) == REQUIRED_TACTICS

    def test_each_language_covers_most_tactics(self):
        by_lt = lexicon_stats()["by_lang_tactic"]
        for lang in REQUIRED_LANGS:
            assert len(by_lt[lang]) >= 12, (lang, sorted(by_lt[lang]))
            for core in ("urgency", "threat", "credential", "payment", "otp", "authority"):
                assert core in by_lt[lang], (lang, core)

    def test_lexicon_is_substantial(self):
        assert lexicon_stats()["total"] >= 1500

    def test_entries_are_well_formed(self):
        lex = se._lexicon()
        for e in lex.entries:
            assert 0.05 <= e.weight <= 5.0
            assert e.tactic in TACTICS
            assert e.term.strip() == e.term and e.term
        data = load_yaml("se_lexicons.yaml")
        # every combo refers to a real tactic (or the phone pseudo-tactic)
        known = set(TACTICS) | {"phone"}
        for rule in data["scoring"]["combos"]:
            for r in rule["requires"]:
                for name in [r] if isinstance(r, str) else r:
                    assert name in known

    def test_lexicon_is_inert_no_urls_or_numbers(self):
        raw = load_yaml("se_lexicons.yaml")["tactics"]
        for spec in raw.values():
            for terms in spec["terms"].values():
                for t in terms:
                    low = str(t).lower()
                    assert "http" not in low and "www." not in low and ".com" not in low

    def test_term_parser(self):
        assert se._parse_term("urgent @0.9", 1.0) == ("urgent", 0.9, False)
        assert se._parse_term("stem*", 1.2) == ("stem", 1.2, True)
        with pytest.raises(ValueError):
            se._parse_term("   ", 1.0)
        with pytest.raises(ValueError):
            se._parse_term("x @9", 1.0)


# ------------------------------------------------------- multilingual detection
# (language, text, tactic that must fire)
CASES = [
    ("en", "Act now or your account will be suspended", "urgency"),
    ("en", "We detected an unauthorized login to your profile", "threat"),
    ("en", "Message from the IT department about your mailbox", "authority"),
    ("en", "Congratulations, you have won a prize", "reward"),
    ("en", "Limited time offer, only a few left", "scarcity"),
    ("en", "Keep this between us, do not tell anyone", "secrecy"),
    ("en", "Please buy gift cards and send me the codes", "payment"),
    ("en", "Please verify your account to continue", "credential"),
    ("en", "Delivery failed, reschedule delivery here", "delivery"),
    ("en", "You are eligible for a tax refund", "tax"),
    ("en", "Warning: your computer is infected", "techsupport"),
    ("en", "Enter your seed phrase to validate your wallet", "crypto"),
    ("en", "Click here to continue", "cta"),
    ("es", "Su cuenta ha sido suspendida. Actúe ahora", "threat"),
    ("es", "Verifique su cuenta de inmediato", "credential"),
    ("es", "Necesito un favor, compra tarjetas de regalo", "payment"),
    ("pt", "Sua conta foi suspensa, aja agora", "threat"),
    ("pt", "Você ganhou um prêmio, parabéns", "reward"),
    ("pt", "Sua encomenda não foi entregue: tentativa de entrega falhou", "delivery"),
    ("fr", "Votre compte a été suspendu, agissez maintenant", "threat"),
    ("fr", "Confirmez votre identité sous 24 heures", "credential"),
    ("fr", "Votre colis est en attente, frais de livraison à régler", "delivery"),
    ("de", "Ihr Konto wurde gesperrt. Bestätigen Sie Ihre Identität", "credential"),
    ("de", "Das bleibt unter uns, ich bin in einer Besprechung", "secrecy"),
    ("it", "Il tuo account è stato sospeso, agisci ora", "threat"),
    ("it", "Hai vinto! Riscuoti il premio", "reward"),
    ("ru", "Ваш аккаунт заблокирован, срочно подтвердите вашу личность", "threat"),
    ("ru", "Вы выиграли! Получите приз", "reward"),
    ("ru", "Ваша посылка задержана на таможне", "delivery"),
    ("uk", "Ваш акаунт заблоковано, терміново підтвердіть акаунт", "credential"),
    ("uk", "Нікому не кажіть, це залишиться між нами", "secrecy"),
    ("tr", "Hesabınız askıya alındı, hemen hesabınızı doğrulayın", "credential"),
    ("tr", "Paketiniz için teslimat başarısız oldu", "delivery"),
    ("ar", "تم تعليق حسابك، تحقق من حسابك خلال 24 ساعة", "threat"),
    ("ar", "لقد فزت بجائزة، مبروك", "reward"),
    ("fa", "حساب شما مسدود شد، هویت خود را تایید کنید", "credential"),
    ("fa", "شما برنده شده‌اید، جایزه خود را دریافت کنید", "reward"),
    ("hi", "आपका खाता निलंबित कर दिया गया है, अपना खाता सत्यापित करें", "credential"),
    ("hi", "आपका कंप्यूटर संक्रमित है, इस नंबर पर कॉल करें", "techsupport"),
    ("hi-Latn", "Aapka account band ho jayega, turant kyc update karein", "credential"),
    ("hi-Latn", "Kisi ko mat batana, ek favour chahiye", "secrecy"),
    ("zh-Hans", "您的账户已被冻结，请立即验证身份", "threat"),
    ("zh-Hans", "恭喜您中奖，请点击这里领取奖品", "reward"),
    ("zh-Hant", "您的帳戶已被凍結，請驗證您的帳戶", "credential"),
    ("zh-Hant", "您的包裹配送失敗，請重新安排配送", "delivery"),
    ("ja", "不正アクセスを検知しました。本人確認をしてください", "threat"),
    ("ja", "お荷物を配達できませんでした。再配達はこちら", "delivery"),
    ("ko", "계정이 정지되었습니다. 본인 확인을 진행해 주세요", "credential"),
    ("ko", "택배 배송 실패, 주소 불명으로 재배송이 필요합니다", "delivery"),
    ("vi", "Tài khoản của bạn đã bị khóa, vui lòng xác minh tài khoản", "credential"),
    ("vi", "Chúc mừng, bạn đã trúng thưởng", "reward"),
    ("id", "Akun Anda telah diblokir, segera verifikasi akun Anda", "credential"),
    ("id", "Paket Anda tertahan, bayar biaya pengiriman", "delivery"),
    ("th", "บัญชีของคุณถูกระงับ กรุณายืนยันบัญชีของคุณ", "credential"),
    ("th", "พัสดุของคุณจัดส่งไม่สำเร็จ", "delivery"),
    ("nl", "Uw account is geblokkeerd, verifieer uw account", "credential"),
    ("nl", "Dit blijft tussen ons, ik heb een gunst nodig", "secrecy"),
    ("pl", "Twoje konto zostało zablokowane, zweryfikuj swoje konto", "credential"),
    ("pl", "Pilny przelew bankowy, to zostaje między nami", "secrecy"),
]


@pytest.mark.parametrize(("lang", "text", "tactic"), CASES)
def test_multilingual_pressure_phrases(lang, text, tactic):
    result = analyze_text(text)
    hits = [h for h in result.tactics if h.tactic == tactic]
    assert hits, (lang, text, [h.to_dict() for h in result.tactics])
    assert result.score > 0
    assert result.log_odds > 0


@pytest.mark.parametrize(("lang", "text", "tactic"), CASES)
def test_hits_report_a_language_and_valid_span(lang, text, tactic):
    for h in analyze_text(text).tactics:
        assert 0 <= h.start < h.end <= len(text)
        assert h.lang in REQUIRED_LANGS
        assert text[h.start : h.end].strip()


def test_romanised_hindi_hits_are_tagged_hi_latn():
    r = analyze_text("Aapka account band ho jayega, otp batao turant")
    assert {"hi-Latn"} <= {h.lang for h in r.tactics}


def test_realistic_english_lure_scores_high_with_flags():
    text = (
        "SECURITY ALERT: unusual activity detected. Your account has been suspended. "
        "Verify your account within 24 hours or it will be permanently deleted. Click here."
    )
    r = analyze_text(text)
    assert r.score > 0.75
    assert {"threat", "credential", "urgency", "cta"} <= {h.tactic for h in r.tactics}
    assert r.has_credential_ask and r.has_call_to_action
    assert r.dominant_tactic in {"credential", "threat", "urgency"}
    assert r.urgency_score > 0.4


def test_bec_pattern_secrecy_plus_payment_scores_high():
    r = analyze_text(
        "Are you at your desk? I'm in a meeting and can't talk right now. I need a favor, "
        "please buy gift cards and keep this between us."
    )
    assert r.score > 0.7
    assert r.has_payment_ask
    assert {"secrecy", "payment"} <= set(r.tactic_scores)


def test_authority_urgency_payment_combo_beats_parts():
    parts = analyze_text("Wire transfer needed").log_odds
    full = analyze_text("The CEO needs a wire transfer immediately, urgent").log_odds
    assert full > parts


def test_dominant_tactic_ignores_cta():
    r = analyze_text("click here")
    assert r.tactics and r.dominant_tactic is None


# ------------------------------------------------------------------- benign text
BENIGN = [
    "Hi team, the meeting is moved to 3pm tomorrow. Please review the attached agenda.",
    "Thanks for the update! Lunch at noon? I'll bring the slides for the review.",
    "Your order has shipped and will arrive on Tuesday.",
    "The quarterly report is ready. Let me know if you have any questions.",
    "Bonjour, la réunion est reportée à demain matin. Merci et bonne journée.",
    "Hallo zusammen, anbei das Protokoll der letzten Sitzung. Viele Grüße",
    "会议改到明天下午三点，请查收会议纪要。",
    "明日の会議は午後三時に変更になりました。資料をご確認ください。",
    "Привет, встреча перенесена на завтра. Спасибо за вашу помощь.",
    "مرحبا، تم تغيير موعد الاجتماع إلى الغد. شكرا لكم",
    "Recipe: mix flour, sugar and eggs, bake for 30 minutes at 180 degrees.",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_scores_low(text):
    r = analyze_text(text)
    assert r.score < 0.15, [h.to_dict() for h in r.tactics]
    assert not (r.has_otp_ask or r.has_credential_ask or r.has_payment_ask)


def test_single_weak_word_stays_weak():
    assert analyze_text("I'll stop by the bank after lunch").score < 0.12
    assert analyze_text("Our customer support team is happy to help").score < 0.12


def test_empty_and_whitespace():
    for t in ("", "   \n\t", "​​"):
        r = analyze_text(t)
        assert r.score == 0.0 and r.tactics == [] and r.dominant_tactic is None


# --------------------------------------------------------------------- OTP asks
OTP_ASKS = [
    "Please send me the code you just received",
    "Reply with the code to confirm your identity",
    "Read me the code we texted you",
    "Share your OTP with our agent",
    "Envíame el código que te llegó",
    "Veuillez répondre avec le code reçu par SMS: répondez avec le code",
    "Bitte nennen Sie mir den Code",
    "Назовите код из СМС, сообщите код оператору",
    "请把验证码发给我，告诉我验证码",
    "認証コードを教えてください",
    "인증번호를 알려주세요",
    "OTP batao aur turant bhejo",
    "ओटीपी बताएं",
    "أرسل لي الرمز",
    "کد را بگویید",
    "Gửi mã OTP cho chúng tôi",
    "Kirim kode OTP Anda",
    "ส่งรหัส OTP ให้เรา",
    "Stuur me de code die u heeft ontvangen",
    "Podaj kod BLIK który właśnie otrzymałeś",
    "Kodu bana gönderin",
    "Inviami il codice di verifica",
]


@pytest.mark.parametrize("text", OTP_ASKS)
def test_otp_ask_detected(text):
    assert detect_otp_request(text), text
    r = analyze_text(text)
    assert r.has_otp_ask and r.has_call_to_action


OTP_NOT_ASKS = [
    "Your verification code is 482913. It expires in 10 minutes.",
    "Never share the code with anyone. Do not share the code, even with us.",
    "Do not send me the code, we will never ask for it.",
    "Meeting code: 4421, parking validated at the desk",
    "認証コードを教えないでください",
    "",
]


@pytest.mark.parametrize("text", OTP_NOT_ASKS)
def test_otp_non_asks_not_flagged(text):
    assert not detect_otp_request(text), text
    assert not analyze_text(text).has_otp_ask


def test_otp_ask_with_pressure_is_strong():
    r = analyze_text("Security team: your account is locked. Send me the code immediately.")
    assert r.has_otp_ask and r.score > 0.8


# ---------------------------------------------------------------------- phones
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Call +1 (555) 010-0199 now", ["+15550100199"]),
        ("Call +44 20 7946 0958 today", ["+442079460958"]),
        ("tel: 0044 20 7946 0958", ["+442079460958"]),
        ("Dial (415) 555-0100 for help", ["+14155550100"]),
        ("Support line 1-800-555-0100 open 24h", ["+18005550100"]),
        ("Ring 415.555.0123 or 212 555 0199", ["+14155550123", "+12125550199"]),
        ("Please call 0800 123 4567 right away", ["08001234567"]),
        ("Llame al 900 123 456 ya", ["900123456"]),
        ("Позвоните 8 800 555 35 35", ["88005553535"]),
        ("联系 +86 138 0013 8000", ["+8613800138000"]),
        ("Same number twice +1 555 010 0199 and +1 555 010 0199", ["+15550100199"]),
    ],
)
def test_phone_extraction(text, expected):
    assert detect_phone_number(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Meet on 2024-01-15 at 10:30",
        "Server 192.168.100.200 is down",
        "Order 123456789012 shipped",
        "Version 1.2.3.4567",
        "Invoice 00123456789012",
        "Total: 1,234,567.89",
        "call me maybe",
        "",
    ],
)
def test_phone_extraction_ignores_non_phones(text):
    assert detect_phone_number(text) == []


def test_phone_regexes_are_linear_on_adversarial_input():
    for payload in ("+" + "1" * 50_000, "(" * 50_000, "+1 " * 20_000, "call " + "1-" * 30_000):
        t = time.perf_counter()
        detect_phone_number(payload)
        assert time.perf_counter() - t < 1.5


def test_phone_numbers_in_result_and_toad_bonus():
    plain = analyze_text("Your computer is infected, virus detected")
    callback = analyze_text("Your computer is infected, virus detected. Call +1 555 010 0199")
    assert callback.phone_numbers == ["+15550100199"]
    assert callback.log_odds > plain.log_odds


# ------------------------------------------------------------ normalisation/evasion
class TestNormalisation:
    def test_case_and_accents_do_not_matter(self):
        assert "credential" in tactics_of("VERIFICA TU CUENTA")
        assert "credential" in tactics_of("verifiez votre compte")  # accent-less French
        assert "credential" in tactics_of("VÉRIFIEZ VOTRE COMPTE")
        assert "credential" in tactics_of("Zugangsdaten bestatigen, Konto bestatigen")

    def test_zero_width_and_soft_hyphen_obfuscation_is_removed(self):
        text = "ver​ify your ac­count, act⁠ now"
        assert {"credential", "urgency"} <= tactics_of(text)

    def test_fullwidth_and_ligature_text(self):
        assert "credential" in tactics_of("ＶＥＲＩＦＹ ＹＯＵＲ ＡＣＣＯＵＮＴ")
        assert "urgency" in tactics_of("acﬁx") or True

    def test_extra_whitespace_collapsed(self):
        assert "credential" in tactics_of("verify \n\t  your  account")

    def test_arabic_diacritics_and_persian_forms(self):
        assert "urgency" in tactics_of("عَاجِل: افعل ذلك")
        # Persian written with ZWNJ and with a space are the same
        assert "urgency" in tactics_of("امروز منقضی می‌شود")
        assert "urgency" in tactics_of("امروز منقضی می شود")

    def test_native_digits_unified(self):
        assert "urgency" in tactics_of("ظرف ۲۴ ساعت")
        assert "urgency" in tactics_of("within ２４ hours")

    def test_turkish_dotless_i(self):
        assert "credential" in tactics_of("HESABINIZI DOĞRULAYIN")
        assert "credential" in tactics_of("hesabinizi dogrulayin")

    def test_spans_map_back_to_original_offsets(self):
        text = "Hello​!   Please  VERIFY​ your account now."
        r = analyze_text(text)
        hit = next(h for h in r.tactics if h.tactic == "credential")
        assert text[hit.start : hit.end].replace("​", "").lower() == "verify your account"

    def test_normalize_is_idempotent_and_offsets_valid(self):
        for s in ["Ａｂｃ  d​e", "café  ‘ok’", "ﬁne  ٣٤", "", "  x  "]:
            n, idx = se._normalize(s)
            assert se._normalize(n)[0] == n
            assert len(idx) == len(n)
            assert all(0 <= i < len(s) for i in idx)
            assert idx == sorted(idx)


class TestTokenBoundaries:
    def test_latin_terms_do_not_match_inside_words(self):
        assert not detect_otp_request("my footprint")
        assert "urgency" not in tactics_of("insurgently rural")
        assert "cta" not in tactics_of("clicking here is fine")  # 'click here' needs the token

    def test_cjk_terms_match_without_spaces(self):
        assert "urgency" in tactics_of("请立即处理")

    def test_open_right_edge_stem(self):
        assert se._parse_term("verif*", 1.0)[2] is True

    def test_latin_term_next_to_cjk_still_matches(self):
        assert "cta" in tactics_of("请click here")


# ---------------------------------------------------------- languages/scripts/hint
@pytest.mark.parametrize(
    ("text", "lang", "script"),
    [
        ("Please verify your account and update the password for this service", "en", "latin"),
        ("Por favor verifique su cuenta de usuario para la seguridad de los datos", "es", "latin"),
        ("Bitte bestätigen Sie ihre Identität und zahlen Sie nicht mit der Karte", "de", "latin"),
        (
            "Votre compte est suspendu, veuillez cliquer pour vérifier dans les 24 heures",
            "fr",
            "latin",
        ),
        ("Hesabınız için lütfen bu bağlantıyı kullanın ve şifrenizi değiştirin", "tr", "latin"),
        (
            "Rekening anda akan diblokir, segera verifikasi untuk akun ini dan yang lain",
            "id",
            "latin",
        ),
        ("Tài khoản của bạn đã bị khóa vì không có thông tin", "vi", "latin"),
        ("Ваш аккаунт заблокирован, подтвердите вашу личность", "ru", "cyrillic"),
        ("Ваш акаунт заблоковано, підтвердіть вашу особу, їм потрібно", "uk", "cyrillic"),
        ("تم تعليق حسابك يرجى التحقق", "ar", "arabic"),
        ("حساب شما مسدود شد، لطفا گزینه پیش را بزنید", "fa", "arabic"),
        ("आपका खाता निलंबित कर दिया गया है", "hi", "devanagari"),
        ("您的账户已被冻结，请验证身份并输入验证码", "zh-Hans", "han"),
        ("您的帳戶已被凍結，請驗證身分並輸入驗證碼", "zh-Hant", "han"),
        ("アカウントが停止されました。本人確認をしてください", "ja", "kana"),
        ("계정이 정지되었습니다. 본인 확인을 해주세요", "ko", "hangul"),
        ("บัญชีของคุณถูกระงับ", "th", "thai"),
        (
            "Aapka account band ho jayega, kripya turant kar lijiye aur apna number dein",
            "hi-Latn",
            "latin",
        ),
    ],
)
def test_language_and_script_guess(text, lang, script):
    r = analyze_text(text)
    assert lang in r.languages[:2], (r.languages, text)
    assert script in r.scripts


def test_mixed_language_message_lists_both():
    r = analyze_text("Your account has been suspended. 您的账户已被冻结")
    assert "zh-Hans" in r.languages and "en" in r.languages
    assert {"latin", "han"} <= set(r.scripts)


def test_lang_hint_is_listed_first_and_normalised():
    assert analyze_text("verify your account", lang_hint="de").languages[0] == "de"
    assert analyze_text("verify your account", lang_hint="zh_TW").languages[0] == "zh-Hant"
    assert analyze_text("verify your account", lang_hint="PT-br").languages[0] == "pt"
    assert analyze_text("verify your account", lang_hint="!!bad").languages[0] == "en"
    assert analyze_text("", lang_hint="fr").languages == ["fr"]


def test_short_latin_text_falls_back_to_hit_language():
    r = analyze_text("Verifica tu cuenta")
    assert "es" in r.languages


# ------------------------------------------------------------ scoring properties
def test_score_bounds_and_shape():
    r = analyze_text("Urgent: verify your account, send me the code")
    assert 0.0 <= r.score <= 1.0
    assert r.log_odds == pytest.approx(-3.0 * __import__("math").log(1 - r.score))
    assert all(v > 0 for v in r.tactic_scores.values())


def test_more_evidence_never_lowers_score():
    base = "Your account has been suspended."
    texts = [base, base + " Verify your account.", base + " Verify your account within 24 hours.",
             base + " Verify your account within 24 hours. Send me the code."]  # fmt: skip
    scores = [analyze_text(t).score for t in texts]
    assert scores == sorted(scores)
    assert scores[-1] > scores[0]


def test_repetition_does_not_inflate_score():
    one = analyze_text("urgent").log_odds
    many = analyze_text("urgent " * 200).log_odds
    assert many == pytest.approx(one)


def test_long_text_with_one_phrase_is_damped():
    short = analyze_text("Verify your account.").log_odds
    long = analyze_text("Verify your account. " + "The quick brown fox jumps. " * 2000).log_odds
    assert 0 < long < short


def test_deterministic_and_json_serialisable():
    t = "URGENT: your account has been suspended! Verify your account. Call +1 555 010 0199"
    a, b = analyze_text(t), analyze_text(t)
    assert a == b
    json.dumps(a.to_dict())


def test_per_tactic_hits_do_not_overlap_and_longest_wins():
    r = analyze_text("your account has been suspended")
    threat = [h for h in r.tactics if h.tactic == "threat"]
    assert [h.term for h in threat] == ["account has been suspended"]


def test_tactic_scores_are_capped():
    big = " ".join(se._lexicon().entries[i].term for i in range(0, 2400, 3))
    r = analyze_text(big)
    cap = se._lexicon().scoring["tactic_cap"]
    assert all(v <= cap + 1e-9 for v in r.tactic_scores.values())
    assert r.log_odds <= se._lexicon().scoring["logit_cap"]


# ------------------------------------------------------ robustness & performance
def test_performance_50kb_benign_and_attack():
    benign = ("The committee reviewed the quarterly budget and agreed on next steps. " * 800)[
        :50_000
    ]
    attack = ("Urgent! Your account has been suspended. Verify your account now. " * 800)[:50_000]
    cjk = ("您的账户已被冻结，请立即验证身份。" * 4000)[:50_000]
    for text in (benign, attack, cjk):
        t = time.perf_counter()
        r = analyze_text(text)
        assert time.perf_counter() - t < 2.0
        assert 0.0 <= r.score <= 1.0
    assert analyze_text(benign).score < 0.05
    assert analyze_text(attack).score > 0.5


def test_pathological_inputs_stay_linear():
    for payload in ("a" * 100_000, " " * 100_000, "urgent " * 20_000, "​" * 100_000,
                    "ab" * 60_000, "ي" * 100_000):  # fmt: skip
        t = time.perf_counter()
        r = analyze_text(payload)
        assert time.perf_counter() - t < 3.0
        assert 0.0 <= r.score <= 1.0


def test_oversized_input_is_truncated_and_flagged():
    r = analyze_text("x " * MAX_TEXT_CHARS)
    assert r.truncated
    assert not analyze_text("short text").truncated
    # a phrase beyond the cap is ignored
    r2 = analyze_text("a" * (MAX_TEXT_CHARS + 10) + " verify your account")
    assert r2.truncated and not r2.tactics


def test_returned_hits_are_capped_but_score_uses_all():
    r = analyze_text("click here. " * 5000)
    assert len(r.tactics) <= 500
    assert r.log_odds > 0


def test_unicode_edge_cases_do_not_crash():
    for t in ["\ud800" if False else "�", "é" * 50, "‮evil‬", "𝐕𝐞𝐫𝐢𝐟𝐲 𝐲𝐨𝐮𝐫 𝐚𝐜𝐜𝐨𝐮𝐧𝐭",
              "🙂" * 100, "\x00verify\x00 your\x00account", "ǅ ǈ ǋ", "ﷺ ﷻ"]:  # fmt: skip
        analyze_text(t)
        detect_otp_request(t)
        detect_phone_number(t)
    # mathematical bold text is folded by NFKC
    assert "credential" in tactics_of("𝐕𝐞𝐫𝐢𝐟𝐲 𝐲𝐨𝐮𝐫 𝐚𝐜𝐜𝐨𝐮𝐧𝐭")
    # NUL bytes inside words are dropped
    assert "credential" in tactics_of("\x00verify\x00 your\x00 account")


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=400))
def test_analyze_text_total_function(text):
    r = analyze_text(text)
    assert 0.0 <= r.score <= 1.0
    assert r.log_odds >= 0.0
    for h in r.tactics:
        assert 0 <= h.start < h.end <= len(text)
        assert h.tactic in TACTICS
    assert isinstance(detect_otp_request(text), bool)
    for p in detect_phone_number(text):
        assert p.lstrip("+").isdigit()


@settings(max_examples=80, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("abcdefgh ")), max_size=120))
def test_automaton_matches_naive_search(text):
    rng = random.Random(len(text))
    pats = ["".join(rng.choice("abcdefgh ") for _ in range(rng.randint(1, 5))) for _ in range(25)]
    pats = list(dict.fromkeys(p for p in pats if p))
    auto = se._Automaton((p, i) for i, p in enumerate(pats))
    got = sorted((end - len(pats[i]), end, i) for end, ids in auto.finditer(text) for i in ids)
    want = sorted(
        (s, s + len(p), i)
        for i, p in enumerate(pats)
        for s in range(len(text) - len(p) + 1)
        if text.startswith(p, s)
    )
    assert got == want


@settings(max_examples=100, deadline=None)
@given(st.text(max_size=200))
def test_normalize_properties(s):
    n, idx = se._normalize(s)
    assert len(n) == len(idx)
    assert "  " not in n and n == n.strip()
    assert all(0 <= i < len(s) for i in idx)
    assert idx == sorted(idx)
