"""Synthetic .eml samples. All hosts are reserved; addresses are fictional.

Each entry: dict(id, filename, label, category, note, headline_signal, hard, raw).
The one exception to "reserved domains only" is that the BEC sample needs a *freemail*
Reply-To to exhibit the real-world pattern; its local part is an obviously fictional
string and nothing is ever sent to it.
"""

from __future__ import annotations

M, B = "malicious", "benign"

_RECV_OK = ("Received: from mail.shop.example.com (mail.shop.example.com [192.0.2.25])\n"
            "\tby mx.corpus.example with ESMTPS id AA11; Mon, 02 Mar 2026 09:14:02 +0000\n")
_RECV_BAD = ("Received: from unknown (unknown [198.51.100.77])\n"
             "\tby mx.corpus.example with SMTP id BB22; Mon, 02 Mar 2026 03:41:55 +0000\n")


def E(id, filename, label, cat, note, head, raw, hard=False):
    return dict(id=id, filename=filename, label=label, category=cat, note=note,
                headline_signal=head, hard=hard, raw=raw)


SPOOFED_DISPLAY = (
    "Authentication-Results: mx.corpus.example; spf=none smtp.mailfrom=mail-service.example;\n"
    "\tdkim=none; dmarc=none header.from=mail-service.example\n" + _RECV_BAD +
    'From: "PayPal Support" <billing@mail-service.example>\n'
    "To: customer@corpus.example\n"
    "Subject: Action required: confirm your PayPal account\n"
    "Date: Mon, 02 Mar 2026 03:41:50 +0000\n"
    "Message-ID: <0001@mail-service.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Dear customer,\n\nWe noticed unusual activity on your PayPal account. To avoid "
    "suspension you must confirm your details within 24 hours.\n\n"
    "Confirm now: https://paypal-account-confirm.example/signin\n\nPayPal Support\n")

DMARC_FAIL = (
    "Authentication-Results: mx.corpus.example; spf=fail smtp.mailfrom=microsoft-notify.example;\n"
    "\tdkim=fail header.d=microsoft-notify.example;\n"
    "\tdmarc=fail header.from=microsoft-notify.example\n" + _RECV_BAD +
    'From: "Microsoft Account Team" <security@microsoft-notify.example>\n'
    "To: customer@corpus.example\n"
    "Subject: Unusual sign-in activity on your Microsoft account\n"
    "Date: Mon, 02 Mar 2026 03:50:10 +0000\n"
    "Message-ID: <0002@microsoft-notify.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/html; charset=utf-8\n\n"
    "<html><body><p>We detected a sign-in from a new location. Review it right away or "
    "your account will be locked.</p>"
    '<p><a href="https://login-microsoft365.example/review">https://www.microsoft.com/security</a>'
    "</p></body></html>\n")

BEC_GIFTCARD = (
    "Authentication-Results: mx.corpus.example; spf=pass smtp.mailfrom=gmail.com;\n"
    "\tdkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com\n" + _RECV_BAD +
    'From: "Dana Whitfield (CEO)" <uniphish.corpus.demo@gmail.com>\n'
    "Reply-To: uniphish.corpus.demo@gmail.com\n"
    "To: finance.assistant@corpus.example\n"
    "Subject: Quick favour\n"
    "Date: Mon, 02 Mar 2026 08:02:11 +0000\n"
    "Message-ID: <0003@mail.gmail.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hi,\n\nAre you at your desk? I'm in meetings all day and need a favour, keep it "
    "between us. I need 5 Apple gift cards of $200 each for a client, urgently. Buy them "
    "now and send me the codes by reply. I'll reimburse you today.\n\nDana\n"
    "Sent from my iPhone\n")

ALIGNED_LEGIT = (
    "Authentication-Results: mx.corpus.example; spf=pass smtp.mailfrom=shop.example.com;\n"
    "\tdkim=pass header.d=example.com; dmarc=pass header.from=example.com\n" + _RECV_OK +
    'From: "Example Shop" <orders@example.com>\n'
    "To: customer@corpus.example\n"
    "Subject: Your order 100234 has shipped\n"
    "Date: Mon, 02 Mar 2026 09:14:00 +0000\n"
    "Message-ID: <0004@example.com>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hello,\n\nYour order 100234 shipped today and should arrive on Thursday. You can view "
    "the details at https://www.example.com/orders/100234 at any time.\n\nThanks for "
    "shopping with us.\n")

FORWARDED_PHISH = (
    "Authentication-Results: mx.corpus.example; spf=pass smtp.mailfrom=corpus.example;\n"
    "\tdkim=pass header.d=corpus.example; dmarc=pass header.from=corpus.example\n" + _RECV_OK +
    'From: "Priya Raman" <priya.raman@corpus.example>\n'
    "To: abuse@corpus.example\n"
    "Subject: Fwd: Confirm your payroll details\n"
    "Date: Mon, 02 Mar 2026 10:05:00 +0000\n"
    "Message-ID: <0005@corpus.example>\n"
    "MIME-Version: 1.0\n"
    'Content-Type: multipart/mixed; boundary="BOUND-FWD"\n\n'
    "--BOUND-FWD\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hi security team, this looks off to me. Can you check it?\n\n"
    "--BOUND-FWD\n"
    "Content-Type: message/rfc822\n"
    'Content-Disposition: attachment; filename="original.eml"\n\n'
    "Authentication-Results: mx.corpus.example; spf=fail smtp.mailfrom=hr-portal.example;\n"
    "\tdkim=none; dmarc=fail header.from=hr-portal.example\n"
    'From: "HR Department" <payroll@hr-portal.example>\n'
    "To: priya.raman@corpus.example\n"
    "Subject: Confirm your payroll details\n"
    "Date: Mon, 02 Mar 2026 04:12:00 +0000\n"
    "Message-ID: <0006@hr-portal.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Your salary payment is on hold. Verify your login and bank details today or payment "
    "will be delayed: https://hr-portal-login.example/payroll/verify\n\n"
    "--BOUND-FWD--\n")

CALLBACK = (
    "Authentication-Results: mx.corpus.example; spf=softfail smtp.mailfrom=billing-desk.example;\n"
    "\tdkim=none; dmarc=none header.from=billing-desk.example\n" + _RECV_BAD +
    'From: "Geek Squad Billing" <invoice@billing-desk.example>\n'
    "To: customer@corpus.example\n"
    "Subject: Invoice 88231 - your subscription has been renewed\n"
    "Date: Mon, 02 Mar 2026 05:30:00 +0000\n"
    "Message-ID: <0007@billing-desk.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Thank you for your order. Your annual protection plan of $449.99 has been renewed and "
    "charged to your card. If you did not authorize this charge, call our billing desk "
    "immediately on 1-888-555-0173 to cancel and receive a full refund.\n")

NEWSLETTER = (
    "Authentication-Results: mx.corpus.example; spf=pass smtp.mailfrom=news.example.org;\n"
    "\tdkim=pass header.d=example.org; dmarc=pass header.from=example.org\n" + _RECV_OK +
    'From: "Example Weekly" <newsletter@example.org>\n'
    "To: customer@corpus.example\n"
    "Subject: This week: three articles on gardening\n"
    "Date: Mon, 02 Mar 2026 07:00:00 +0000\n"
    "Message-ID: <0008@example.org>\n"
    "List-Unsubscribe: <https://www.example.org/unsubscribe>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hello gardeners,\n\nThis week we cover composting, pruning roses and spring planting. "
    "Read more at https://www.example.org/weekly/2026-09.\n\n"
    "To stop receiving this newsletter use the link in the header.\n")

INTERNAL = (
    "Authentication-Results: mx.corpus.example; spf=pass smtp.mailfrom=corpus.example;\n"
    "\tdkim=pass header.d=corpus.example; dmarc=pass header.from=corpus.example\n" + _RECV_OK +
    'From: "Sam Okafor" <sam.okafor@corpus.example>\n'
    "To: team@corpus.example\n"
    "Subject: Sprint review moved to 3pm\n"
    "Date: Mon, 02 Mar 2026 11:20:00 +0000\n"
    "Message-ID: <0009@corpus.example>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hi all, the sprint review is now at 3pm in the usual room. Slides are in the team "
    "drive. See you there.\n\nSam\n")

EMAILS = [
    E("eml-spoofed-display-name", "spoofed_display_name.eml", M, "spoofed_brand",
      "Display name claims PayPal; the address is an unrelated domain with no authentication.",
      "brand.sender.display_name", SPOOFED_DISPLAY),
    E("eml-dmarc-fail", "dmarc_fail_microsoft.eml", M, "auth_failure",
      "SPF, DKIM and DMARC all fail for a look-alike Microsoft sender; link text differs "
      "from its target.", "auth.dmarc.fail", DMARC_FAIL),
    E("eml-bec-giftcard", "bec_giftcard.eml", M, "bec",
      "Executive impersonation asking for gift-card codes, no links, freemail sender.",
      "email.bec.payment_pressure", BEC_GIFTCARD),
    E("eml-forwarded-phish", "forwarded_phish.eml", M, "forwarded_phish",
      "A staff member forwards a phish to the abuse mailbox; the container is clean but the "
      "attached original must be surfaced.", "engine.child.email", FORWARDED_PHISH),
    E("eml-callback-toad", "callback_toad.eml", M, "callback_phishing",
      "Fake renewal invoice that pushes the reader to phone a number (no link).",
      "social.email.callback_number", CALLBACK),
    E("eml-aligned-legit", "aligned_legit.eml", B, "legit_authenticated",
      "Order notice that authenticates as its own From domain (DMARC aligned).",
      "auth.aligned_pass.known", ALIGNED_LEGIT),
    E("eml-newsletter", "benign_newsletter.eml", B, "legit_newsletter",
      "Aligned newsletter with List-Unsubscribe.", None, NEWSLETTER),
    E("eml-internal", "benign_internal.eml", B, "legit_internal",
      "Plain internal message with aligned authentication.", None, INTERNAL),
]


def quishing_email(qr_png: bytes) -> dict:
    """An email whose only lure is an attached QR image (built here: needs the PNG bytes)."""
    import base64
    b64 = base64.encodebytes(qr_png).decode("ascii")
    raw = (
        "Authentication-Results: mx.corpus.example; spf=fail smtp.mailfrom=it-helpdesk.example;\n"
        "\tdkim=none; dmarc=fail header.from=it-helpdesk.example\n" + _RECV_BAD +
        'From: "IT Helpdesk" <noreply@it-helpdesk.example>\n'
        "To: staff@corpus.example\n"
        "Subject: Mandatory MFA re-enrolment - scan within 24 hours\n"
        "Date: Mon, 02 Mar 2026 06:15:00 +0000\n"
        "Message-ID: <0010@it-helpdesk.example>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="BOUND-QR"\n\n'
        "--BOUND-QR\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Your multi-factor authentication token expires today. Scan the attached QR code "
        "with your phone to re-enrol, otherwise your account will be disabled.\n\n"
        "--BOUND-QR\n"
        "Content-Type: image/png; name=\"mfa-enrol.png\"\n"
        "Content-Transfer-Encoding: base64\n"
        "Content-Disposition: attachment; filename=\"mfa-enrol.png\"\n\n"
        + b64 + "\n--BOUND-QR--\n")
    return E("eml-quishing", "quishing_qr_attachment.eml", M, "quishing",
             "Phish whose only link is a QR code in an attached image (the QR encodes a "
             "reserved-domain URL).", "engine.child.file", raw)
