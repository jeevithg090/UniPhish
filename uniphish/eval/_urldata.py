"""Static tables for the generated URL sets (brands, look-alike tables, benign hosts).

Why this module exists: keeps :mod:`uniphish.eval.datasets` focused on the generators and
loaders. Everything here is synthetic or plainly legitimate; the look-alike character
tables are the harness author's own and are deliberately independent of
``uniphish.url.confusables`` so the detector is not graded against its own data.
"""

from __future__ import annotations

BRANDS = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "docusign",
    "coinbase",
    "binance",
    "chase",
    "wellsfargo",
    "dhl",
    "fedex",
    "spotify",
    "adobe",
    "whatsapp",
    "steam",
    "outlook",
    "icloud",
    "telegram",
)

_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/account/verify",
    "/secure/update",
    "/auth",
    "/",
    "/webapps/auth",
    "/recover",
    "/session/new",
)
_HOST_WORDS = (
    "account",
    "verify",
    "secure",
    "support",
    "service",
    "help",
    "update",
    "billing",
    "portal",
    "center",
    "access",
    "alert",
)

# Deliberately independent of uniphish.url.confusables: the tables below are the test
# author's own, so the detector is not graded against its own data.
_CYR = {
    "a": "а",
    "c": "с",
    "e": "е",
    "i": "і",
    "j": "ј",
    "l": "ӏ",
    "o": "о",
    "p": "р",
    "s": "ѕ",
    "x": "х",
    "y": "у",
    "d": "ԁ",
    "h": "һ",
    "q": "ԛ",
    "w": "ԝ",
}
_GRK = {
    "o": "ο",
    "a": "α",
    "p": "ρ",
    "v": "ν",
    "i": "ι",
    "n": "η",
    "t": "τ",
    "u": "υ",
    "k": "κ",
    "x": "χ",
    "b": "β",
}
_ARM = {"o": "օ", "u": "ս", "n": "ո", "h": "հ", "g": "ց", "q": "զ"}
_LATX = {"a": "ɑ", "g": "ɡ", "i": "ı", "l": "ӏ", "o": "ɵ", "s": "ꜱ", "c": "ᴄ", "w": "ᴡ"}
_DIAC = {"a": "á", "e": "é", "i": "í", "o": "ó", "u": "ú", "n": "ñ", "c": "ç", "s": "š", "y": "ý"}
_DIGITS = {"o": "0", "l": "1", "i": "1", "s": "5", "e": "3", "a": "4"}
_KEY_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")

# (native brand, lang, script, login words, reserved IDN test TLD)
_NATIVE = (
    ("支付宝", "zh", "Hani", ("登录", "账户", "验证"), "测试"),
    ("楽天", "ja", "Jpan", ("ログイン", "確認", "アカウント"), "テスト"),
    ("네이버", "ko", "Hang", ("로그인", "인증", "계정"), "테스트"),
    ("Сбербанк", "ru", "Cyrl", ("вход", "безопасность", "подтверждение"), "испытание"),
    ("بايبال", "ar", "Arab", ("دخول", "حسابي", "تحقق"), "اختبار"),
    ("पेटीएम", "hi", "Deva", ("लॉगिन", "खाता", "सत्यापन"), "परीक्षा"),
)


_BRAND_OFFICIAL = (
    "https://www.paypal.com/signin",
    "https://accounts.google.com/signin",
    "https://login.microsoftonline.com/",
    "https://www.amazon.com/ap/signin",
    "https://appleid.apple.com/sign-in",
    "https://www.netflix.com/login",
    "https://www.facebook.com/login/",
    "https://www.linkedin.com/login",
    "https://www.dropbox.com/login",
    "https://account.docusign.com/",
    "https://www.coinbase.com/signin",
    "https://www.binance.com/en/login",
    "https://secure.chase.com/web/auth/dashboard",
    "https://www.wellsfargo.com/",
    "https://www.dhl.com/en/tracking.html",
    "https://www.fedex.com/en-us/tracking.html",
    "https://open.spotify.com/",
    "https://www.adobe.com/",
    "https://web.whatsapp.com/",
    "https://store.steampowered.com/login/",
    "https://github.com/login",
    "https://outlook.live.com/mail/",
    "https://www.icloud.com/",
    "https://web.telegram.org/",
    "https://www.instagram.com/accounts/login/",
    "https://www.paypal.com/myaccount/summary",
    "https://myaccount.google.com/security",
    "https://support.apple.com/en-us/HT201994",
)

_LOTS_BENIGN = (
    "https://sites.google.com/view/garden-club-newsletter",
    "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit",
    "https://drive.google.com/file/d/1ExAmPlEfIlEiD0123456789/view",
    "https://example-org.github.io/docs/",
    "https://bike-repair-co.pages.dev/",
    "https://community-library.web.app/",
    "https://choir-news.netlify.app/",
    "https://recipe-notes.vercel.app/",
    "https://raw.githubusercontent.com/example-org/example-repo/main/README.md",
    "https://storage.googleapis.com/example-public-bucket/report.pdf",
    "https://example-team.notion.site/Handbook-0123456789abcdef",
    "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/",
    "https://forms.gle/AbCdEfGhIjKlMnOp9",
    "https://firebasestorage.googleapis.com/v0/b/example-app.appspot.com/o/guide.pdf?alt=media",
    "https://example-club.wixsite.com/home",
    "https://example-shop.myshopify.com/products/mug",
    "https://example-author.medium.com/a-year-of-gardening-1a2b3c",
    "https://example-user.gitlab.io/portfolio/",
    "https://blog-example.blogspot.com/2025/03/spring-planting.html",
    "https://example-site.weebly.com/",
)

_BRAND_CONTEXT = (
    "https://en.wikipedia.org/wiki/PayPal",
    "https://github.com/paypal/paypal-sdk-examples",
    "https://www.reuters.com/technology/microsoft-expands-cloud-investment-2025-03-04/",
    "https://stackoverflow.com/questions/12345678/paypal-ipn-listener-returns-invalid",
    "https://support.example.com/integrations/google-calendar-sync",
    "https://blog.example.org/2025/02/how-to-spot-fake-amazon-emails",
    "https://www.example.com/guides/connect-your-netflix-account-to-the-tv",
    "https://en.wikipedia.org/wiki/Apple_Inc.",
    "https://www.bbc.co.uk/news/technology-12345678",
    "https://docs.example.net/api/facebook-login-button",
    "https://news.example.org/coinbase-earnings-q4",
    "https://learn.example.edu/courses/microsoft-excel-basics/lesson-3",
)

_MULTISCRIPT_LEGIT = (
    "https://ja.wikipedia.org/wiki/日本語",
    "https://zh.wikipedia.org/wiki/网络钓鱼",
    "https://ar.wikipedia.org/wiki/الإنترنت",
    "https://ru.wikipedia.org/wiki/Интернет",
    "https://ko.wikipedia.org/wiki/한국어",
    "https://hi.wikipedia.org/wiki/हिन्दी",
    "https://www.bbc.co.uk/news",
    "https://www.rakuten.co.jp/",
    "https://www.naver.com/",
    "https://www.baidu.com/",
    "https://yandex.ru/",
    "https://www.amazon.co.uk/",
)

_LEGIT_IDN = (
    "https://www.bücher.de/",
    "https://www.münchen.de/",
    "https://www.köln.de/",
    "https://президент.рф/",
    "https://пример.испытание/",
    "https://пример.испытание/вход",
    "https://例え.テスト/",
    "https://例え.テスト/ホーム",
    "https://例子.测试/",
    "https://例子.测试/首页",
    "https://실례.테스트/",
    "https://مثال.اختبار/",
    "https://उदाहरण.परीक्षा/",
    "https://παράδειγμα.δοκιμή/",
    "https://www.bücherei.example/",
    "https://café-du-coin.example/menu",
    "https://www.müller-gmbh.example/kontakt",
    "https://naïve-café.test/",
)

_TAIL_NOUNS = (
    "bakery",
    "chess-club",
    "yoga-studio",
    "dental-care",
    "hardware",
    "bookshop",
    "garden-centre",
    "bike-repair",
    "pizzeria",
    "library",
    "dance-school",
    "plumbing",
    "photo-lab",
    "pet-clinic",
    "cycling-team",
    "knitting-circle",
)
_TAIL_PAGES = (
    "menu",
    "about",
    "contact",
    "blog/2025/03/my-trip-to-lisbon",
    "products/item-42?color=blue",
    "events",
    "faq",
    "newsletter/unsubscribe?id=1042",
    "support/tickets/1042",
    "opening-hours",
    "gallery?page=3",
    "team/anna-meyer",
    "pricing",
    "news/spring-sale",
)
_TAIL_LOGIN = (
    "members/login",
    "portal/account/settings",
    "customer/signin",
    "admin/login",
    "my-account/orders",
    "account/password/reset",
    "booking/manage",
    "secure/payments",
)
_LONG_BASES = (
    ("https://www.google.com/search", ("q", "hl", "ie", "oq", "sclient", "gs_lcp")),
    ("https://www.youtube.com/watch", ("v", "list", "index", "t", "feature")),
    (
        "https://www.amazon.com/dp/B0EXAMPLE12/ref=sr_1_3",
        ("keywords", "qid", "sr", "crid", "sprefix"),
    ),
    (
        "https://www.example.com/products/search",
        ("utm_source", "utm_medium", "utm_campaign", "utm_content", "gclid"),
    ),
    ("https://docs.python.org/3/library/urllib.parse.html", ("highlight", "ref", "from")),
    (
        "https://github.com/example-org/example-repo/blob/main/src/pkg/sub/module.py",
        ("plain", "ref"),
    ),
)
_WORDS = (
    "spring",
    "sale",
    "winter",
    "boots",
    "trail",
    "guide",
    "review",
    "weekly",
    "digest",
    "offer",
    "garden",
    "kitchen",
    "travel",
    "budget",
    "ideas",
    "report",
)
