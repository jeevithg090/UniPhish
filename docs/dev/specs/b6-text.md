# Spec: text/message analyzer (smishing, chat, social engineering)
OWN: uniphish/analyzers/text.py, tests/analyzers/test_text_analyzer.py.
stage=0, blocking=True, kinds={ArtifactKind.TEXT}. Depends on uniphish.nlp.
social_engineering (a9), uniphish.url.parse extract_urls. This is the SMS/chat/WhatsApp
surface — the paper's messaging thesis.

Emit signals (category 'social'): social-engineering pressure from SEResult (map score +
dominant tactic to weight, e.g. urgency+authority+credential-ask combination +2.5; OTP
request +3 T1621/T1111-adjacent; payment/gift-card/wire ask +2.5 T1657; tech-support/
callback phone number +2 with the number as an Indicator(phone)); crypto seed-phrase ask
+4. Extract URLs from the text as child Artifacts (origin='text.link') so they're analysed
and their risk propagates. meta {'languages':..,'tactics':..}. Keep benign chat low.
Also detect 'brand + link mismatch': message names a brand but the only link's domain is
unrelated (coordinate loosely via extracted hosts + nlp; +2).
TESTS: a smishing SMS (parcel/bank + link + urgency) -> suspicious/malicious with child URL
risk; OTP-phish; gift-card BEC-style text; benign message low; phone + crypto asks
detected. Multilingual sample (es/hi/pt).
