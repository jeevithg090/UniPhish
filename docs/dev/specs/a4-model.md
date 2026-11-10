# Spec: TF-free runtime for the UniPhish byte-level CNN
OWN: uniphish/url/model.py, uniphish/url/saliency.py, uniphish/assets/model/ (copy
extension/model/manifest.json + weights.bin here + model_info.json with provenance:
param count 377985, metrics/caveats from MODEL_CARD.md & docs/paper_vs_reality.md),
tests/url/test_model.py, tests/url/test_model_parity.py, tests/url/parity_runner.js.

PURPOSE: run the original IEEE-paper byte-level CNN with pure NumPy so the platform
needs no TensorFlow. Read extension/model.js and scripts/export_web.py for the exact
tensor layout and forward pass.

model.py: NumPy forward pass identical to extension/model.js: UTF-8 bytes truncated/
zero-padded to 600; embedding (256x64); conv1d kernels 2..6 x128 'valid' + ReLU +
global-max-pool (padding positions included exactly as the JS does); dense 640->256
ReLU ->128 ReLU ->1 sigmoid. Vectorise (im2col/sliding-window matmul, float32,
batched). class UrlModel(manifest_path=None, weights_path=None): predict(urls)->
np.ndarray[float32], predict_one(url)->float, logits(urls), param_count, info()->dict.
get_model() lazy thread-safe singleton; ModelUnavailable if assets missing. Validate
weights-file size against the manifest. Optional temperature calibration (default T=1).

saliency.py: occlusion saliency (which characters move the score) — for each character
(multi-byte aware) replace its bytes and measure the probability change, batched in one
predict call; return list[CharSaliency(index,char,start_byte,end_byte,delta)] +
top_spans(url,k) merging adjacent salient chars into index ranges for UI highlighting.

PARITY: tests/url/parity_runner.js loads extension/model.js + weights, prints JSON probs
for ~25 diverse URLs (Latin/Cyrillic/Arabic/CJK/Devanagari/Hangul, >600 bytes, short);
the test runs node (skip if absent) and asserts NumPy matches within 1e-4. Report ms/URL
(single + batched) in your summary. Note the dataset caveat honestly in the docstring
(raw model may over-score long legit URLs; the fused engine compensates).
