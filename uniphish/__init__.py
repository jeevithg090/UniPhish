"""UniPhish: Unicode-native character-level 1D-CNN for multilingual phishing URL detection."""

from uniphish.encoding import encode_url, encode_batch, MAX_LEN, VOCAB_SIZE, PAD_BYTE

__version__ = "0.1.0"

__all__ = ["encode_url", "encode_batch", "MAX_LEN", "VOCAB_SIZE", "PAD_BYTE", "__version__"]
