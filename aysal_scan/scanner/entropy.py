import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def is_high_entropy_secret(value: str, threshold: float = 4.5, min_length: int = 20) -> bool:
    if len(value) < min_length:
        return False
    # Skip strings that look like variable names or constant identifiers
    if value.replace("_", "").isupper():
        return False
    # Skip pure hex strings of typical hash lengths (SHA1=40, SHA256=64, MD5=32)
    # These are git commit SHAs, content hashes — not secrets
    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return False
    # Skip UUID-like strings (8-4-4-4-12 pattern)
    if len(value) == 32 and all(c in "0123456789abcdef-" for c in value.lower()):
        return False
    return shannon_entropy(value) >= threshold