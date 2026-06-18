from aysal_scan.scanner.entropy import shannon_entropy, is_high_entropy_secret


def test_high_entropy_random_string():
    # A random-looking base64 string should be flagged
    assert is_high_entropy_secret("aB3xK9mZ2pQrTyUvWsNj4hDcFgLeOiPo") is True


def test_low_entropy_repeated():
    assert is_high_entropy_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") is False


def test_short_string_not_flagged():
    assert is_high_entropy_secret("aB3xK9mZ") is False  # too short


def test_entropy_value():
    # All same chars = 0 entropy
    assert shannon_entropy("aaaa") == 0.0
    # Mixed string has positive entropy
    assert shannon_entropy("aB3xK9mZ2p") > 0
