import pytest

from main import normalize_domain


def test_normalize_domain_accepts_public_domain():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("https://Example.com/path") == "example.com"


def test_normalize_domain_rejects_private_and_loopback_targets():
    with pytest.raises(ValueError):
        normalize_domain("localhost")

    with pytest.raises(ValueError):
        normalize_domain("127.0.0.1")

    with pytest.raises(ValueError):
        normalize_domain("http://127.0.0.1:8000/")
