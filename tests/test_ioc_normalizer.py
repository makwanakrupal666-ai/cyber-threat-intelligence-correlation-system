from backend.normalizers.ioc_normalizer import normalize_ip
from backend.normalizers.ioc_normalizer import normalize_domain
from backend.normalizers.ioc_normalizer import normalize_url
from backend.normalizers.ioc_normalizer import normalize_hash


def test_normalize_ip():
    value = " 185.10.20.30 "

    result = normalize_ip(value)

    assert result == "185.10.20.30"


def test_normalize_domain():
    value = " Evil-Example.COM. "

    result = normalize_domain(value)

    assert result == "evil-example.com"


def test_normalize_url():
    value = " https://Evil-Example.COM/payload.exe. "

    result = normalize_url(value)

    assert result == "https://Evil-Example.COM/payload.exe"


def test_normalize_hash():
    value = " 5D41402ABC4B2A76B9719D911017C592 "

    result = normalize_hash(value)

    assert result == "5d41402abc4b2a76b9719d911017c592"