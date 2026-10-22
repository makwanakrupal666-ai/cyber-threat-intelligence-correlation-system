
from backend.extractors.ioc_extractor import extract_ips
from backend.extractors.ioc_extractor import extract_domains
from backend.extractors.ioc_extractor import extract_urls
from backend.extractors.ioc_extractor import extract_md5
from backend.extractors.ioc_extractor import extract_sha1
from backend.extractors.ioc_extractor import extract_sha256


def test_extract_ips():
    text = "The attacker used 185.10.20.30."

    result = extract_ips(text)

    assert result == ["185.10.20.30"]


def test_extract_domains():
    text = "The attacker used evil-example.com."

    result = extract_domains(text)

    assert result == ["evil-example.com"]


def test_extract_urls():
    text = "The malware was downloaded from https://evil-example.com/payload.exe."

    result = extract_urls(text)

    assert result == ["https://evil-example.com/payload.exe"]

def test_extract_md5():
    text = "The malware MD5 hash is 5d41402abc4b2a76b9719d911017c592."

    result = extract_md5(text)

    assert result == ["5d41402abc4b2a76b9719d911017c592"]


def test_extract_sha1():
    text = "The malware SHA-1 hash is 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed."

    result = extract_sha1(text)

    assert result == ["2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"]


def test_extract_sha256():
    text = "The malware SHA-256 hash is d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592."

    result = extract_sha256(text)

    assert result == [
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    ]