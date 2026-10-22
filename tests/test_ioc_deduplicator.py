from backend.deduplicators.ioc_deduplicator import deduplicate
from backend.deduplicators.ioc_deduplicator import normalize_and_deduplicate_domains
from backend.deduplicators.ioc_deduplicator import normalize_and_deduplicate_ips
from backend.deduplicators.ioc_deduplicator import normalize_and_deduplicate_hashes
from backend.deduplicators.ioc_deduplicator import normalize_and_deduplicate_urls
def test_deduplicate():
    values = [
        "185.10.20.30",
        "evil-example.com",
        "185.10.20.30",
        "evil-example.com",
    ]

    result = deduplicate(values)

    assert result == [
        "185.10.20.30",
        "evil-example.com",
    ]
def test_deduplicate_preserves_order():
    values = [
        "evil.com",
        "185.10.20.30",
        "malware.com",
        "evil.com",
        "185.10.20.30",
    ]

    result = deduplicate(values)

    assert result == [
        "evil.com",
        "185.10.20.30",
        "malware.com",
    ]

def test_normalize_and_deduplicate_domains():
    domains = [
        "Evil-Example.COM.",
        "evil-example.com",
        " EVIL-EXAMPLE.COM ",
        "malware.com",
    ]

    result = normalize_and_deduplicate_domains(domains)

    assert result == [
        "evil-example.com",
        "malware.com",
    ]

def test_normalize_and_deduplicate_ips():
    ips = [
        " 185.10.20.30 ",
        "185.10.20.30",
        " 192.168.1.10 ",
        "185.10.20.30",
    ]

    result = normalize_and_deduplicate_ips(ips)

    assert result == [
        "185.10.20.30",
        "192.168.1.10",
    ]

def test_normalize_and_deduplicate_hashes():
    hashes = [
        "5D41402ABC4B2A76B9719D911017C592",
        "5d41402abc4b2a76b9719d911017c592",
        " 5D41402ABC4B2A76B9719D911017C592 ",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    ]

    result = normalize_and_deduplicate_hashes(hashes)

    assert result == [
        "5d41402abc4b2a76b9719d911017c592",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    ]

def test_normalize_and_deduplicate_urls():
    urls = [
        " https://evil-example.com/payload.exe. ",
        "https://evil-example.com/payload.exe",
        "https://malware.com/test.exe",
        " https://evil-example.com/payload.exe ",
    ]

    result = normalize_and_deduplicate_urls(urls)

    assert result == [
        "https://evil-example.com/payload.exe",
        "https://malware.com/test.exe",
    ]