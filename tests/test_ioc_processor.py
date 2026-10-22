from backend.processors.ioc_processor import extract_all_iocs


def test_extract_all_iocs():
    text = """
    The attacker used 185.10.20.30.
    The malicious domain was evil-example.com.
    The payload was downloaded from https://evil-example.com/payload.exe.
    MD5: 5d41402abc4b2a76b9719d911017c592
    SHA-1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
    SHA-256: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
    """

    result = extract_all_iocs(text)

    assert len(result["ips"]) == 1
    assert result["ips"][0].ioc_type == "ip"
    assert result["ips"][0].ioc_value == "185.10.20.30"

    assert len(result["domains"]) == 1
    assert result["domains"][0].ioc_type == "domain"
    assert result["domains"][0].ioc_value == "evil-example.com"

    assert len(result["urls"]) == 1
    assert result["urls"][0].ioc_type == "url"
    assert result["urls"][0].ioc_value == "https://evil-example.com/payload.exe"

    assert len(result["md5"]) == 1
    assert result["md5"][0].ioc_type == "md5"
    assert result["md5"][0].ioc_value == "5d41402abc4b2a76b9719d911017c592"

    assert len(result["sha1"]) == 1
    assert result["sha1"][0].ioc_type == "sha1"
    assert result["sha1"][0].ioc_value == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

    assert len(result["sha256"]) == 1
    assert result["sha256"][0].ioc_type == "sha256"
    assert result["sha256"][0].ioc_value == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"