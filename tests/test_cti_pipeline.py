from backend.processors.cti_pipeline import process_cti_url


def test_process_cti_url(monkeypatch):
    """
    Test the complete CTI processing pipeline
    without making a real internet request or
    writing to the real database.
    """

    fake_source = {
        "url": "https://example.com/cti.txt",
        "content_type": "text/plain",
        "text": """
        The attacker used 185.10.20.30.
        Malicious domain: evil-example.com
        Payload URL: https://evil-example.com/payload.exe
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA-256: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
        """
    }

    def fake_fetch_cti_text(url):
        return fake_source

    def fake_save_ioc_records(records):
        return len(records)

    monkeypatch.setattr(
        "backend.processors.cti_pipeline.fetch_cti_text",
        fake_fetch_cti_text
    )

    monkeypatch.setattr(
        "backend.processors.cti_pipeline.save_ioc_records",
        fake_save_ioc_records
    )

    result = process_cti_url(
        "https://example.com/cti.txt"
    )

    assert result["source_url"] == "https://example.com/cti.txt"
    assert result["content_type"] == "text/plain"

    assert result["ioc_count"] == 5
    assert result["saved_count"] == 5

    assert len(result["records"]) == 5