from backend.models.ioc_model import IOCRecord
from backend.collectors.multi_source_collector import (
    SOURCE_FEEDS,
    collect_ip_feed,
    collect_entity_feed,
    collect_all_sources,
)


def test_collect_ip_feed(monkeypatch):
    fake_text = """
    # Example CTI feed
    185.10.20.30
    185.10.20.30
    203.0.113.50
    """

    monkeypatch.setattr(
        "backend.collectors.multi_source_collector.fetch_feed",
        lambda url: fake_text,
    )

    records = collect_ip_feed("Test Source", "https://example.com/feed.txt")

    assert len(records) == 2
    assert records[0].ioc_type == "ip"
    assert records[0].ioc_value == "185.10.20.30"
    assert records[0].source_name == "Test Source"
    assert records[0].sources == ["Test Source"]
    assert records[0].source_url == "https://example.com/feed.txt"
    assert records[0].evidence[0]["source"] == "Test Source"
    assert records[0].evidence[0]["method"] == "ip_feed"
    assert records[0].evidence[0]["source_url"] == "https://example.com/feed.txt"
    assert records[0].evidence[0]["collected_at"]


def test_collect_entity_feed_extracts_declared_types_and_evidence(monkeypatch):
    fake_text = """
    https://malicious.example/path
    185.10.20.30
    d41d8cd98f00b204e9800998ecf8427e
    CVE-2024-12345
    """

    monkeypatch.setattr(
        "backend.collectors.multi_source_collector.fetch_feed",
        lambda url: fake_text,
    )

    records = collect_entity_feed(
        "Test URL Feed",
        "https://example.com/feed.txt",
        allowed_types=["url", "domain"],
    )

    assert records
    assert {record.ioc_type for record in records} <= {"url", "domain"}
    assert all(record.evidence for record in records)
    assert all(record.source_url == "https://example.com/feed.txt" for record in records)


def test_collect_all_sources_reports_each_configured_feed(monkeypatch):
    def fake_ip_feed(source_name, url):
        return [IOCRecord(
            ioc_type="ip",
            ioc_value="185.10.20.30",
            source_name=source_name,
            source_url=url,
            sources=[source_name],
            evidence=[{"source": source_name, "method": "test"}],
        )]

    def fake_entity_feed(source_name, url, allowed_types=None):
        kind = next((t for t in allowed_types or [] if t in {"domain", "url", "md5", "sha1", "sha256"}), "domain")
        return [IOCRecord(
            ioc_type=kind,
            ioc_value="malicious.example",
            source_name=source_name,
            source_url=url,
            sources=[source_name],
            evidence=[{"source": source_name, "method": "test"}],
        )]

    monkeypatch.setattr(
        "backend.collectors.multi_source_collector.collect_ip_feed",
        fake_ip_feed,
    )
    monkeypatch.setattr(
        "backend.collectors.multi_source_collector.collect_entity_feed",
        fake_entity_feed,
    )

    result = collect_all_sources()

    assert len(SOURCE_FEEDS) >= 20
    assert len(result["sources"]) == len(SOURCE_FEEDS)
    assert len(result["records"]) == len(SOURCE_FEEDS)
    assert all(source["status"] == "success" for source in result["sources"])
    assert result["catalog"]["active_feed_count"] >= 20
