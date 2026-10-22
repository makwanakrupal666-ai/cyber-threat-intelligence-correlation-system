from backend import main


def test_ioc_type_filter_is_applied_before_pagination(monkeypatch):
    records = [
        {"ioc_type": "ip", "ioc_value": "8.8.8.8", "sources": ["feed-a"]},
        {"ioc_type": "domain", "ioc_value": "example-threat.test", "sources": ["feed-b"]},
        {"ioc_type": "domain", "ioc_value": "phishing.example.test", "sources": ["feed-b", "feed-c"]},
        {"ioc_type": "sha256", "ioc_value": "a" * 64, "sources": ["feed-d"]},
    ]
    monkeypatch.setattr(main, "get_all_records", lambda: records)

    response = main.get_iocs(limit=1, offset=1, ioc_type="DOMAIN")

    assert response["total"] == 2
    assert response["count"] == 1
    assert response["records"][0]["ioc_value"] == "phishing.example.test"
    assert response["records"][0]["ioc_type"] == "domain"


def test_ioc_type_filter_without_type_keeps_all_records(monkeypatch):
    records = [
        {"ioc_type": "ip", "ioc_value": "8.8.8.8", "sources": ["feed-a"]},
        {"ioc_type": "domain", "ioc_value": "example.test", "sources": ["feed-b"]},
    ]
    monkeypatch.setattr(main, "get_all_records", lambda: records)

    response = main.get_iocs(limit=20, offset=0, ioc_type=None)

    assert response["total"] == 2
    assert {item["ioc_type"] for item in response["records"]} == {"ip", "domain"}
