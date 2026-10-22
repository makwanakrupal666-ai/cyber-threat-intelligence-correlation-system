from backend.enrichment.enrichment_service import enrich_ioc


def test_enrich_ip(monkeypatch):

    def fake_enrich_ip(ip):
        return {
            "rdap_status": "success",
            "name": "Example Network",
            "country": "US"
        }

    monkeypatch.setattr(
        "backend.enrichment.enrichment_service.enrich_ip",
        fake_enrich_ip
    )

    result = enrich_ioc(
        "ip",
        "192.0.2.10"
    )

    assert result["rdap_status"] == "success"
    assert result["name"] == "Example Network"


def test_unsupported_ioc_type():

    result = enrich_ioc(
        "sha256",
        "abcdef"
    )

    assert result["status"] == "unsupported"
    assert result["ioc_type"] == "sha256"   