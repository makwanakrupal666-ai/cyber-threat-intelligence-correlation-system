from backend.enrichment.rdap_enricher import (
    extract_entity_name,
    extract_rdap_summary,
    enrich_ip
)


def test_extract_entity_name():

    entity = {
        "vcardArray": [
            "vcard",
            [
                [
                    "version",
                    {},
                    "text",
                    "4.0"
                ],
                [
                    "fn",
                    {},
                    "text",
                    "Example Network"
                ]
            ]
        ]
    }

    assert extract_entity_name(
        entity
    ) == "Example Network"


def test_extract_rdap_summary():

    data = {
        "handle": "TEST-123",
        "name": "TEST-NETWORK",
        "type": "PUBLIC",
        "country": "US",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
        "entities": []
    }

    result = extract_rdap_summary(
        data
    )

    assert result["rdap_status"] == "success"
    assert result["handle"] == "TEST-123"
    assert result["name"] == "TEST-NETWORK"
    assert result["country"] == "US"


def test_enrich_ip_failure(monkeypatch):

    def fake_fetch_rdap(ip):
        raise RuntimeError(
            "test failure"
        )

    monkeypatch.setattr(
        "backend.enrichment.rdap_enricher.fetch_rdap",
        fake_fetch_rdap
    )

    result = enrich_ip(
        "192.0.2.10"
    )

    assert result["rdap_status"] == "error"
    assert "test failure" in result["error"]