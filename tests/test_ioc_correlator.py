from backend.models.ioc_model import IOCRecord

from backend.processors.ioc_correlator import (
    correlate_iocs,
    calculate_confidence,
    calculate_priority,
    classify_priority
)


def test_correlate_same_ioc_from_multiple_sources():

    records = [
        IOCRecord(
            ioc_type="domain",
            ioc_value="evil-example.com",
            source_name="source-a.com",
            sources=["source-a.com"]
        ),
        IOCRecord(
            ioc_type="domain",
            ioc_value="evil-example.com",
            source_name="source-b.com",
            sources=["source-b.com"]
        )
    ]

    result = correlate_iocs(records)

    assert len(result) == 1
    assert result[0].ioc_value == "evil-example.com"

    assert set(result[0].sources) == {
        "source-a.com",
        "source-b.com"
    }


def test_confidence_score():

    assert calculate_confidence(0) == 0
    assert calculate_confidence(1) == 40
    assert calculate_confidence(2) == 60
    assert calculate_confidence(3) == 80
    assert calculate_confidence(5) == 100


def test_priority_score():

    assert calculate_priority(80, "domain") == 80
    assert calculate_priority(80, "url") == 88
    assert calculate_priority(80, "sha256") == 72


def test_priority_classification():

    assert classify_priority(90) == "High"
    assert classify_priority(60) == "Medium"
    assert classify_priority(30) == "Low"