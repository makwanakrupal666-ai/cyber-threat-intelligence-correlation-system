from backend.processors.priority_scorer import (
    calculate_source_evidence_score,
    calculate_ioc_type_score,
    calculate_enrichment_score,
    calculate_attack_evidence_score,
    calculate_research_priority
)


def test_source_evidence_score():

    assert calculate_source_evidence_score(0) == 0
    assert calculate_source_evidence_score(1) == 15
    assert calculate_source_evidence_score(2) == 25
    assert calculate_source_evidence_score(3) == 32
    assert calculate_source_evidence_score(4) == 40


def test_ioc_type_score():

    assert calculate_ioc_type_score("url") == 15
    assert calculate_ioc_type_score("ip") == 12
    assert calculate_ioc_type_score("sha256") == 10


def test_enrichment_score():

    assert calculate_enrichment_score(
        {}
    ) == 0

    enrichment = {
        "rdap_status": "success",
        "name": "Example Network",
        "entities": [
            "Example Organization"
        ]
    }

    assert calculate_enrichment_score(
        enrichment
    ) == 20


def test_attack_evidence_score():

    mappings = [
        {
            "technique_id": "T1059.001",
            "mapping_confidence": 0.9
        }
    ]

    score = calculate_attack_evidence_score(
        mappings
    )

    assert score == 20.5


def test_research_priority():

    enrichment = {
        "rdap_status": "success",
        "name": "Example Network",
        "entities": [
            "Example Organization"
        ]
    }

    mappings = [
        {
            "technique_id": "T1059.001",
            "mapping_confidence": 0.9
        }
    ]

    result = calculate_research_priority(
        ioc_type="ip",
        source_count=2,
        enrichment=enrichment,
        attack_mappings=mappings
    )

    assert result["score"] == 77.5
    assert result["priority"] == "High"

    assert (
        result["components"]["source_evidence"]
        == 25
    )

    assert (
        result["components"]["ioc_type"]
        == 12
    )

    assert (
        result["components"]["enrichment"]
        == 20
    )

    assert (
        result["components"]["attack_evidence"]
        == 20.5
    )