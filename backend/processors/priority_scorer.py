"""
Transparent CTI prioritization scoring.

The score is designed for research and analyst triage.

It estimates how much attention an IOC should receive
based on available evidence and context.

It does NOT determine whether an IOC is malicious.
"""

from typing import Optional


def calculate_source_evidence_score(
    source_count: int
) -> float:
    """
    Score the amount of cross-source evidence.

    0 sources  -> 0
    1 source   -> 15
    2 sources  -> 25
    3 sources  -> 32
    4+ sources -> 40
    """

    if source_count <= 0:
        return 0.0

    if source_count == 1:
        return 15.0

    if source_count == 2:
        return 25.0

    if source_count == 3:
        return 32.0

    return 40.0


def calculate_ioc_type_score(
    ioc_type: str
) -> float:
    """
    Assign a project-defined triage weight
    according to IOC type.

    Maximum: 15 points.
    """

    weights = {
        "url": 15.0,
        "domain": 13.0,
        "ip": 12.0,
        "sha256": 10.0,
        "sha1": 9.0,
        "md5": 8.0
    }

    return weights.get(
        ioc_type.lower(),
        5.0
    )


def calculate_enrichment_score(
    enrichment: Optional[dict] = None
) -> float:
    """
    Score useful external enrichment context.

    Maximum: 20 points.

    RDAP success provides registration context.
    Other enrichment providers can be added later.
    """

    if not enrichment:
        return 0.0

    score = 0.0

    rdap_status = enrichment.get(
        "rdap_status"
    )

    if rdap_status == "success":

        score += 10.0

        if enrichment.get("name"):
            score += 5.0

        if enrichment.get("entities"):
            score += 5.0

    return min(
        score,
        20.0
    )


def calculate_attack_evidence_score(
    attack_mappings: Optional[list] = None
) -> float:
    """
    Score behavioral evidence mapped to
    MITRE ATT&CK.

    Maximum: 25 points.

    Mapping confidence contributes to the score,
    while multiple distinct techniques provide
    additional evidence.
    """

    if not attack_mappings:
        return 0.0

    valid_mappings = [
        mapping
        for mapping in attack_mappings
        if isinstance(mapping, dict)
    ]

    if not valid_mappings:
        return 0.0

    confidence_values = []

    technique_ids = set()

    for mapping in valid_mappings:

        confidence = mapping.get(
            "mapping_confidence",
            0.0
        )

        try:
            confidence = float(
                confidence
            )
        except (
            TypeError,
            ValueError
        ):
            confidence = 0.0

        confidence = max(
            0.0,
            min(
                confidence,
                1.0
            )
        )

        confidence_values.append(
            confidence
        )

        technique_id = mapping.get(
            "technique_id"
        )

        if technique_id:
            technique_ids.add(
                technique_id
            )

    if not confidence_values:
        return 0.0

    average_confidence = (
        sum(confidence_values)
        / len(confidence_values)
    )

    confidence_score = (
        average_confidence * 20.0
    )

    technique_bonus = min(
        len(technique_ids) * 2.5,
        5.0
    )

    return min(
        confidence_score + technique_bonus,
        25.0
    )


def calculate_research_priority(
    ioc_type: str,
    source_count: int,
    enrichment: Optional[dict] = None,
    attack_mappings: Optional[list] = None
) -> dict:
    """
    Calculate the complete transparent
    research prioritization score.

    Maximum = 100 points.

    Components:

        Cross-source evidence : 40
        IOC type              : 15
        Enrichment            : 20
        ATT&CK evidence       : 25
        --------------------------------
        Total                 : 100
    """

    source_score = (
        calculate_source_evidence_score(
            source_count
        )
    )

    ioc_type_score = (
        calculate_ioc_type_score(
            ioc_type
        )
    )

    enrichment_score = (
        calculate_enrichment_score(
            enrichment
        )
    )

    attack_score = (
        calculate_attack_evidence_score(
            attack_mappings
        )
    )

    total_score = (
        source_score
        + ioc_type_score
        + enrichment_score
        + attack_score
    )

    total_score = round(
        min(
            total_score,
            100.0
        ),
        2
    )

    if total_score >= 70:
        priority = "High"

    elif total_score >= 40:
        priority = "Medium"

    else:
        priority = "Low"

    return {
        "score": total_score,
        "priority": priority,
        "components": {
            "source_evidence": source_score,
            "ioc_type": ioc_type_score,
            "enrichment": enrichment_score,
            "attack_evidence": attack_score
        }
    }