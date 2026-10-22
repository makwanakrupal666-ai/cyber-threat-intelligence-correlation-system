from backend.processors.priority_scorer import calculate_research_priority


def evaluate_priority_consistency():
    scenarios = [
        {
            "name": "same input is deterministic",
            "ioc_type": "ip",
            "source_count": 2,
            "enrichment": None,
            "attack_mappings": [],
            "expected_same_output": True,
        },
        {
            "name": "more source evidence does not reduce source score",
            "ioc_type": "ip",
            "source_count": 1,
            "enrichment": None,
            "attack_mappings": [],
            "compare_source_counts": [1, 2, 3, 4],
            "expected_monotonic": True,
        },
        {
            "name": "valid enrichment adds evidence",
            "ioc_type": "ip",
            "source_count": 1,
            "enrichment": None,
            "attack_mappings": [],
            "compare_enrichment": True,
            "expected_increase": True,
        },
        {
            "name": "ATT&CK evidence adds score when supplied",
            "ioc_type": "ip",
            "source_count": 1,
            "enrichment": None,
            "attack_mappings": [],
            "compare_attack": True,
            "expected_increase": True,
        },
    ]

    results = []

    # 1. Determinism
    base = scenarios[0]
    first = calculate_research_priority(
        base["ioc_type"], base["source_count"],
        base["enrichment"], base["attack_mappings"]
    )
    second = calculate_research_priority(
        base["ioc_type"], base["source_count"],
        base["enrichment"], base["attack_mappings"]
    )
    results.append({
        "name": base["name"],
        "passed": first == second,
        "first": first,
        "second": second,
    })

    # 2. Source evidence monotonicity
    values = []
    for count in scenarios[1]["compare_source_counts"]:
        result = calculate_research_priority("ip", count, None, [])
        values.append(result["score"])
    passed = all(a <= b for a, b in zip(values, values[1:]))
    results.append({
        "name": scenarios[1]["name"],
        "passed": passed,
        "source_counts": scenarios[1]["compare_source_counts"],
        "scores": values,
    })

    # 3. Enrichment evidence
    without_enrichment = calculate_research_priority("ip", 1, None, [])
    valid_enrichment = {
        "rdap_status": "success",
        "name": "Example Organization",
        "entities": ["Example Entity"],
    }
    with_enrichment = calculate_research_priority(
        "ip", 1, valid_enrichment, []
    )
    passed = with_enrichment["score"] > without_enrichment["score"]
    results.append({
        "name": scenarios[2]["name"],
        "passed": passed,
        "without_enrichment": without_enrichment["score"],
        "with_enrichment": with_enrichment["score"],
    })

    # 4. ATT&CK evidence
    attack_mapping = [{
        "technique_id": "T1059.001",
        "mapping_confidence": 0.9,
    }]
    without_attack = calculate_research_priority("ip", 1, None, [])
    with_attack = calculate_research_priority(
        "ip", 1, None, attack_mapping
    )
    passed = with_attack["score"] > without_attack["score"]
    results.append({
        "name": scenarios[3]["name"],
        "passed": passed,
        "without_attack": without_attack["score"],
        "with_attack": with_attack["score"],
    })

    passed_cases = sum(1 for result in results if result["passed"])

    return {
        "dataset_name": "Project Curated Priority Consistency Scenarios",
        "dataset_version": "1.0",
        "dataset_cases": len(results),
        "passed_cases": passed_cases,
        "consistency_rate": round(
            passed_cases / len(results), 4
        ) if results else 0.0,
        "evaluation_scope": (
            "determinism and monotonic evidence-property checks; "
            "not maliciousness accuracy"
        ),
        "dataset_status": "fixed deterministic property-test scenarios",
        "case_results": results,
    }
