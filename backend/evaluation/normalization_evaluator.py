import json
from pathlib import Path

from backend.normalizers.ioc_normalizer import (
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from backend.deduplicators.ioc_deduplicator import deduplicate


VALIDATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "test"
    / "normalization_validation.json"
)


def _load_dataset():
    with open(VALIDATION_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def _normalize_values(values, ioc_type):
    if ioc_type == "domain":
        normalized = [normalize_domain(value) for value in values]
    elif ioc_type == "ip":
        normalized = [normalize_ip(value) for value in values]
    elif ioc_type == "url":
        normalized = [normalize_url(value) for value in values]
    elif ioc_type == "hash":
        normalized = [normalize_hash(value) for value in values]
    else:
        normalized = values

    return deduplicate(normalized)


def evaluate_normalization():
    dataset = _load_dataset()

    if not isinstance(dataset, list):
        raise ValueError(
            "Normalization validation dataset must be a JSON list."
        )

    total_input = 0
    total_expected_unique = 0
    total_correct = 0

    case_results = []

    for index, case in enumerate(dataset, start=1):
        inputs = case.get("input", {})
        expected = case.get("expected_unique", {})

        predicted = {}

        # Domains
        if "domains" in inputs:
            predicted["domains"] = _normalize_values(
                inputs["domains"],
                "domain"
            )

        # IPs
        if "ips" in inputs:
            predicted["ips"] = _normalize_values(
                inputs["ips"],
                "ip"
            )

        # URLs
        if "urls" in inputs:
            predicted["urls"] = _normalize_values(
                inputs["urls"],
                "url"
            )

        # Hashes
        if "hashes" in inputs:
            predicted["hashes"] = _normalize_values(
                inputs["hashes"],
                "hash"
            )

        case_input_count = sum(
            len(values)
            for values in inputs.values()
        )

        case_expected_count = sum(
            len(values)
            for values in expected.values()
        )

        case_correct = 0

        for field_name, expected_values in expected.items():
            predicted_values = predicted.get(
                field_name,
                []
            )

            expected_set = set(expected_values)
            predicted_set = set(predicted_values)

            case_correct += len(
                expected_set & predicted_set
            )

        total_input += case_input_count
        total_expected_unique += case_expected_count
        total_correct += case_correct

        duplicate_removed = (
            case_input_count - len(
                [
                    value
                    for values in predicted.values()
                    for value in values
                ]
            )
        )

        case_results.append(
            {
                "id": index,
                "name": case.get("name", f"Case {index}"),
                "input_count": case_input_count,
                "expected_unique_count": case_expected_count,
                "predicted_unique_count": sum(
                    len(values)
                    for values in predicted.values()
                ),
                "correct_normalized_values": case_correct,
                "duplicates_removed": duplicate_removed,
                "passed": predicted == expected,
            }
        )

    total_predicted_unique = sum(
        result["predicted_unique_count"]
        for result in case_results
    )

    total_duplicates_removed = (
        total_input - total_predicted_unique
    )

    normalization_accuracy = (
        total_correct / total_expected_unique
        if total_expected_unique
        else 0.0
    )

    duplicate_reduction = (
        total_duplicates_removed / total_input
        if total_input
        else 0.0
    )

    passed_cases = sum(
        1
        for result in case_results
        if result["passed"]
    )

    return {
        "dataset_name": "Project Curated Normalization Validation Dataset",
        "dataset_version": "1.0",
        "dataset_cases": len(dataset),
        "passed_cases": passed_cases,
        "total_input_values": total_input,
        "total_expected_unique_values": total_expected_unique,
        "total_predicted_unique_values": total_predicted_unique,
        "correct_normalized_values": total_correct,
        "duplicates_removed": total_duplicates_removed,
        "normalization_accuracy": round(
            normalization_accuracy,
            4
        ),
        "duplicate_reduction": round(
            duplicate_reduction * 100,
            2
        ),
        "evaluation_scope": (
            "exact normalized value and deduplication match"
        ),
        "dataset_status": (
            "project-curated labelled validation set"
        ),
        "case_results": case_results,
    }