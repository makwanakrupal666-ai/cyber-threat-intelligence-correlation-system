import json
from pathlib import Path

from backend.models.ioc_model import IOCRecord
from backend.processors.ioc_correlator import correlate_iocs

VALIDATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "test"
    / "correlation_validation.json"
)


def _load_dataset():
    with open(VALIDATION_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_correlation():
    dataset = _load_dataset()
    if not isinstance(dataset, list):
        raise ValueError("Correlation validation dataset must be a JSON list.")

    passed_cases = 0
    total_groups = 0
    correct_groups = 0
    case_results = []

    for index, case in enumerate(dataset, start=1):
        records = []
        for item in case.get("records", []):
            records.append(
                IOCRecord(
                    ioc_type=item["ioc_type"],
                    ioc_value=item["ioc_value"],
                    sources=[item["source"]],
                    source_name=item["source"],
                )
            )

        correlated = correlate_iocs(records)
        predicted_groups = len(correlated)
        expected_groups = int(case.get("expected_groups", 0))

        predicted_source_counts = sorted(
            len(record.sources) for record in correlated
        )
        expected_source_counts = sorted(
            int(value) for value in case.get("expected_source_counts", [])
        )

        groups_correct = predicted_groups == expected_groups
        source_counts_correct = predicted_source_counts == expected_source_counts
        passed = groups_correct and source_counts_correct

        if passed:
            passed_cases += 1

        total_groups += expected_groups
        if groups_correct:
            correct_groups += expected_groups

        case_results.append(
            {
                "id": index,
                "name": case.get("name", f"Case {index}"),
                "expected_groups": expected_groups,
                "predicted_groups": predicted_groups,
                "expected_source_counts": expected_source_counts,
                "predicted_source_counts": predicted_source_counts,
                "passed": passed,
            }
        )

    case_accuracy = passed_cases / len(dataset) if dataset else 0.0
    group_accuracy = correct_groups / total_groups if total_groups else 0.0

    return {
        "dataset_name": "Project Curated Correlation Validation Dataset",
        "dataset_version": "1.0",
        "dataset_cases": len(dataset),
        "passed_cases": passed_cases,
        "case_accuracy": round(case_accuracy, 4),
        "expected_groups": total_groups,
        "correct_groups": correct_groups,
        "group_accuracy": round(group_accuracy, 4),
        "evaluation_scope": (
            "exact IOC type/value grouping and source-count match"
        ),
        "dataset_status": "project-curated labelled validation set",
        "case_results": case_results,
    }
