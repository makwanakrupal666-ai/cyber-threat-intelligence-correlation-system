import json
from pathlib import Path

from backend.processors.ioc_processor import extract_all_iocs


VALIDATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "test"
    / "ioc_validation.json"
)


TYPE_MAPPING = {
    "ips": "ip",
    "domains": "domain",
    "urls": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}


def _load_dataset():
    with open(VALIDATION_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def _prediction_set(text):
    extracted = extract_all_iocs(text)

    predictions = set()

    for ioc_type, records in extracted.items():
        normalized_type = TYPE_MAPPING.get(ioc_type, ioc_type)

        for record in records:
            predictions.add(
                (normalized_type, record.ioc_value)
            )

    return predictions


def _expected_set(expected):
    expected_set = set()

    for field_name, ioc_type in TYPE_MAPPING.items():
        values = expected.get(field_name, [])

        for value in values:
            expected_set.add(
                (ioc_type, value)
            )

    return expected_set


def evaluate_ioc_extraction():
    dataset = _load_dataset()

    if not isinstance(dataset, list):
        raise ValueError(
            "Validation dataset must be a JSON list of test cases."
        )

    tp = 0
    fp = 0
    fn = 0

    case_results = []

    for index, case in enumerate(dataset, start=1):
        text = case.get("text", "")

        expected = _expected_set(
            case.get("expected", {})
        )

        predicted = _prediction_set(text)

        case_tp = len(expected & predicted)
        case_fp = len(predicted - expected)
        case_fn = len(expected - predicted)

        tp += case_tp
        fp += case_fp
        fn += case_fn

        case_results.append(
            {
                "id": index,
                "true_positive": case_tp,
                "false_positive": case_fp,
                "false_negative": case_fn,
                "expected_count": len(expected),
                "predicted_count": len(predicted),
            }
        )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return {
        "dataset_name": "Project Curated IOC Validation Dataset",
        "dataset_version": "1.0",
        "dataset_cases": len(dataset),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "evaluation_scope": (
            "exact IOC type + normalized IOC value match"
        ),
        "dataset_status": (
            "project-curated labelled validation set"
        ),
        "case_results": case_results,
    }