from backend.evaluation.ioc_evaluator import evaluate_ioc_extraction


def test_ioc_extraction_evaluation_returns_metrics():
    result = evaluate_ioc_extraction()
    assert result["dataset_cases"] == 10
    assert result["true_positive"] >= 1
    assert 0.0 <= result["precision"] <= 1.0
    assert 0.0 <= result["recall"] <= 1.0
    assert 0.0 <= result["f1"] <= 1.0


def test_ioc_extraction_evaluation_exposes_known_limitations():
    """
    The regex-only baseline extractor is expected to misclassify a
    version-number string such as "1.2.3.4" as an IPv4 address (case V10
    in the validation set). This mirrors the false-positive limitation
    documented in Tang et al. 2024 (AIIOC) for context-free IOC
    extraction, and is exactly the kind of measured weakness this
    project's evaluation harness is meant to surface.
    """
    result = evaluate_ioc_extraction()
    assert result["false_positive"] >= 1
