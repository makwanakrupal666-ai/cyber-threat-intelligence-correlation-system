import time

from backend.enrichment.rdap_enricher import enrich_ip


VALIDATION_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "101.126.130.65",
]


def evaluate_rdap_enrichment():
    """Measure the configured RDAP provider on a small fixed public-IP set.

    This is an online service evaluation, not a ground-truth accuracy test.
    Success means the provider returned valid RDAP data that the project
    successfully summarized.
    """
    results = []
    success_count = 0
    total = len(VALIDATION_IPS)
    started = time.perf_counter()

    for ip in VALIDATION_IPS:
        case_started = time.perf_counter()
        result = enrich_ip(ip)
        elapsed = round(time.perf_counter() - case_started, 4)
        success = result.get("rdap_status") == "success"
        if success:
            success_count += 1
        results.append({
            "ip": ip,
            "success": success,
            "status": result.get("rdap_status"),
            "name_present": bool(result.get("name")),
            "entities_present": bool(result.get("entities")),
            "elapsed_seconds": elapsed,
            "error": result.get("error"),
        })

    total_seconds = round(time.perf_counter() - started, 4)
    success_rate = (success_count / total * 100) if total else 0.0

    return {
        "dataset_name": "Project Curated Public IP RDAP Service Evaluation",
        "dataset_version": "1.0",
        "dataset_cases": total,
        "successful_enrichments": success_count,
        "failed_enrichments": total - success_count,
        "success_rate": round(success_rate, 2),
        "total_processing_time_seconds": total_seconds,
        "evaluation_scope": "online RDAP response and project summary extraction",
        "dataset_status": "fixed public-IP evaluation set",
        "accuracy_claim": False,
        "limitation": "This measures RDAP service/processing success; it does not establish factual accuracy against an independent ground truth.",
        "case_results": results,
    }
