import time
from datetime import datetime, timezone

from backend.processors.multi_source_pipeline import process_all_sources
from backend.database.mongodb import (
    DATABASE_NAME,
    get_collection_runs_collection,
    upsert_source,
)

def utc_now():
    return datetime.now(timezone.utc)

def process_and_record_collection():
    started_at = utc_now()
    timer_started = time.perf_counter()

    result = process_all_sources()

    processing_time_seconds = round(time.perf_counter() - timer_started, 4)
    completed_at = utc_now()

    raw_count = int(result.get("collected_count", 0))
    unique_after_correlation = int(result.get("correlated_count", 0))
    overlap_removed = max(raw_count - unique_after_correlation, 0)
    reduction = round((overlap_removed / raw_count) * 100, 2) if raw_count else 0.0
    throughput = round(raw_count / processing_time_seconds, 2) if processing_time_seconds > 0 else 0.0

    source_results = result.get("sources", [])
    for source in source_results:
        source_name = source.get("source_name", "unknown")
        source_url = source.get("source_url", "")
        upsert_source(
            source_name,
            source_url,
            status=source.get("status", "unknown"),
            records_collected=int(source.get("ioc_count", 0)),
            last_collected=completed_at,
        )

    cross_source_matches = sum(
        1 for record in result.get("records", [])
        if len(set(record.sources)) >= 2
    )

    source_statuses = [source.get("status") for source in source_results]
    if source_statuses and all(status == "success" for status in source_statuses):
        run_status = "success"
    elif any(status == "success" for status in source_statuses):
        run_status = "partial"
    else:
        run_status = "failed"

    run_document = {
        "started_at": started_at,
        "completed_at": completed_at,
        "status": run_status,
        "source_count": len(source_results),
        "sources": source_results,
        "raw_iocs": raw_count,
        "unique_after_correlation": unique_after_correlation,
        "overlap_or_duplicates_removed": overlap_removed,
        "duplicate_reduction_percent": reduction,
        "cross_source_matches": cross_source_matches,
        "saved_new_records": int(result.get("saved_count", 0)),
        "processing_time_seconds": processing_time_seconds,
        "throughput_records_per_second": throughput,
    }

    run_id = get_collection_runs_collection().insert_one(run_document).inserted_id

    return {
        **result,
        "status": run_status,
        "run_id": str(run_id),
        "database": DATABASE_NAME,
        "evaluation": {
            "recorded_at": completed_at.isoformat(),
            "raw_iocs": raw_count,
            "unique_after_correlation": unique_after_correlation,
            "overlap_or_duplicates_removed": overlap_removed,
            "duplicate_reduction_percent": reduction,
            "cross_source_matches": cross_source_matches,
            "saved_new_records": int(result.get("saved_count", 0)),
            "source_count": len(source_results),
            "processing_time_seconds": processing_time_seconds,
            "throughput_records_per_second": throughput,
        },
    }
