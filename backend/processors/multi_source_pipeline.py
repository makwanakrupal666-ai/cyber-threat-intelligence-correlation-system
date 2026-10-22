from backend.collectors.multi_source_collector import (
    collect_all_sources
)

from backend.processors.ioc_correlator import (
    correlate_iocs
)

from backend.database.mongodb import (
    save_ioc_records
)


def process_all_sources():
    """
    Collect IOC data from all configured CTI sources,
    correlate duplicate IOCs across sources, and save
    the correlated records.
    """

    collection_result = collect_all_sources()

    records = collection_result["records"]

    correlated_records = correlate_iocs(
        records
    )

    saved_count = save_ioc_records(
        correlated_records
    )

    return {
        "sources": collection_result["sources"],
        "collected_count": len(records),
        "correlated_count": len(correlated_records),
        "saved_count": saved_count,
        "records": correlated_records
    }