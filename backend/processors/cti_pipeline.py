from urllib.parse import urlparse

from backend.collectors.cti_collector import fetch_cti_text
from backend.database.mongodb import save_ioc_records
from backend.processors.ioc_processor import extract_all_iocs


def flatten_ioc_records(ioc_result):
    """
    Convert the processor's dictionary of IOC lists
    into one flat list of IOCRecord objects.
    """

    records = []

    for ioc_type_records in ioc_result.values():
        records.extend(ioc_type_records)

    return records


def get_source_name(url):
    """
    Extract a readable source name from a URL.
    """

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname

    if not hostname:
        return "unknown"

    return hostname.lower()


def add_source_metadata(records, source_url):
    """
    Attach source information to every IOC record.
    """

    source_name = get_source_name(
        source_url
    )

    for record in records:

        record.source_url = source_url
        record.source_name = source_name

        if source_name not in record.sources:
            record.sources.append(
                source_name
            )

    return records


def process_cti_url(url):
    """
    Fetch CTI from a public URL, extract IOCs,
    attach source metadata, and save the results.
    """

    source = fetch_cti_text(url)

    ioc_result = extract_all_iocs(
        source["text"]
    )

    records = flatten_ioc_records(
        ioc_result
    )

    records = add_source_metadata(
        records,
        source["url"]
    )

    saved_count = save_ioc_records(
        records
    )

    return {
        "source_url": source["url"],
        "source_name": get_source_name(
            source["url"]
        ),
        "content_type": source["content_type"],
        "ioc_count": len(records),
        "saved_count": saved_count,
        "records": records
    }