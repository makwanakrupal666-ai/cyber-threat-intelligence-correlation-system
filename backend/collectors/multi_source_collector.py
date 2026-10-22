"""Concurrent, evidence-preserving collection from configured public CTI feeds."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from backend.collectors.source_registry import SOURCE_CATALOG, source_catalog_summary
from backend.extractors.ioc_extractor import extract_all_entities, extract_ips
from backend.normalizers.ioc_normalizer import normalize_entity, normalize_ip
from backend.models.ioc_model import IOCRecord

# Public feeds enabled for live collection. Catalog entries that need keys or
# are metadata/datasets remain documented but are not fetched as plain feeds.
SOURCE_FEEDS = {
    item["name"]: {"url": item["url"], "types": item.get("types", ["ip"])}
    for item in SOURCE_CATALOG
    if item.get("enabled")
}
MAX_RECORDS_PER_SOURCE = 250
FETCH_TIMEOUT_SECONDS = 8


def fetch_feed(url, timeout=FETCH_TIMEOUT_SECONDS, max_bytes=2_000_000):
    request = Request(url, headers={"User-Agent": "CTI-Research-Collector/2.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            chunks, total = [], 0
            while total < max_bytes:
                chunk = response.read(min(64 * 1024, max_bytes - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace")
    except HTTPError as error:
        raise RuntimeError(f"Feed returned HTTP {error.code}") from error
    except URLError as error:
        raise RuntimeError(f"Unable to reach feed: {error.reason}") from error
    except TimeoutError as error:
        raise RuntimeError("Feed request timed out") from error


def _evidence(source_name, url, method):
    return [{
        "source": source_name,
        "source_url": url,
        "method": method,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }]


def collect_ip_feed(source_name, url, max_records=MAX_RECORDS_PER_SOURCE):
    """Collect validated IP literals from a text feed with explicit provenance."""
    ips = list(dict.fromkeys(normalize_ip(ip) for ip in extract_ips(fetch_feed(url))))[:max_records]
    evidence = _evidence(source_name, url, "ip_feed")
    return [
        IOCRecord(
            ioc_type="ip",
            ioc_value=ip,
            source_url=url,
            source_name=source_name,
            sources=[source_name],
            evidence=evidence,
            metadata={"collection_format": "ip_feed"},
        )
        for ip in ips
    ]


def collect_entity_feed(
    source_name,
    url,
    allowed_types=None,
    max_records=MAX_RECORDS_PER_SOURCE,
):
    """Extract only source-declared entity types and retain source provenance."""
    text = fetch_feed(url)
    entities = extract_all_entities(text)
    allowed = set(allowed_types or entities.keys())
    if "hash" in allowed:
        allowed.update({"md5", "sha1", "sha256"})
    records = []
    evidence = _evidence(source_name, url, "typed_regex_feed_extractor")
    for entity_type, values in entities.items():
        if entity_type not in allowed:
            continue
        for value in values:
            normalized = normalize_entity(entity_type, value)
            if not normalized:
                continue
            records.append(
                IOCRecord(
                    ioc_type=entity_type,
                    ioc_value=normalized,
                    source_url=url,
                    source_name=source_name,
                    sources=[source_name],
                    evidence=evidence,
                    metadata={"collection_format": "text_or_structured_text"},
                )
            )
            if len(records) >= max_records:
                return records
    return records


def _collect_one(source_name, config):
    url = config["url"]
    allowed_types = config.get("types", ["ip"])
    if set(allowed_types) == {"ip"}:
        records = collect_ip_feed(source_name, url)
    else:
        records = collect_entity_feed(source_name, url, allowed_types=allowed_types)
    types_found = sorted({record.ioc_type for record in records})
    return {
        "source_name": source_name,
        "source_url": url,
        "status": "success",
        "ioc_count": len(records),
        "types": types_found or allowed_types,
    }, records


def collect_all_sources():
    """Collect configured public feeds concurrently and report each failure honestly."""
    all_records = []
    source_results = []
    items = list(SOURCE_FEEDS.items())

    # Bounded concurrency avoids serial timeout delays while keeping the demo
    # polite to public providers. map/as_completed results are reordered below.
    results_by_name = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_collect_one, name, config): name
            for name, config in items
        }
        for future in as_completed(futures):
            name = futures[future]
            config = SOURCE_FEEDS[name]
            try:
                source_result, records = future.result()
                results_by_name[name] = (source_result, records)
            except Exception as error:
                results_by_name[name] = ({
                    "source_name": name,
                    "source_url": config["url"],
                    "status": "error",
                    "error": str(error),
                    "ioc_count": 0,
                    "types": config.get("types", []),
                }, [])

    for name, _config in items:
        source_result, records = results_by_name[name]
        source_results.append(source_result)
        all_records.extend(records)

    return {
        "sources": source_results,
        "records": all_records,
        "catalog": source_catalog_summary(),
    }
