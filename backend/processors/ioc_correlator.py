from collections import defaultdict


def _merge_unique_dicts(items):
    seen, result = set(), []
    for item in items:
        key = repr(sorted(item.items())) if isinstance(item, dict) else repr(item)
        if key not in seen:
            seen.add(key); result.append(item)
    return result


def correlate_iocs(records):
    groups = defaultdict(list)
    for record in records:
        key = (record.ioc_type, record.ioc_value)
        groups[key].append(record)

    correlated = []
    for grouped in groups.values():
        primary = grouped[0]
        primary.sources = list(dict.fromkeys(source for record in grouped for source in record.sources))
        primary.source_reliability = {source: 1.0 for source in primary.sources}
        primary.tags = list(dict.fromkeys(tag for record in grouped for tag in getattr(record, "tags", [])))
        primary.relationships = _merge_unique_dicts(rel for record in grouped for rel in getattr(record, "relationships", []))
        primary.evidence = _merge_unique_dicts(ev for record in grouped for ev in getattr(record, "evidence", []))
        primary.first_seen = min((record.first_seen for record in grouped if getattr(record, "first_seen", None)), default=primary.first_seen)
        primary.last_seen = max((record.last_seen for record in grouped if getattr(record, "last_seen", None)), default=primary.last_seen)
        primary.metadata = {k: v for record in grouped for k, v in getattr(record, "metadata", {}).items()}
        correlated.append(primary)
    return correlated


def calculate_confidence(source_count):
    if source_count <= 0:
        return 0
    return min(20 + (source_count * 20), 100)


def calculate_priority(confidence, ioc_type):
    type_weight = {"ip": 1.0, "domain": 1.0, "url": 1.1, "md5": .9, "sha1": .9, "sha256": .9}
    return round(min(confidence * type_weight.get(ioc_type, 1.0), 100), 2)


def classify_priority(priority_score):
    if priority_score >= 80: return "High"
    if priority_score >= 50: return "Medium"
    return "Low"
