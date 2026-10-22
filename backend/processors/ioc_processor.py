from backend.extractors.ioc_extractor import extract_all_entities
from backend.normalizers.ioc_normalizer import normalize_entity
from backend.models.ioc_model import create_ioc_record


def extract_all_iocs(text):
    """Extract, normalize, deduplicate, and structure heterogeneous CTI entities.

    The plural keys for the original six IOC types are retained for API/test
    compatibility; newer entity classes use their canonical type names.
    """
    entities = extract_all_entities(text)
    legacy_names = {"ip": "ips", "domain": "domains", "url": "urls", "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
    result = {}
    for entity_type, values in entities.items():
        canonical = list(dict.fromkeys(normalize_entity(entity_type, value) for value in values))
        key = legacy_names.get(entity_type, entity_type)
        result[key] = [create_ioc_record(entity_type, value) for value in canonical]
    return result
