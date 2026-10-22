from urllib.parse import urlsplit, urlunsplit


def normalize_ip(value):
    return value.strip()


def normalize_domain(value):
    return value.strip().lower().rstrip(".")


def normalize_url(value):
    return value.strip().rstrip(".")


def normalize_hash(value):
    return value.strip().lower()


def normalize_email(value):
    return value.strip().lower()


def normalize_cve(value):
    return value.strip().upper()


def normalize_attack(value):
    return value.strip().upper()


def normalize_entity(ioc_type, value):
    if ioc_type in {"domain", "malware", "threat_actor", "campaign", "file_name"}:
        return value.strip().lower()
    if ioc_type == "url":
        return normalize_url(value)
    if ioc_type == "email":
        return normalize_email(value)
    if ioc_type == "cve":
        return normalize_cve(value)
    if ioc_type == "attack_technique":
        return normalize_attack(value)
    return normalize_hash(value) if ioc_type in {"md5", "sha1", "sha256"} else normalize_ip(value)
