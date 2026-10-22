import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def _unique(values):
    return list(dict.fromkeys(values))


def extract_ips(text):
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    result = []
    for value in candidates:
        try:
            ipaddress.ip_address(value)
            result.append(value)
        except ValueError:
            continue
    return _unique(result)


def extract_ipv6(text):
    values = []
    for candidate in re.findall(r"(?<![\w:])([0-9A-Fa-f:]{2,45})(?![\w:])", text):
        if ":" in candidate:
            try:
                if ipaddress.ip_address(candidate).version == 6:
                    values.append(candidate)
            except ValueError:
                pass
    return _unique(values)


def extract_urls(text):
    return _unique([url.rstrip(".,;:!?)]}") for url in re.findall(r"https?://[^\s<>\"']+", text)])


def extract_domains(text):
    text_without_urls = re.sub(r"https?://[^\s<>\"']+", " ", text)
    return _unique(re.findall(r"(?<![@\w-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w-])", text_without_urls))


def extract_md5(text):
    return _unique(re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text))


def extract_sha1(text):
    return _unique(re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text))


def extract_sha256(text):
    return _unique(re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])", text))


def extract_emails(text):
    return _unique(re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I))


def extract_cves(text):
    return _unique(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I))


def extract_attack_techniques(text):
    return _unique(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.I))


def extract_named_entities(text):
    """Extract explicitly labelled CTI entities without pretending NLP certainty."""
    patterns = {
        "malware": r"(?:malware|family|ransomware)\s*[:=]\s*([A-Za-z][\w.-]{2,50})",
        "threat_actor": r"(?:threat actor|actor|group)\s*[:=]\s*([A-Za-z][\w .-]{2,50})",
        "campaign": r"(?:campaign)\s*[:=]\s*([A-Za-z][\w .-]{2,50})",
        "file_name": r"(?:file|filename|file name)\s*[:=]\s*([\w.-]{2,120})",
    }
    return {kind: _unique(re.findall(pattern, text, re.I)) for kind, pattern in patterns.items()}


def extract_all_entities(text):
    """Return typed entities plus provenance spans for downstream fusion."""
    named = extract_named_entities(text)
    entities = {
        "ip": extract_ips(text) + extract_ipv6(text),
        "domain": extract_domains(text),
        "url": extract_urls(text),
        "md5": extract_md5(text),
        "sha1": extract_sha1(text),
        "sha256": extract_sha256(text),
        "email": extract_emails(text),
        "cve": [value.upper() for value in extract_cves(text)],
        "attack_technique": [value.upper() for value in extract_attack_techniques(text)],
        **named,
    }
    return {kind: _unique(values) for kind, values in entities.items() if values}


def extract_all_iocs(text):
    """Compatibility-friendly alias used by processors and feed adapters."""
    return extract_all_entities(text)
