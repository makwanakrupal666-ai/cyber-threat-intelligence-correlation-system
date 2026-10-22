from backend.normalizers.ioc_normalizer import normalize_domain
from backend.normalizers.ioc_normalizer import normalize_ip


def deduplicate(values):
    """
    Remove duplicate values while preserving their original order.
    """

    return list(dict.fromkeys(values))


def normalize_and_deduplicate_domains(domains):
    """
    Normalize domain names and remove duplicates.
    """

    normalized_domains = [
        normalize_domain(domain)
        for domain in domains
    ]

    return deduplicate(normalized_domains)


def normalize_and_deduplicate_ips(ips):
    """
    Normalize IPv4 addresses and remove duplicates.
    """

    normalized_ips = [
        normalize_ip(ip)
        for ip in ips
    ]

    return deduplicate(normalized_ips)

from backend.normalizers.ioc_normalizer import normalize_hash


def normalize_and_deduplicate_hashes(hashes):
    """
    Normalize hash values and remove duplicates.
    """

    normalized_hashes = [
        normalize_hash(hash_value)
        for hash_value in hashes
    ]

    return deduplicate(normalized_hashes)

from backend.normalizers.ioc_normalizer import normalize_url


def normalize_and_deduplicate_urls(urls):
    """
    Normalize URLs and remove duplicates.
    """

    normalized_urls = [
        normalize_url(url)
        for url in urls
    ]

    return deduplicate(normalized_urls)