from backend.enrichment.rdap_enricher import enrich_ip


def enrich_ioc(ioc_type, ioc_value):
    """
    Enrich a single IOC using the appropriate
    enrichment provider.

    Currently IP enrichment is supported through RDAP.
    """

    if ioc_type == "ip":
        return enrich_ip(ioc_value)

    return {
        "status": "unsupported",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "message": (
            f"No enrichment provider configured "
            f"for IOC type '{ioc_type}'."
        )
    }