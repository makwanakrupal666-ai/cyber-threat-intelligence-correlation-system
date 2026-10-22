import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


RDAP_BASE_URL = "https://rdap.org/ip/"


def fetch_rdap(ip, timeout=8):
    """
    Fetch structured RDAP information for an IP address.

    RDAP data is treated as external/untrusted information.
    No returned content is executed.
    """

    url = f"{RDAP_BASE_URL}{ip}"

    request = Request(
        url,
        headers={
            "User-Agent": "CTI-Research-Enricher/1.0",
            "Accept": "application/rdap+json, application/json"
        }
    )

    try:

        with urlopen(
            request,
            timeout=timeout
        ) as response:

            raw_data = response.read()

            return json.loads(
                raw_data.decode(
                    "utf-8",
                    errors="replace"
                )
            )

    except HTTPError as error:

        raise RuntimeError(
            f"RDAP returned HTTP {error.code}"
        ) from error

    except URLError as error:

        raise RuntimeError(
            f"Unable to reach RDAP service: {error.reason}"
        ) from error

    except TimeoutError as error:

        raise RuntimeError(
            "RDAP request timed out"
        ) from error

    except json.JSONDecodeError as error:

        raise RuntimeError(
            "RDAP returned invalid JSON"
        ) from error


def extract_entity_name(entity):
    """
    Extract a useful name from an RDAP entity object.
    """

    vcard_array = entity.get(
        "vcardArray"
    )

    if not isinstance(
        vcard_array,
        list
    ) or len(vcard_array) < 2:

        return None

    properties = vcard_array[1]

    for property_item in properties:

        if not isinstance(
            property_item,
            list
        ):

            continue

        if len(property_item) < 4:

            continue

        property_name = property_item[0]
        property_value = property_item[3]

        if property_name in (
            "fn",
            "org"
        ):

            if isinstance(
                property_value,
                str
            ):

                return property_value

    return None


def extract_rdap_summary(data):
    """
    Convert a raw RDAP response into a small,
    dashboard-friendly enrichment object.
    """

    summary = {
        "rdap_status": "success",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "start_address": data.get(
            "startAddress"
        ),
        "end_address": data.get(
            "endAddress"
        ),
        "entities": []
    }

    entities = data.get(
        "entities",
        []
    )

    for entity in entities:

        entity_name = extract_entity_name(
            entity
        )

        if entity_name and entity_name not in summary[
            "entities"
        ]:

            summary["entities"].append(
                entity_name
            )

    return summary


def enrich_ip(ip):
    """
    Enrich an IP address with RDAP registration context.

    Returns a structured result even when enrichment
    is unavailable, so enrichment failure does not
    stop CTI processing.
    """

    try:

        data = fetch_rdap(ip)

        return extract_rdap_summary(
            data
        )

    except Exception as error:

        return {
            "rdap_status": "error",
            "error": str(error)
        }