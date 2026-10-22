"""
MITRE ATT&CK evidence-based mapper.

The mapper:
1. Loads the official MITRE ATT&CK Enterprise STIX dataset.
2. Builds an index of ATT&CK techniques.
3. Searches CTI behavior text using transparent rules.
4. Returns technique metadata and supporting evidence.

Important:
An IOC itself is NOT automatically mapped to an ATT&CK
technique. Mapping requires behavioral evidence.
"""

import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from backend.attack.attack_rules import ATTACK_RULES


# ============================================================
# CONFIGURATION
# ============================================================

ATTACK_DATA_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ATTACK_DATA_DIRECTORY = (
    PROJECT_ROOT / "data" / "attack"
)

ATTACK_DATA_PATH = (
    ATTACK_DATA_DIRECTORY / "enterprise-attack.json"
)


# ============================================================
# DOWNLOAD MITRE ATT&CK DATA
# ============================================================

def download_attack_data(
    timeout=30,
    max_bytes=150_000_000
):
    """
    Download the Enterprise ATT&CK STIX dataset.

    Downloaded content is treated as untrusted JSON data.
    Nothing from the dataset is executed.
    """

    request = Request(
        ATTACK_DATA_URL,
        headers={
            "User-Agent": "CTI-Research-ATTACK-Loader/1.0",
            "Accept": "application/json"
        }
    )

    try:
        with urlopen(
            request,
            timeout=timeout
        ) as response:

            chunks = []
            total_bytes = 0

            while True:

                chunk = response.read(
                    64 * 1024
                )

                if not chunk:
                    break

                remaining = (
                    max_bytes - total_bytes
                )

                if remaining <= 0:
                    raise RuntimeError(
                        "MITRE ATT&CK dataset exceeds "
                        "the configured size limit."
                    )

                if len(chunk) > remaining:
                    chunk = chunk[:remaining]

                chunks.append(chunk)

                total_bytes += len(chunk)

                if total_bytes >= max_bytes:
                    raise RuntimeError(
                        "MITRE ATT&CK dataset exceeds "
                        "the configured size limit."
                    )

            raw_data = b"".join(chunks)

            return raw_data.decode(
                "utf-8",
                errors="replace"
            )

    except HTTPError as error:
        raise RuntimeError(
            f"MITRE ATT&CK download returned HTTP {error.code}"
        ) from error

    except URLError as error:
        raise RuntimeError(
            f"Unable to reach MITRE ATT&CK data: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise RuntimeError(
            "MITRE ATT&CK download timed out."
        ) from error


# ============================================================
# SAVE MITRE ATT&CK DATA
# ============================================================

def save_attack_data(raw_text):
    """
    Validate and save ATT&CK JSON locally.
    """

    try:
        data = json.loads(raw_text)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "MITRE ATT&CK response was not valid JSON."
        ) from error

    if not isinstance(data, dict):
        raise RuntimeError(
            "MITRE ATT&CK dataset has an invalid structure."
        )

    if not isinstance(
        data.get("objects"),
        list
    ):
        raise RuntimeError(
            "MITRE ATT&CK dataset does not contain "
            "a valid STIX objects list."
        )

    ATTACK_DATA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        ATTACK_DATA_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2
        )

    return data


# ============================================================
# LOAD MITRE ATT&CK DATA
# ============================================================

def load_attack_data(
    force_refresh=False
):
    """
    Load the local ATT&CK dataset.

    If the local dataset does not exist,
    download it from MITRE.
    """

    if (
        ATTACK_DATA_PATH.exists()
        and not force_refresh
    ):

        try:
            with open(
                ATTACK_DATA_PATH,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if (
                isinstance(data, dict)
                and isinstance(
                    data.get("objects"),
                    list
                )
            ):
                return data

        except (
            OSError,
            json.JSONDecodeError
        ):
            pass

    raw_text = download_attack_data()

    return save_attack_data(
        raw_text
    )


# ============================================================
# BUILD TECHNIQUE INDEX
# ============================================================

def build_technique_index(data):
    """
    Build an index such as:

        T1059.001 -> ATT&CK technique object

    Only valid Enterprise ATT&CK attack-pattern
    objects are included.
    """

    techniques = {}

    for obj in data.get(
        "objects",
        []
    ):

        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked", False):
            continue

        if obj.get(
            "x_mitre_deprecated",
            False
        ):
            continue

        external_references = obj.get(
            "external_references",
            []
        )

        for reference in external_references:

            source_name = reference.get(
                "source_name"
            )

            external_id = reference.get(
                "external_id"
            )

            if (
                source_name == "mitre-attack"
                and external_id
                and external_id.startswith("T")
            ):

                techniques[external_id] = obj

                break

    return techniques


# ============================================================
# GET TECHNIQUE METADATA
# ============================================================

def get_technique_metadata(
    technique_object
):
    """
    Convert an ATT&CK STIX attack-pattern object
    into a compact project-friendly structure.
    """

    external_id = None

    for reference in technique_object.get(
        "external_references",
        []
    ):

        if (
            reference.get("source_name")
            == "mitre-attack"
        ):

            candidate = reference.get(
                "external_id"
            )

            if candidate:
                external_id = candidate
                break

    tactics = []

    for phase in technique_object.get(
        "kill_chain_phases",
        []
    ):

        phase_name = phase.get(
            "phase_name"
        )

        if phase_name:
            tactics.append(
                phase_name
            )

    return {
        "technique_id": external_id,
        "name": technique_object.get(
            "name"
        ),
        "description": technique_object.get(
            "description"
        ),
        "tactics": tactics
    }


# ============================================================
# FIND BEHAVIOR RULE MATCHES
# ============================================================

def find_rule_matches(text):
    """
    Find transparent behavioral rule matches
    in CTI text.

    Matching is case-insensitive.
    """

    if not isinstance(
        text,
        str
    ):
        return []

    normalized_text = text.lower()

    matches = []

    for rule in ATTACK_RULES:

        matched_keywords = []

        for keyword in rule.get(
            "keywords",
            []
        ):

            if keyword.lower() in normalized_text:

                matched_keywords.append(
                    keyword
                )

        if matched_keywords:

            matches.append(
                {
                    "technique_id": (
                        rule["technique_id"]
                    ),
                    "matched_keywords": (
                        matched_keywords
                    ),
                    "evidence_type": (
                        rule.get(
                            "evidence_type",
                            "behavior"
                        )
                    ),
                    "rule_confidence": (
                        rule.get(
                            "confidence",
                            0.0
                        )
                    )
                }
            )

    return matches


# ============================================================
# MAP BEHAVIOR TO ATT&CK
# ============================================================

def map_behavior_to_attack(
    text,
    attack_data=None
):
    """
    Map behavioral evidence from CTI text
    to MITRE ATT&CK techniques.

    A mapping requires:

    1. A transparent behavioral rule match.
    2. The technique must exist in the MITRE
       ATT&CK dataset.

    An IOC alone is not mapped to a technique.
    """

    if attack_data is None:
        attack_data = load_attack_data()

    technique_index = build_technique_index(
        attack_data
    )

    rule_matches = find_rule_matches(
        text
    )

    results = []

    seen_ids = set()

    for match in rule_matches:

        technique_id = match[
            "technique_id"
        ]

        if technique_id in seen_ids:
            continue

        technique_object = technique_index.get(
            technique_id
        )

        if not technique_object:
            continue

        metadata = get_technique_metadata(
            technique_object
        )

        results.append(
            {
                "technique_id": technique_id,

                "technique_name": metadata[
                    "name"
                ],

                "tactics": metadata[
                    "tactics"
                ],

                "evidence": {
                    "matched_keywords": match[
                        "matched_keywords"
                    ],
                    "evidence_type": match[
                        "evidence_type"
                    ]
                },

                "mapping_confidence": match[
                    "rule_confidence"
                ],

                "mapping_method": (
                    "transparent_keyword_rule"
                )
            }
        )

        seen_ids.add(
            technique_id
        )

    return results


# ============================================================
# SINGLE TECHNIQUE LOOKUP
# ============================================================

def get_attack_technique(
    technique_id,
    attack_data=None
):
    """
    Look up one ATT&CK technique by ID.
    """

    if attack_data is None:
        attack_data = load_attack_data()

    technique_index = build_technique_index(
        attack_data
    )

    technique_object = technique_index.get(
        technique_id
    )

    if not technique_object:
        return None

    return get_technique_metadata(
        technique_object
    )