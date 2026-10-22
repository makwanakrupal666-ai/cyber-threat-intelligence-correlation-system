import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from dotenv import load_dotenv
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("MONGODB_DATABASE", "cti_database")

IOC_COLLECTION_NAME = "iocs"
SOURCES_COLLECTION_NAME = "sources"
COLLECTION_RUNS_COLLECTION_NAME = "collection_runs"
ENRICHMENTS_COLLECTION_NAME = "enrichments"
ATTACK_MAPPINGS_COLLECTION_NAME = "attack_mappings"

LOCAL_STORAGE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "processed"
    / "iocs.json"
)

_MONGO_CLIENT: Optional[MongoClient] = None


def utc_now():
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def get_client():
    """Return a reusable MongoDB client."""
    global _MONGO_CLIENT

    if _MONGO_CLIENT is None:
        _MONGO_CLIENT = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
            socketTimeoutMS=5000,
        )

    return _MONGO_CLIENT


def get_database() -> Database:
    """Return the configured CTI MongoDB database."""
    client = get_client()
    client.admin.command("ping")
    return client[DATABASE_NAME]


def mongodb_available() -> bool:
    """Check whether the configured MongoDB server is reachable."""
    try:
        get_database()
        return True
    except PyMongoError:
        return False


def get_ioc_collection() -> Collection:
    """Return the IOC collection."""
    return get_database()[IOC_COLLECTION_NAME]


def get_sources_collection() -> Collection:
    """Return the CTI sources collection."""
    return get_database()[SOURCES_COLLECTION_NAME]


def get_collection_runs_collection() -> Collection:
    """Return collection-run history collection."""
    return get_database()[COLLECTION_RUNS_COLLECTION_NAME]


def get_enrichments_collection() -> Collection:
    """Return IOC enrichment collection."""
    return get_database()[ENRICHMENTS_COLLECTION_NAME]


def get_attack_mappings_collection() -> Collection:
    """Return MITRE ATT&CK mapping collection."""
    return get_database()[ATTACK_MAPPINGS_COLLECTION_NAME]


def ensure_indexes() -> dict:
    """
    Ensure the main CTI indexes exist.

    Returns a small summary that can be used by health/debug endpoints.
    """
    database = get_database()

    database[IOC_COLLECTION_NAME].create_index(
        [("ioc_type", ASCENDING), ("ioc_value", ASCENDING)],
        unique=True,
        name="ioc_type_1_ioc_value_1",
    )
    database[IOC_COLLECTION_NAME].create_index(
        [("sources", ASCENDING)],
        name="sources_1",
    )
    database[IOC_COLLECTION_NAME].create_index(
        [("priority", ASCENDING)],
        name="priority_1",
    )
    database[IOC_COLLECTION_NAME].create_index(
        [("created_at", DESCENDING)],
        name="created_at_-1",
    )

    database[COLLECTION_RUNS_COLLECTION_NAME].create_index(
        [("started_at", DESCENDING)],
        name="started_at_-1",
    )

    database[ENRICHMENTS_COLLECTION_NAME].create_index(
        [("ioc_type", ASCENDING), ("ioc_value", ASCENDING)],
        name="ioc_type_1_ioc_value_1",
    )

    database[ATTACK_MAPPINGS_COLLECTION_NAME].create_index(
        [("technique_id", ASCENDING)],
        name="technique_id_1",
    )

    return {
        "database": DATABASE_NAME,
        "collections": database.list_collection_names(),
        "status": "ready",
    }


def _load_local_records():
    """Load the legacy JSON fallback dataset."""
    if not LOCAL_STORAGE_PATH.exists():
        return []

    try:
        with open(LOCAL_STORAGE_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_local_records(records):
    """Save records to the legacy JSON fallback dataset."""
    LOCAL_STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(LOCAL_STORAGE_PATH, "w", encoding="utf-8") as file:
        json.dump(records, file, indent=4)


def _record_to_document(record):
    """Convert a Pydantic IOCRecord or compatible object to MongoDB data."""
    now = utc_now()

    return {
        "ioc_type": record.ioc_type,
        "ioc_value": record.ioc_value,
        "source_url": record.source_url,
        "source_name": record.source_name,
        "sources": list(record.sources),
        "source_reliability": dict(getattr(record, "source_reliability", {}) or {}),
        "first_seen": getattr(record, "first_seen", None),
        "last_seen": getattr(record, "last_seen", None),
        "tags": list(getattr(record, "tags", []) or []),
        "relationships": list(getattr(record, "relationships", []) or []),
        "evidence": list(getattr(record, "evidence", []) or []),
        "metadata": dict(getattr(record, "metadata", {}) or {}),
        "created_at": now,
        "updated_at": now,
    }


def save_ioc_records(records: Iterable) -> int:
    """
    Save IOC records to MongoDB.

    MongoDB is now the primary persistent store.
    The legacy JSON file is used only when MongoDB is unavailable.

    Returns the number of newly inserted IOC records.
    """
    records = list(records)

    if not records:
        return 0

    if mongodb_available():
        ensure_indexes()
        collection = get_ioc_collection()
        inserted_count = 0

        for record in records:
            document = _record_to_document(record)

            key = {
                "ioc_type": document["ioc_type"],
                "ioc_value": document["ioc_value"],
            }

            existing = collection.find_one(
                key,
                {"_id": 1},
            )

            update = {
                "$set": {
                    "source_url": document["source_url"],
                    "source_name": document["source_name"],
                    "updated_at": document["updated_at"],
                    "last_seen": document.get("last_seen"),
                    "source_reliability": document.get("source_reliability", {}),
                    "metadata": document.get("metadata", {}),
                },
                "$addToSet": {
                    "sources": {
                        "$each": document["sources"],
                    },
                    "tags": {"$each": document.get("tags", [])},
                    "relationships": {"$each": document.get("relationships", [])},
                    "evidence": {"$each": document.get("evidence", [])},
                },
                "$setOnInsert": {
                    "created_at": document["created_at"],
                },
            }

            collection.update_one(
                key,
                update,
                upsert=True,
            )

            if existing is None:
                inserted_count += 1

        return inserted_count

    # Legacy local fallback.
    existing_records = _load_local_records()

    record_index = {
        (
            record.get("ioc_type"),
            record.get("ioc_value"),
        ): record
        for record in existing_records
    }

    saved_count = 0

    for record in records:
        key = (
            record.ioc_type,
            record.ioc_value,
        )

        document = _record_to_document(record)

        # JSON cannot serialize datetime objects, so use ISO strings here.
        document["created_at"] = document["created_at"].isoformat()
        document["updated_at"] = document["updated_at"].isoformat()

        if key in record_index:
            existing = record_index[key]

            existing_sources = existing.get("sources", [])
            new_sources = document.get("sources", [])

            existing["sources"] = list(
                dict.fromkeys(
                    existing_sources + new_sources
                )
            )

            if document.get("source_url"):
                existing["source_url"] = document["source_url"]

            if document.get("source_name"):
                existing["source_name"] = document["source_name"]

            existing["updated_at"] = document["updated_at"]

        else:
            existing_records.append(document)
            record_index[key] = document
            saved_count += 1

    _save_local_records(existing_records)

    return saved_count


def upsert_source(source_name, source_url, **extra_fields):
    """Create or update a CTI source definition."""
    collection = get_sources_collection()
    now = utc_now()

    document = {
        "source_name": source_name,
        "source_url": source_url,
        "updated_at": now,
        **extra_fields,
    }

    collection.update_one(
        {
            "source_name": source_name,
            "source_url": source_url,
        },
        {
            "$set": document,
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


def save_collection_run(run_document):
    """Persist one CTI collection execution record."""
    collection = get_collection_runs_collection()

    document = dict(run_document)
    document.setdefault("started_at", utc_now())
    document.setdefault("completed_at", utc_now())

    result = collection.insert_one(document)

    return str(result.inserted_id)


def save_enrichment(ioc_type, ioc_value, enrichment):
    """Persist enrichment evidence for an IOC."""
    collection = get_enrichments_collection()
    now = utc_now()

    document = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "enrichment": enrichment,
        "updated_at": now,
    }

    collection.update_one(
        {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
        },
        {
            "$set": document,
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


def save_attack_mappings(
    ioc_type,
    ioc_value,
    mappings,
    behavior_text=None,
):
    """Persist behavior-to-MITRE ATT&CK mapping evidence."""
    collection = get_attack_mappings_collection()
    now = utc_now()

    document = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "behavior_text": behavior_text,
        "mappings": mappings,
        "updated_at": now,
    }

    collection.update_one(
        {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
        },
        {
            "$set": document,
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )
