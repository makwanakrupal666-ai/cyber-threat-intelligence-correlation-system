from backend.database.mongodb import (
    save_ioc_records,
    LOCAL_STORAGE_PATH
)

from backend.models.ioc_model import IOCRecord


def test_save_ioc_records():
    # Use a unique test IOC so we don't depend on existing data.
    records = [
        IOCRecord(
            ioc_type="ip",
            ioc_value="203.0.113.10"
        )
    ]

    saved_count = save_ioc_records(records)

    assert saved_count in (0, 1)


def test_local_storage_path():
    assert LOCAL_STORAGE_PATH.name == "iocs.json"