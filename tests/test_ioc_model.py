from backend.models.ioc_model import IOCRecord
from backend.models.ioc_model import create_ioc_record

def test_ioc_record():
    record = IOCRecord(
        ioc_type="ip",
        ioc_value="185.10.20.30"
    )

    assert record.ioc_type == "ip"
    assert record.ioc_value == "185.10.20.30"

def test_create_ioc_record():
    record = create_ioc_record(
        "domain",
        "evil-example.com"
    )

    assert record.ioc_type == "domain"
    assert record.ioc_value == "evil-example.com"