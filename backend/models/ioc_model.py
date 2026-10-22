from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


class IOCRecord(BaseModel):
    """Canonical, evidence-preserving CTI entity observation."""
    ioc_type: str
    ioc_value: str
    source_url: Optional[str] = None
    source_name: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    source_reliability: dict[str, float] = Field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: float = 0.0
    tags: list[str] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def create_ioc_record(ioc_type, ioc_value, source_url=None, source_name=None, **kwargs):
    sources = [source_name] if source_name else []
    now = datetime.now(timezone.utc).isoformat()
    return IOCRecord(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        source_url=source_url,
        source_name=source_name,
        sources=sources,
        first_seen=kwargs.pop("first_seen", now),
        last_seen=kwargs.pop("last_seen", now),
        **kwargs,
    )
