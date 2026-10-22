from fastapi import FastAPI, HTTPException, Query

import json
import time
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import APP_NAME

from backend.processors.cti_pipeline import (
    process_cti_url
)

from backend.services.collection_service import (
    process_and_record_collection
)

from backend.processors.ioc_correlator import (
    calculate_confidence,
    calculate_priority,
    classify_priority
)

from backend.processors.priority_scorer import (
    calculate_research_priority
)

from backend.database.mongodb import (
    mongodb_available,
    get_ioc_collection,
    _load_local_records
)

from backend.enrichment.enrichment_service import (
    enrich_ioc
)

from backend.attack.attack_mapper import (
    map_behavior_to_attack
)

from backend.evaluation.enrichment_evaluator import (
    evaluate_rdap_enrichment
)

from backend.evaluation.ioc_evaluator import (
    evaluate_ioc_extraction
)

from backend.evaluation.normalization_evaluator import (
    evaluate_normalization
)

from backend.evaluation.correlation_evaluator import (
    evaluate_correlation
)

from backend.evaluation.priority_evaluator import (
    evaluate_priority_consistency
)

from backend.collectors.source_registry import source_catalog_summary


# ============================================================
# RESEARCH EVALUATION STORAGE
# ============================================================

EVALUATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "processed"
    / "evaluation_metrics.json"
)


def _save_evaluation_metrics(metrics):
    EVALUATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(EVALUATION_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)


def _load_evaluation_metrics():
    if not EVALUATION_PATH.exists():
        return None
    try:
        with open(EVALUATION_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    description=(
        "Automated Multi-Source Cyber Threat Intelligence "
        "Correlation and Prioritization System"
    )
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODELS
# ============================================================

class CTIProcessRequest(BaseModel):
    url: str


class IOCAnalyzeRequest(BaseModel):
    iocType: str
    iocValue: str
    sourceCount: int = 0
    enrichment: dict | None = None
    behaviorText: str = ""


# ============================================================
# DATABASE / STORAGE HELPERS
# ============================================================

def get_all_records():
    """
    Get all stored IOC records.

    MongoDB is used when available.
    Local JSON storage is used as a fallback.
    """

    if mongodb_available():

        collection = get_ioc_collection()

        return list(
            collection.find(
                {},
                {
                    "_id": 0
                }
            )
        )

    return _load_local_records()


# ============================================================
# IOC SCORING
# ============================================================

def enrich_ioc_record(record):
    """
    Add calculated CTI intelligence fields to an IOC.

    Research priority components:

        Cross-source evidence
        IOC type
        Enrichment evidence
        ATT&CK evidence

    Missing evidence contributes zero points.
    The score is a project-defined research heuristic
    and does not independently prove maliciousness.
    """

    sources = record.get(
        "sources",
        []
    )

    source_count = len(
        set(sources)
    )

    confidence = calculate_confidence(
        source_count
    )

    priority_result = calculate_research_priority(
        ioc_type=record.get(
            "ioc_type",
            ""
        ),

        source_count=source_count,

        enrichment=record.get(
            "enrichment"
        ),

        attack_mappings=record.get(
            "attack_mappings"
        )
    )

    return {
        **record,

        "source_count": source_count,

        "confidence": confidence,

        "priority_score": priority_result[
            "score"
        ],

        "priority": priority_result[
            "priority"
        ],

        "priority_components": (
            priority_result[
                "components"
            ]
        )
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    """
    Basic application health check.
    """

    return {
        "status": "ok",
        "application": APP_NAME,
        "version": "1.0.0"
    }


# ============================================================
# PROCESS SINGLE CTI URL
# ============================================================

@app.post("/api/v1/cti/process")
def process_cti(
    request: CTIProcessRequest
):
    """
    Fetch CTI from a public URL,
    extract IOCs, normalize them,
    attach source metadata and save them.
    """

    cleaned_url = request.url.strip()

    if not cleaned_url:

        raise HTTPException(
            status_code=400,
            detail="CTI URL cannot be empty."
        )

    try:

        result = process_cti_url(
            cleaned_url
        )

        return {
            "status": "success",

            "source_url": result[
                "source_url"
            ],

            "source_name": result[
                "source_name"
            ],

            "content_type": result[
                "content_type"
            ],

            "ioc_count": result[
                "ioc_count"
            ],

            "saved_count": result[
                "saved_count"
            ],

            "records": [
                record.model_dump()
                for record in result[
                    "records"
                ]
            ]
        }

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# ============================================================
# MULTI-SOURCE CTI COLLECTION
# ============================================================

@app.post("/api/v1/cti/collect")
def collect_multi_source_cti():
    """
    Collect IOC data from all configured public CTI feeds,
    correlate the collected indicators, persist IOC records,
    and record collection/source metadata in MongoDB.

    Pipeline:

        collect
          ↓
        correlate
          ↓
        save IOCs
          ↓
        save source metadata
          ↓
        save collection run
    """

    try:
        result = process_and_record_collection()

        evaluation_metrics = result.get("evaluation", {})
        _save_evaluation_metrics(evaluation_metrics)

        preview_records = [
            record.model_dump()
            for record in result.get("records", [])[:20]
        ]

        response = {
            "status": result.get("status", "success"),
            "sources": result.get("sources", []),
            "collected_count": result.get("collected_count", 0),
            "correlated_count": result.get("correlated_count", 0),
            "saved_count": result.get("saved_count", 0),
            "evaluation": evaluation_metrics,
            "preview_count": len(preview_records),
            "records_preview": preview_records,
        }

        if result.get("run_id") is not None:
            response["run_id"] = result["run_id"]
        if result.get("database") is not None:
            response["database"] = result["database"]

        return response

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# GET STORED IOCs
# ============================================================

@app.get("/api/v1/iocs")
def get_iocs(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),

    offset: int = Query(
        default=0,
        ge=0
    ),

    ioc_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=20
    )
):
    """
    Return stored IOCs with pagination.

    Each IOC includes:

        source_count
        confidence
        priority_score
        priority
        priority_components
    """

    records = get_all_records()

    # Filter before pagination so analysts can inspect each IOC type
    # without scanning only the first 100 stored records in the UI.
    if ioc_type:
        normalized_type = ioc_type.strip().lower()
        records = [
            record for record in records
            if str(record.get("ioc_type", "")).strip().lower() == normalized_type
        ]

    total = len(
        records
    )

    selected_records = records[
        offset:offset + limit
    ]

    enriched_records = [
        enrich_ioc_record(record)
        for record in selected_records
    ]

    return {
        "status": "success",

        "total": total,

        "limit": limit,

        "offset": offset,

        "count": len(
            enriched_records
        ),

        "records": enriched_records
    }


# ============================================================
# GET CORRELATED IOCs
# ============================================================

@app.get("/api/v1/iocs/correlated")
def get_correlated_iocs(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),

    offset: int = Query(
        default=0,
        ge=0
    )
):
    """
    Return IOCs observed in at least two
    configured CTI sources.
    """

    records = get_all_records()

    correlated_records = []

    for record in records:

        enriched = enrich_ioc_record(
            record
        )

        if enriched[
            "source_count"
        ] >= 2:

            correlated_records.append(
                enriched
            )

    total = len(
        correlated_records
    )

    selected_records = correlated_records[
        offset:offset + limit
    ]

    return {
        "status": "success",

        "total": total,

        "limit": limit,

        "offset": offset,

        "count": len(
            selected_records
        ),

        "records": selected_records
    }


# ============================================================
# SINGLE IOC ENRICHMENT
# ============================================================

@app.get("/api/v1/iocs/enrich")
def enrich_single_ioc(
    ioc_type: str,
    ioc_value: str
):
    """
    Enrich a single IOC.

    Currently supported:

        IP → RDAP
    """

    cleaned_type = (
        ioc_type.strip().lower()
    )

    cleaned_value = (
        ioc_value.strip()
    )

    if not cleaned_type:

        raise HTTPException(
            status_code=400,
            detail="IOC type cannot be empty."
        )

    if not cleaned_value:

        raise HTTPException(
            status_code=400,
            detail="IOC value cannot be empty."
        )

    try:

        result = enrich_ioc(
            cleaned_type,
            cleaned_value
        )

        return {
            "status": "success",

            "ioc_type": cleaned_type,

            "ioc_value": cleaned_value,

            "enrichment": result
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# MITRE ATT&CK BEHAVIOR MAPPING
# ============================================================

@app.get("/api/v1/attack/map")
def map_cti_behavior(
    text: str
):
    """
    Map behavioral evidence from CTI text
    to MITRE ATT&CK techniques.

    An IOC alone is NOT automatically mapped
    to an ATT&CK technique.
    """

    cleaned_text = text.strip()

    if not cleaned_text:

        raise HTTPException(
            status_code=400,
            detail="CTI behavior text cannot be empty."
        )

    try:

        mappings = map_behavior_to_attack(
            cleaned_text
        )

        return {
            "status": "success",

            "input_text": cleaned_text,

            "mapping_count": len(
                mappings
            ),

            "mappings": mappings
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# COMPLETE IOC ANALYSIS
# ============================================================

@app.post("/api/v1/iocs/analyze")
def analyze_ioc(request: IOCAnalyzeRequest):
    """
    Orchestrate the complete analyst-side IOC investigation flow.

    Flow:

        source evidence
              ↓
        supplied enrichment
              ↓
        behavioral ATT&CK mapping
              ↓
        transparent priority scoring

    The endpoint does not execute or contact the IOC itself.
    Enrichment is supplied by the existing enrichment endpoint,
    and ATT&CK mapping is performed only on the supplied behavior text.
    """

    cleaned_type = request.iocType.strip().lower()
    cleaned_value = request.iocValue.strip()
    behavior_text = request.behaviorText.strip()

    if not cleaned_type:
        raise HTTPException(
            status_code=400,
            detail="IOC type cannot be empty."
        )

    if not cleaned_value:
        raise HTTPException(
            status_code=400,
            detail="IOC value cannot be empty."
        )

    source_count = max(int(request.sourceCount), 0)
    enrichment = request.enrichment if isinstance(request.enrichment, dict) else None

    try:
        attack_mappings = []
        if behavior_text:
            attack_mappings = map_behavior_to_attack(behavior_text)

        confidence = calculate_confidence(source_count)

        priority_result = calculate_research_priority(
            ioc_type=cleaned_type,
            source_count=source_count,
            enrichment=enrichment,
            attack_mappings=attack_mappings
        )

        return {
            "status": "success",
            "ioc": {
                "ioc_type": cleaned_type,
                "ioc_value": cleaned_value
            },
            "source_count": source_count,
            "confidence": confidence,
            "enrichment": enrichment,
            "behavior_text": behavior_text,
            "attack_mappings": attack_mappings,
            "priority": priority_result,
            "analysis_method": {
                "enrichment": "RDAP supplied by enrichment service",
                "attack_mapping": "evidence-based MITRE ATT&CK rules",
                "priority": "transparent research scoring model"
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# RESEARCH PRIORITY CALCULATOR
# ============================================================

@app.get("/api/v1/iocs/priority")
def calculate_ioc_priority(
    ioc_type: str,

    source_count: int = Query(
        default=1,
        ge=0,
        le=100
    )
):
    """
    Calculate the transparent research
    priority score using the evidence supplied.

    At this endpoint, enrichment and ATT&CK
    evidence are not supplied, so their
    contribution is zero.
    """

    cleaned_type = (
        ioc_type.strip().lower()
    )

    if not cleaned_type:

        raise HTTPException(
            status_code=400,
            detail="IOC type cannot be empty."
        )

    try:

        result = calculate_research_priority(
            ioc_type=cleaned_type,

            source_count=source_count,

            enrichment=None,

            attack_mappings=None
        )

        return {
            "status": "success",

            "ioc_type": cleaned_type,

            "source_count": source_count,

            "priority": result
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# IOC STATISTICS
# ============================================================

@app.get("/api/v1/iocs/stats")
def get_ioc_stats():
    """
    Return overall CTI statistics.

    Includes:

        total IOC count
        IOC type distribution
        priority distribution
        source distribution
        multi-source IOC count
    """

    records = get_all_records()

    stats = {"total": 0}

    priority_counts = {
        "High": 0,

        "Medium": 0,

        "Low": 0
    }

    source_counts = {}

    multi_source_count = 0

    for record in records:

        ioc_type = record.get(
            "ioc_type"
        )

        stats[ioc_type] = stats.get(ioc_type, 0) + 1

        enriched = enrich_ioc_record(
            record
        )

        priority = enriched[
            "priority"
        ]

        priority_counts[
            priority
        ] += 1

        if enriched[
            "source_count"
        ] >= 2:

            multi_source_count += 1

        for source in record.get(
            "sources",
            []
        ):

            source_counts[
                source
            ] = source_counts.get(
                source,
                0
            ) + 1

    stats[
        "total"
    ] = len(records)

    return {
        "status": "success",

        "statistics": stats,

        "priority_distribution": (
            priority_counts
        ),

        "source_distribution": (
            source_counts
        ),

        "multi_source_ioc_count": (
            multi_source_count
        ),
        "configured_source_count": source_catalog_summary()["configured_count"],
        "enabled_feed_count": source_catalog_summary()["active_feed_count"],
        "active_source_count": len(source_counts),
        "entity_type_count": len([key for key in stats if key != "total"])
    }


@app.get("/api/v1/sources")
def get_source_catalog():
    """Return the auditable source registry and its license/API-key notes."""
    return {"status": "success", **source_catalog_summary()}


@app.get("/api/v1/analytics/overview")
def get_analytics_overview():
    """Return deterministic evidence and cross-source correlation metrics."""
    records = get_all_records()
    type_counts, source_counts, relationship_counts = {}, {}, {}
    multi_source = 0
    for record in records:
        kind = record.get("ioc_type", "unknown")
        type_counts[kind] = type_counts.get(kind, 0) + 1
        sources = record.get("sources", [])
        if len(set(sources)) >= 2:
            multi_source += 1
        for source in sources:
            source_counts[source] = source_counts.get(source, 0) + 1
        for relation in record.get("relationships", []):
            relation_type = relation.get("type", "related_to") if isinstance(relation, dict) else "related_to"
            relationship_counts[relation_type] = relationship_counts.get(relation_type, 0) + 1
    total = len(records)
    return {
        "status": "success",
        "method": "deterministic evidence aggregation over canonical IOC records",
        "total_entities": total,
        "entity_types": type_counts,
        "source_coverage": source_counts,
        "multi_source_entities": multi_source,
        "cross_source_rate": round((multi_source / total) * 100, 2) if total else 0,
        "relationship_types": relationship_counts,
        "configured_source_count": source_catalog_summary()["configured_count"],
    }

# ============================================================
# IOC EXTRACTION EVALUATION
# ============================================================

@app.get("/api/v1/research/extraction-evaluation")
def get_extraction_evaluation():
    """
    Return measured IOC extraction metrics on the project-curated
    labelled validation dataset.
    """
    try:
        return {
            "status": "success",
            "evaluation": evaluate_ioc_extraction()
        }
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# NORMALIZATION + DEDUPLICATION EVALUATION
# ============================================================

@app.get("/api/v1/research/normalization-evaluation")
def get_normalization_evaluation():
    """
    Return measured normalization and deduplication metrics on the
    project-curated labelled validation dataset.
    """
    try:
        return {
            "status": "success",
            "evaluation": evaluate_normalization()
        }
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# RDAP ENRICHMENT EVALUATION
# ============================================================

@app.get("/api/v1/research/enrichment-evaluation")
def get_enrichment_evaluation():
    """Measure configured RDAP enrichment on the fixed public-IP set."""
    try:
        return {
            "status": "success",
            "evaluation": evaluate_rdap_enrichment()
        }
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


# ============================================================
# CORRELATION EVALUATION
# ============================================================

@app.get("/api/v1/research/correlation-evaluation")
def get_correlation_evaluation():
    """
    Return measured correlation metrics on the project-curated
    labelled validation dataset.
    """
    try:
        return {
            "status": "success",
            "evaluation": evaluate_correlation()
        }
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


# ============================================================
# PRIORITY CONSISTENCY EVALUATION
# ============================================================

@app.get("/api/v1/research/priority-evaluation")
def get_priority_evaluation():
    """
    Return deterministic property-test results for the research
    priority scoring model.
    """
    try:
        return {
            "status": "success",
            "evaluation": evaluate_priority_consistency()
        }
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


# ============================================================
# RESEARCH EVALUATION METRICS
# ============================================================

@app.get("/api/v1/research/evaluation")
def get_research_evaluation():
    """
    Return the latest measured collection/evaluation metrics.

    Metrics are recorded only after an actual CTI collection run.
    No historical values are fabricated.
    """

    metrics = _load_evaluation_metrics()

    if metrics is None:
        return {
            "status": "not_recorded",
            "message": (
                "Run Collect CTI once to record experimental "
                "baseline and timing metrics."
            ),
            "evaluation": None
        }

    return {
        "status": "success",
        "evaluation": metrics
    }
