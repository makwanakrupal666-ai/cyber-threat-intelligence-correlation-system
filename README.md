# Automated Multi-Source Cyber Threat Intelligence Correlation & Prioritization

A research-oriented CTI pipeline that collects indicators from public threat
feeds, extracts and normalizes them, correlates repeated observations across
sources, maps behavioral evidence to MITRE ATT&CK, and produces a
transparent, explainable priority score for each indicator — with a
measured, honest evaluation (precision/recall/F1) instead of unverified
claims.

This is not "a dashboard that shows threat feeds." The dashboard is the last
stage; the research contribution is the processing pipeline in between.

```
PUBLIC CTI SOURCES (21 enabled feeds + single-URL processing)
      │
      ▼
  COLLECTOR ──▶ IOC EXTRACTOR ──▶ NORMALIZER ──▶ DEDUPLICATOR
      │
      ▼
  CORRELATION (same IOC across sources) ──▶ ENRICHMENT (RDAP)
      │
      ▼
  MITRE ATT&CK MAPPING (behavior text ──▶ technique)
      │
      ▼
  TRANSPARENT PRIORITY SCORING ──▶ API ──▶ REACT DASHBOARD
```

## What actually works right now

- FastAPI backend with a real, modular pipeline (collectors → extractors →
  normalizers → deduplicators → correlator → enrichment → ATT&CK mapper →
  priority scorer).
- MongoDB storage **with an automatic local-JSON fallback** — the whole
  system runs and demos correctly even if MongoDB is not installed.
- Concurrent collection from 21 enabled public CTI feeds, with per-feed success/error
  reporting. The source catalog also documents additional feeds and providers that
  need credentials or separate format-specific adapters.
- Typed IOC extraction across supported feed formats (IP, domain, URL, MD5/SHA
  hashes, CVE and ATT&CK IDs where the source content and declared types support them).
- MITRE ATT&CK technique mapping using the official Enterprise ATT&CK STIX
  dataset (auto-downloaded on first use and cached locally).
- IP enrichment via RDAP (registrar/country/ASN-level context).
- A transparent, documented priority-scoring formula (source evidence 40 pts
  + IOC type 15 pts + enrichment 20 pts + ATT&CK evidence 25 pts = 100),
  not a black box.
- A real evaluation harness: precision/recall/F1 for IOC extraction, and
  accuracy/duplicate-reduction for normalization, measured against
  project-curated labelled datasets (`data/test/`) — see
  [Evaluation & known limitations](#evaluation--known-limitations) below.
- 49 passing automated tests (`pytest`).
- A React + Recharts dashboard (Overview stats, IOC table, priority chart,
  ATT&CK panel).

## Project structure

```
backend/
  collectors/        fetch CTI from a single URL or all configured feeds
  extractors/         regex-based IOC extraction (IP, domain, URL, MD5/SHA1/SHA256)
  normalizers/        canonical form for each IOC type
  deduplicators/       normalize + dedupe per IOC type
  processors/          ioc_processor, cti_pipeline, multi_source_pipeline,
                        ioc_correlator, priority_scorer
  enrichment/          RDAP enrichment
  attack/              MITRE ATT&CK loader + evidence-based mapper
  evaluation/          measured precision/recall/F1 and normalization accuracy
  database/            MongoDB with local-JSON fallback
  models/              IOCRecord (pydantic)
  main.py              FastAPI app and all HTTP endpoints
frontend/              React + Vite + Recharts dashboard
data/
  test/                labelled validation datasets used by evaluation/
  processed/           generated at runtime (IOC store, evaluation snapshots)
  attack/              MITRE ATT&CK dataset cache (auto-downloaded)
tests/                 49 pytest unit/integration tests
```

## Setup

### Requirements
- Python 3.10+
- Node.js 18+ (for the dashboard)
- MongoDB is optional — if it isn't running, the backend automatically uses
  `data/processed/iocs.json` as local storage instead.

### 1. Backend

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env      # defaults are fine for local use

uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Or just run `start_backend.bat` (Windows) / `./start_backend.sh` (macOS/Linux)
after the one-time venv + pip install above.

Check it worked: open http://127.0.0.1:8000/health — you should see
`{"status":"ok", ...}`. Interactive API docs are at
http://127.0.0.1:8000/docs.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the printed local URL (usually http://127.0.0.1:5173). The dashboard
talks to the backend at `http://127.0.0.1:8000` (see `frontend/src/api.js`).

### 3. Run the tests

```bash
pytest
```

You should see `49 passed`.

## Using it

1. Start the backend and frontend as above.
2. Click **Collect CTI** in the dashboard (or `POST /api/v1/cti/collect`) to
   pull fresh indicators from the configured public feeds and correlate
   them.
3. Review `/api/v1/sources` for configured versus enabled feed coverage. Feed
   reachability is determined by the latest collection result, not by registry presence.
4. Or paste any CTI report/feed URL into the single-source form
   (`POST /api/v1/cti/process`) to extract IOCs from it directly.
5. Browse `GET /api/v1/iocs`, `GET /api/v1/iocs/correlated`, and
   `GET /api/v1/iocs/stats` to see the correlated, scored results.
6. `GET /api/v1/attack/map?text=...` maps free-text behavioral evidence
   (e.g. "used PowerShell to download a payload") to MITRE ATT&CK
   techniques — an IOC is never auto-mapped to a technique without
   supporting behavioral text.
7. `GET /api/v1/research/extraction-evaluation` and
   `/api/v1/research/normalization-evaluation` return the measured
   precision/recall/F1 metrics described below — useful to show a faculty
   reviewer real numbers instead of a claim.

## Evaluation & known limitations

The extraction evaluator (`backend/evaluation/ioc_evaluator.py`) runs the
regex extractor against a 10-case labelled dataset
(`data/test/ioc_validation.json`) that deliberately includes adversarial
cases, not just easy ones:

| Case | Tests for |
|---|---|
| V05 | rejects an invalid IPv4 (`999.1.2.3`) |
| V07 | correctly ignores an IPv6 address (regex is IPv4-only by design) |
| V08 | deduplicates a repeated indicator |
| V10 | **known false positive**: a version string `1.2.3.4` gets extracted as an IP |

Current measured result: **precision 0.857, recall 0.923, F1 0.889** (run
`pytest` or hit `/api/v1/research/extraction-evaluation` to reproduce).

The V10 false positive is not a bug to hide — it is exactly the
context-free-extraction weakness described in the literature (e.g. Tang et
al. 2024, AIIOC: "false positives caused by insufficient fine-grained
contextual understanding"). Reporting it honestly, and proposing a fix, is
stronger for a viva than claiming a perfect score:

- **Future work / MVP-4**: disambiguate numeric strings that look like IPv4
  addresses using surrounding context (e.g. skip matches preceded by
  "version", "v", "release") or add an optional local LLM pass (Ollama) and
  compare it against this regex baseline — exactly the "Regex vs LLM"
  experiment the original project brief calls for.

## API reference (summary)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | liveness check |
| POST | `/api/v1/cti/process` | extract IOCs from one URL |
| POST | `/api/v1/cti/collect` | collect + correlate from all configured feeds |
| GET | `/api/v1/iocs` | paginated stored IOCs (scored) |
| GET | `/api/v1/iocs/correlated` | IOCs seen in ≥2 sources |
| GET | `/api/v1/iocs/enrich` | RDAP enrichment for one IOC |
| GET | `/api/v1/attack/map` | map behavior text to ATT&CK techniques |
| POST | `/api/v1/iocs/analyze` | full pipeline for one IOC (enrich + ATT&CK + score) |
| GET | `/api/v1/iocs/priority` | priority score for given evidence |
| GET | `/api/v1/iocs/stats` | dashboard summary statistics |
| GET | `/api/v1/research/extraction-evaluation` | measured extraction precision/recall/F1 |
| GET | `/api/v1/research/normalization-evaluation` | measured normalization accuracy |
| GET | `/api/v1/research/evaluation` | metrics from the last collection run |

## Notes on scope (what this project intentionally does not claim)

- The priority score is a **project-defined heuristic for analyst triage**,
  not a maliciousness verdict — this is stated in the code and in every
  API response's `analysis_method` field.
- ATT&CK mapping requires explicit behavioral text; an IOC is never
  auto-mapped to a technique just because it exists.
- MITRE ATT&CK data and RDAP responses are treated as untrusted external
  data — nothing fetched from the internet is ever executed.
