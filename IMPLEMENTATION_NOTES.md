# CTI CORE rebuild — implementation notes

## What changed

This revision addresses the faculty criticism at the architecture level rather than by adding a chatbot or cosmetic widgets.

- **25-source registry:** `backend/collectors/source_registry.py` records diverse public feeds, formats, supported entity types, and licensing/API-key constraints. The two stable feeds remain the default live demo profile so a student deployment does not fail because every public provider rate-limits anonymous requests.
- **Heterogeneous extraction:** the extractor now handles IPv4, IPv6, domains, URLs, MD5/SHA-1/SHA-256, emails, CVEs, ATT&CK technique IDs, and explicitly labelled malware, actor, campaign, and file-name entities.
- **Canonical normalization:** typed normalization exists for domains, URLs, hashes, email addresses, CVEs, and ATT&CK IDs. Extracted values are deduplicated before record construction.
- **Evidence-preserving model:** IOC records now retain first/last seen timestamps, source reliability, tags, relationships, evidence objects, and collection metadata instead of reducing an observation to only `(type, value)`.
- **Cross-source fusion:** correlation merges source sets, evidence, relationships, timestamps, and tags. This allows a reviewer to see why an entity is considered multi-source rather than only seeing a count.
- **Research analytics:** `/api/v1/sources` reports the auditable coverage plan; `/api/v1/analytics/overview` reports entity-type distribution, source coverage, cross-source rate, and relationship types using deterministic aggregation.
- **Dashboard coverage:** the frontend now displays the configured source count and dynamically charts all entity types returned by the backend.

## Defensible scope decisions

- The source registry is not a claim that all 25 feeds are always reachable. Public feeds have different formats, licenses, rate limits, and API requirements. Activation should be controlled by an environment profile and recorded per collection run.
- Priority remains a transparent triage heuristic, not a maliciousness verdict.
- ATT&CK mapping still requires behavioral evidence. An IP address is not automatically assigned a technique merely because it appears in a feed.
- No LLM was added. The research value is in multi-source fusion, canonicalization, evidence retention, correlation, and measurable evaluation.

## Demonstration plan

1. Show `/api/v1/sources` and explain why source metadata is tracked.
2. Process a report containing an IP, IPv6, URL, hash, CVE, and labelled actor/malware values.
3. Show the canonical records and evidence fields.
4. Collect the stable demo feeds and compare raw observations with correlated records.
5. Use the existing evaluation endpoints for extraction, normalization, correlation, enrichment, and priority consistency.
6. Report the known limitations honestly: regex/context extraction can produce false positives, and source reachability varies over time.

## Verification

- Backend regression suite: **49 passed**.
- Python modules compile successfully.
- Frontend production build succeeds after reinstalling the archive's incomplete optional native dependency from `package-lock.json`.
