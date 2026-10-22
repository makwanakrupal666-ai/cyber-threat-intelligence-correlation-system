# Final Viva Quickstart — CTI CORE

## Start the project

Open two terminals in `D:\Project\cti-project-final` (or the folder where this ZIP is extracted).

**Terminal 1 — backend**
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend**
```powershell
cd frontend
npm run dev
```

Open the Vite URL printed in Terminal 2. Backend health: `http://127.0.0.1:8000/health`. API docs: `http://127.0.0.1:8000/docs`.


## Inspecting IOC types in the dashboard

In **Threat intelligence records**, select the **All IOC types** dropdown to filter by IP address, domain, URL, SHA-256, SHA-1, MD5 or CVE. Use **Previous / Next** to page through that type's results. The search box searches only the currently loaded page, so switch to the desired type first and use page navigation when needed.

## 3-minute demonstration sequence

1. **Source coverage:** open `/api/v1/sources`. Explain that the registry distinguishes catalogued sources from the 21 enabled feed adapters. A source being configured does not mean it is reachable; reachability is measured during collection.
2. **Live collection:** click **Collect CTI** once. Wait for the request to finish. Show the per-source statuses and raw/correlated counts. Public feeds may rate-limit, change format, or be unavailable; explain failures rather than claiming every feed succeeded.
3. **IOC diversity:** use the IOC table and search/filter to show the types actually collected. The extractor supports IP, domain, URL, MD5/SHA hashes, CVE and ATT&CK IDs when those types are present in a feed and permitted by its adapter. Do not invent records for types a source does not provide.
4. **Provenance:** open an IOC and show its source list and source URL. Newly collected records carry evidence containing source, collection method and collection timestamp.
5. **Correlation and scoring:** explain that duplicates are grouped by `(ioc_type, ioc_value)` and source/evidence lists are merged. Priority is a transparent triage heuristic, not proof that an IOC is malicious.
6. **Research evaluation:** show the research metrics endpoints:
   - `/api/v1/research/extraction-evaluation`
   - `/api/v1/research/normalization-evaluation`
   - `/api/v1/research/correlation-evaluation`
   - `/api/v1/research/priority-evaluation`

## Honest wording for the viva

- **Configured vs. live:** “The platform has 28 catalogued sources and 21 enabled public feed adapters. The dashboard records which feeds succeeded or failed on the latest collection.”
- **IOC types:** “The extraction pipeline supports multiple typed indicators; the types visible in a live run depend on the formats and contents returned by the feeds.”
- **Evidence:** “Evidence records provenance and collection context. It does not independently prove maliciousness.”
- **Limitations:** “Public feeds can change or rate-limit clients. Some catalogued sources require credentials or dedicated format adapters. The system reports reachability instead of treating every catalog entry as a successful feed.”

## Verification

From the project root:
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The updated source package was verified with **50 passing tests**. Run the command again on the viva laptop after extracting the ZIP.
