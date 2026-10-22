# System Architecture

The following diagram shows the main data flow through the Cyber Threat Intelligence Correlation System.

```mermaid
flowchart TD
    A["Public CTI Feeds<br/>21 enabled feeds"] --> B["Feed Collection"]
    U["Single CTI Report URL"] --> V["Single-URL Processing"]
    B --> C["IOC Extraction"]
    V --> C
    C --> D["Normalization and Deduplication"]
    D --> E["Cross-Source Correlation"]
    E --> F[("MongoDB or Local JSON Fallback")]
    F --> G["FastAPI REST API"]
    G --> H["React + Recharts Dashboard"]
    G --> I["RDAP Enrichment<br/>IP indicators"]
    G --> J["MITRE ATT&CK Mapping<br/>Supplied behavior text only"]
    E --> K["Explainable Priority Scoring"]
    I --> K
    J --> K
    K --> H
```

## Important Notes

- Priority scoring is a project-defined heuristic for analyst triage, not proof that an indicator is malicious.
- MITRE ATT&CK mapping uses supplied behavioral text; an IOC is not automatically attributed to a technique merely because it exists.
- MongoDB is supported, with local JSON storage as a fallback.
