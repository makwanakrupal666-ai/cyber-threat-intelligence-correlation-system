const API_BASE_URL =
  "http://127.0.0.1:8000";


// ============================================================
// GENERIC REQUEST HELPER
// ============================================================

async function apiRequest(
  endpoint,
  options = {}
) {
  const response =
    await fetch(
      `${API_BASE_URL}${endpoint}`,
      {
        ...options,

        headers: {
          "Content-Type":
            "application/json",

          ...(options.headers || {}),
        },
      }
    );


  let data = null;

  try {
    data = await response.json();
  } catch {
    data = null;
  }


  if (!response.ok) {
    const message =
      data?.detail ||
      data?.message ||
      `Request failed with HTTP ${response.status}`;

    throw new Error(message);
  }


  return data;
}


// ============================================================
// HEALTH
// ============================================================

export async function getHealth() {
  return apiRequest(
    "/health"
  );
}


// ============================================================
// GET STATISTICS
// ============================================================

export async function getStats() {
  return apiRequest(
    "/api/v1/iocs/stats"
  );
}


// ============================================================
// GET IOCs
// ============================================================

export async function getIOCs(
  limit = 50,
  offset = 0,
  iocType = "all"
) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });

  if (iocType && iocType !== "all") {
    params.set("ioc_type", iocType);
  }

  return apiRequest(
    `/api/v1/iocs?${params.toString()}`
  );
}


// ============================================================
// GET CORRELATED IOCs
// ============================================================

export async function getCorrelatedIOCs(
  limit = 50,
  offset = 0
) {
  return apiRequest(
    `/api/v1/iocs/correlated?limit=${limit}&offset=${offset}`
  );
}


// ============================================================
// COLLECT CTI
// ============================================================

export async function collectCTI() {
  return apiRequest(
    "/api/v1/cti/collect",
    {
      method: "POST",
    }
  );
}


// ============================================================
// PROCESS SINGLE CTI URL
// ============================================================

export async function processCTI(
  url
) {
  return apiRequest(
    "/api/v1/cti/process",
    {
      method: "POST",

      body: JSON.stringify({
        url,
      }),
    }
  );
}


// ============================================================
// IOC ENRICHMENT
// ============================================================

export async function enrichIOC(
  iocType,
  iocValue
) {
  const params =
    new URLSearchParams({
      ioc_type: iocType,
      ioc_value: iocValue,
    });


  return apiRequest(
    `/api/v1/iocs/enrich?${params.toString()}`
  );
}


// ============================================================
// MITRE ATT&CK MAPPING
// ============================================================

export async function mapAttackBehavior(
  text
) {
  const params =
    new URLSearchParams({
      text,
    });


  return apiRequest(
    `/api/v1/attack/map?${params.toString()}`
  );
}


// ============================================================
// PRIORITY CALCULATOR
// ============================================================

export async function calculatePriority(
  iocType,
  sourceCount = 1
) {
  const params =
    new URLSearchParams({
      ioc_type: iocType,

      source_count:
        String(sourceCount),
    });


  return apiRequest(
    `/api/v1/iocs/priority?${params.toString()}`
  );
}


// ============================================================
// COMPLETE IOC ANALYSIS
// ============================================================

export async function analyzeIOC({
  iocType,
  iocValue,
  sourceCount,
  enrichment,
  behaviorText,
}) {
  return apiRequest(
    "/api/v1/iocs/analyze",
    {
      method: "POST",

      body: JSON.stringify({
        // IMPORTANT:
        // Backend IOCAnalyzeRequest expects camelCase
        iocType: iocType,

        iocValue: iocValue,

        sourceCount:
          Number(sourceCount || 0),

        enrichment:
          enrichment || null,

        behaviorText:
          behaviorText || "",
      }),
    }
  );
}

export async function getSourceCatalog() {
  return apiRequest("/api/v1/sources");
}
