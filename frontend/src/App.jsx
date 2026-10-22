import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import {
  getHealth,
  getStats,
  getIOCs,
  getCorrelatedIOCs,
  collectCTI,
  enrichIOC,
  mapAttackBehavior,
  analyzeIOC,
  getSourceCatalog,
} from "./api";

import "./styles.css";

const COUNTRY_NAMES = {
  AF:"Afghanistan", AL:"Albania", DZ:"Algeria", AR:"Argentina", AM:"Armenia",
  AU:"Australia", AT:"Austria", AZ:"Azerbaijan", BD:"Bangladesh", BY:"Belarus",
  BE:"Belgium", BR:"Brazil", BG:"Bulgaria", CA:"Canada", CL:"Chile", CN:"China",
  CO:"Colombia", HR:"Croatia", CY:"Cyprus", CZ:"Czech Republic", DK:"Denmark",
  EG:"Egypt", EE:"Estonia", FI:"Finland", FR:"France", GE:"Georgia", DE:"Germany",
  GR:"Greece", HK:"Hong Kong", HU:"Hungary", IS:"Iceland", IN:"India",
  ID:"Indonesia", IR:"Iran", IQ:"Iraq", IE:"Ireland", IL:"Israel", IT:"Italy",
  JP:"Japan", JO:"Jordan", KZ:"Kazakhstan", KE:"Kenya", KR:"South Korea",
  KW:"Kuwait", LV:"Latvia", LB:"Lebanon", LT:"Lithuania", LU:"Luxembourg",
  MY:"Malaysia", MX:"Mexico", MD:"Moldova", MN:"Mongolia", ME:"Montenegro",
  MA:"Morocco", NP:"Nepal", NL:"Netherlands", NZ:"New Zealand", NG:"Nigeria",
  NO:"Norway", PK:"Pakistan", PA:"Panama", PE:"Peru", PH:"Philippines",
  PL:"Poland", PT:"Portugal", QA:"Qatar", RO:"Romania", RU:"Russia",
  SA:"Saudi Arabia", RS:"Serbia", SG:"Singapore", SK:"Slovakia", SI:"Slovenia",
  ZA:"South Africa", ES:"Spain", LK:"Sri Lanka", SE:"Sweden", CH:"Switzerland",
  TW:"Taiwan", TH:"Thailand", TR:"Turkey", UA:"Ukraine",
  AE:"United Arab Emirates", GB:"United Kingdom", US:"United States",
  UZ:"Uzbekistan", VN:"Vietnam",
};

function countryName(value) {
  if (!value) return "Not available";
  const key = String(value).trim().toUpperCase();
  return COUNTRY_NAMES[key] || String(value);
}

function priorityClass(value) {
  return `priority-${String(value || "low").toLowerCase()}`;
}

function safeSourceCount(record) {
  if (Array.isArray(record?.sources) && record.sources.length) {
    return record.sources.length;
  }
  return Number(record?.source_count || 0);
}

function formatTactic(value) {
  if (!value) return "Not available";
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (x) => x.toUpperCase());
}

function formatKey(value) {
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (x) => x.toUpperCase());
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function Icon({ name, size = 18 }) {
  const paths = {
    shield: <><path d="M12 3l7 3v5c0 5-3.3 8.2-7 10-3.7-1.8-7-5-7-10V6l7-3Z"/><path d="M9 12l2 2 4-5"/></>,
    activity: <><path d="M3 12h4l2-7 4 14 2-7h6"/></>,
    layers: <><path d="m12 3 8 4-8 4-8-4 8-4Z"/><path d="m4 12 8 4 8-4"/><path d="m4 17 8 4 8-4"/></>,
    database: <><ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v7c0 1.7 3.1 3 7 3s7-1.3 7-3V5"/><path d="M5 12v7c0 1.7 3.1 3 7 3s7-1.3 7-3v-7"/></>,
    link: <><path d="M10 13a5 5 0 0 0 7.1.1l1.4-1.4a5 5 0 0 0-7.1-7.1L10.3 5.7"/><path d="M14 11a5 5 0 0 0-7.1-.1l-1.4 1.4a5 5 0 0 0 7.1 7.1l1.1-1.1"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    crosshair: <><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></>,
    zap: <path d="m13 2-9 12h7l-1 8 9-13h-7l1-7Z"/>,
    globe: <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/></>,
    terminal: <><path d="m4 5 6 7-6 7"/><path d="M12 19h8"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    refresh: <><path d="M20 11a8 8 0 0 0-14.9-3L3 11"/><path d="M3 5v6h6"/><path d="M4 13a8 8 0 0 0 14.9 3L21 13"/><path d="M21 19v-6h-6"/></>,
    arrow: <path d="M5 12h14M13 6l6 6-6 6"/>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true">
      {paths[name] || paths.activity}
    </svg>
  );
}

function App() {
  const [stats, setStats] = useState(null);
  const [records, setRecords] = useState([]);
  const [correlated, setCorrelated] = useState([]);
  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [health, setHealth] = useState("checking");
  const [loading, setLoading] = useState(true);
  const [collecting, setCollecting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [pageOffset, setPageOffset] = useState(0);
  const [recordTotal, setRecordTotal] = useState(0);
  const [behavior, setBehavior] = useState("");
  const [activeView, setActiveView] = useState("overview");
  const [evaluation, setEvaluation] = useState(null);
  const [sourceCatalog, setSourceCatalog] = useState([]);
  const [sourceStatuses, setSourceStatuses] = useState([]);
  const [lastCollection, setLastCollection] = useState(null);

  async function loadDashboard(
    showLoader = true,
    selectedType = typeFilter,
    selectedOffset = pageOffset
  ) {
    try {
      if (showLoader) setLoading(true);
      setError("");
      const [statsData, iocData, correlatedData, evaluationResponse, sourceResponse] = await Promise.all([
        getStats(),
        getIOCs(100, selectedOffset, selectedType),
        getCorrelatedIOCs(100, 0),
        fetch("http://127.0.0.1:8000/api/v1/research/evaluation")
          .then((response) => response.ok ? response.json() : null)
          .catch(() => null),
        getSourceCatalog().catch(() => null),
      ]);
      setStats(statsData || {});
      setRecords(iocData?.records || []);
      setRecordTotal(Number(iocData?.total || 0));
      setCorrelated(correlatedData?.records || []);
      setEvaluation(evaluationResponse?.evaluation || null);
      setSourceCatalog(sourceResponse?.sources || []);
      try {
        await getHealth();
        setHealth("online");
      } catch {
        setHealth("offline");
      }
    } catch (err) {
      setError(err.message || "Unable to connect to the CTI backend.");
      setHealth("offline");
    } finally {
      if (showLoader) setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  async function handleCollect() {
    try {
      setCollecting(true);
      setError("");
      const collectionResult = await collectCTI();
      setSourceStatuses(collectionResult?.sources || []);
      setLastCollection({
        status: collectionResult?.status || "unknown",
        collected: Number(collectionResult?.collected_count || 0),
        correlated: Number(collectionResult?.correlated_count || 0),
        successful: (collectionResult?.sources || []).filter((source) => source.status === "success").length,
        failed: (collectionResult?.sources || []).filter((source) => source.status === "error").length,
      });
      setPageOffset(0);
      setSearch("");
      await loadDashboard(false, typeFilter, 0);
    } catch (err) {
      setError(err.message || "CTI collection failed.");
    } finally {
      setCollecting(false);
    }
  }

  async function handleTypeFilterChange(nextType) {
    setTypeFilter(nextType);
    setPageOffset(0);
    setSearch("");
    setError("");
    try {
      const response = await getIOCs(100, 0, nextType);
      setRecords(response?.records || []);
      setRecordTotal(Number(response?.total || 0));
    } catch (err) {
      setError(err.message || "Unable to load this IOC type.");
    }
  }

  async function handlePageChange(nextOffset) {
    const safeOffset = Math.max(0, nextOffset);
    if (safeOffset === pageOffset) return;
    setPageOffset(safeOffset);
    setSearch("");
    setError("");
    try {
      const response = await getIOCs(100, safeOffset, typeFilter);
      setRecords(response?.records || []);
      setRecordTotal(Number(response?.total || 0));
    } catch (err) {
      setError(err.message || "Unable to load the requested IOC page.");
    }
  }

  async function openIOC(record) {
    setSelected(record);
    setAnalysis(null);
    const observedBehavior = typeof record.behavior_text === "string"
      ? record.behavior_text.trim()
      : "";
    setBehavior(observedBehavior);
    setAnalyzing(true);
    setError("");
    try {
      const enrichmentResponse = await enrichIOC(
        record.ioc_type,
        record.ioc_value
      );
      const enrichment = enrichmentResponse?.enrichment || null;

      let complete = null;
      try {
        complete = await analyzeIOC({
          iocType: record.ioc_type,
          iocValue: record.ioc_value,
          sourceCount: safeSourceCount(record),
          enrichment,
          behaviorText: observedBehavior,
        });
      } catch (analysisError) {
        // Never invent behavioral evidence when complete analysis fails.
        // Fall back only to the stored IOC score and observed source data.
        complete = {
          status: "partial",
          analysis_error: analysisError.message || "Complete analysis failed.",
          ioc: {
            ioc_type: record.ioc_type,
            ioc_value: record.ioc_value,
          },
          source_count: safeSourceCount(record),
          enrichment,
          behavior_text: observedBehavior,
          attack_mappings: [],
          priority: {
            score: record.priority_score || 0,
            priority: record.priority || "Low",
            components: record.priority_components || {},
          },
        };
      }
      setAnalysis(complete);
    } catch (err) {
      setAnalysis({
        status: "partial",
        enrichment: {
          rdap_status: "error",
          error: err.message || "Enrichment failed.",
        },
        attack_mappings: [],
        priority: {
          score: record.priority_score || 0,
          priority: record.priority || "Low",
          components: record.priority_components || {},
        },
      });
    } finally {
      setAnalyzing(false);
    }
  }

  async function remapBehavior() {
    const evidenceText = behavior.trim();
    if (!evidenceText || !selected) return;

    try {
      setAnalyzing(true);
      setError("");

      const enrichmentResponse = await enrichIOC(
        selected.ioc_type,
        selected.ioc_value
      );
      const enrichmentData = enrichmentResponse?.enrichment || null;

      // Re-run the complete transparent scoring pipeline.
      // ATT&CK points are added only for the behavioral evidence
      // explicitly supplied in this investigation field.
      const complete = await analyzeIOC({
        iocType: selected.ioc_type,
        iocValue: selected.ioc_value,
        sourceCount: safeSourceCount(selected),
        enrichment: enrichmentData,
        behaviorText: evidenceText,
      });

      setAnalysis(complete);
    } catch (err) {
      setError(err.message || "IOC analysis failed.");
    } finally {
      setAnalyzing(false);
    }
  }

  const total = stats?.statistics?.total ?? stats?.total ?? 0;
  const multiSource = stats?.multi_source_ioc_count ?? 0;
  const priority = stats?.priority_distribution || { High: 0, Medium: 0, Low: 0 };
  const sourceDistribution = stats?.source_distribution || {};
  const sourceCount = Number(stats?.enabled_feed_count ?? stats?.configured_source_count ?? 0);
  const enabledFeedCount = sourceCatalog.filter((source) => source.enabled).length;

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return records;
    return records.filter((r) =>
      `${r.ioc_value || ""} ${r.ioc_type || ""}`.toLowerCase().includes(q)
    );
  }, [records, search]);

  const chartData = Object.entries(stats?.statistics || {})
    .filter(([name, value]) => name !== "total" && Number(value) > 0)
    .map(([name, value]) => ({ name: formatKey(name), value: Number(value) }));

  const priorityData = [
    { name: "High", count: priority.High || 0 },
    { name: "Medium", count: priority.Medium || 0 },
    { name: "Low", count: priority.Low || 0 },
  ];

  const selectedAnalysis = analysis || {};
  const enrichment = selectedAnalysis.enrichment;
  const mappings = selectedAnalysis.attack_mappings || [];
  const components = selectedAnalysis.priority?.components ||
    selected?.priority_components || {};

  const statistics = stats?.statistics || {};
  const uniqueIocs = Number(statistics.total ?? total ?? 0);
  const correlationRate = total > 0 ? (multiSource / total) * 100 : 0;
  const sourceOccurrences = Object.values(sourceDistribution).reduce(
    (sum, value) => sum + Number(value || 0),
    0
  );
  const sourceOverlapRate = total > 0 ? (sourceOccurrences / total) : 0;
  const loadedAnalysisCount = records.length;
  const measuredRaw = Number(evaluation?.raw_iocs || 0);
  const measuredUnique = Number(evaluation?.unique_after_correlation || 0);
  const measuredRemoved = Number(evaluation?.overlap_or_duplicates_removed || 0);
  const measuredReduction = Number(evaluation?.duplicate_reduction_percent || 0);
  const measuredSeconds = Number(evaluation?.processing_time_seconds || 0);
  const measuredThroughput = Number(evaluation?.throughput_records_per_second || 0);
  const evaluationRecorded = Boolean(evaluation);
  const latestCrossSourceMatches = Number(evaluation?.cross_source_matches || 0);
  const latestCorrelationRate = measuredUnique > 0
    ? (latestCrossSourceMatches / measuredUnique) * 100
    : 0;

  const evaluationCards = [
    {
      label: "STORED DATASET",
      value: formatNumber(total),
      note: "all currently stored IOC records",
      tone: "cyan",
    },
    {
      label: "LATEST RAW COLLECTION",
      value: evaluationRecorded ? formatNumber(measuredRaw) : "—",
      note: evaluationRecorded ? "feed-level IOC observations in latest run" : "run Collect CTI to measure",
      tone: "blue",
    },
    {
      label: "LATEST CORRELATED SET",
      value: evaluationRecorded ? formatNumber(measuredUnique) : "—",
      note: evaluationRecorded ? `${formatNumber(measuredRemoved)} overlap records removed in latest run` : "run Collect CTI to measure",
      tone: "purple",
    },
    {
      label: "SOURCE COVERAGE",
      value: formatNumber(sourceCount),
      note: `${sourceOccurrences.toLocaleString()} stored source associations`,
      tone: "green",
    },
  ];

  return (
    <div className="app-shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />

      <header className="topbar">
        <div className="brand-block">
          <div className="brand-mark"><Icon name="shield" size={22} /></div>
          <div>
            <div className="brand-name">CTI<span>CORE</span></div>
            <div className="brand-sub">THREAT INTELLIGENCE // RESEARCH CONSOLE</div>
          </div>
        </div>

        <nav className="topnav">
          <button className={activeView === "overview" ? "nav-active" : ""} onClick={() => setActiveView("overview")}>Overview</button>
          <button onClick={() => document.getElementById("records")?.scrollIntoView({ behavior: "smooth" })}>Indicators</button>
          <button onClick={() => document.getElementById("correlation")?.scrollIntoView({ behavior: "smooth" })}>Correlation</button>
          <button onClick={() => document.getElementById("sources")?.scrollIntoView({ behavior: "smooth" })}>Sources</button>
          <button onClick={() => document.getElementById("research")?.scrollIntoView({ behavior: "smooth" })}>Research</button>
        </nav>

        <div className="top-actions">
          <div className={`connection ${health}`}>
            <span className="pulse-dot" />
            {health === "online" ? "BACKEND ONLINE" : health === "checking" ? "CONNECTING" : "BACKEND OFFLINE"}
          </div>
          <button className="collect-cta" onClick={handleCollect} disabled={collecting}>
            <Icon name={collecting ? "refresh" : "zap"} size={15} />
            {collecting ? "COLLECTING" : "COLLECT CTI"}
          </button>
        </div>
      </header>

      <main className="main-content">
        {error && (
          <div className="error-strip">
            <span>{error}</span>
            <button onClick={() => loadDashboard()}><Icon name="refresh" size={14} /> Retry</button>
          </div>
        )}

        <section className="hero-section">
          <div className="hero-copy">
            <div className="hero-kicker"><span className="live-dot" /> SECURITY OPERATIONS / CTI LAB</div>
            <h1>See the signal.<br /><span>Correlate the threat.</span></h1>
            <p>Automated multi-source intelligence for collecting, correlating, enriching and prioritizing threat indicators.</p>
            <div className="hero-actions">
              <button className="hero-primary" onClick={() => document.getElementById("records")?.scrollIntoView({ behavior: "smooth" })}>
                Investigate IOCs <Icon name="arrow" size={16} />
              </button>
              <span className="research-pill"><span /> RESEARCH MVP · LOCAL + PUBLIC CTI</span>
            </div>
          </div>

          <div className="hero-terminal">
            <div className="terminal-top">
              <div className="terminal-dots"><i /><i /><i /></div>
              <span>cti-core://live-feed</span>
              <span className="terminal-status">LIVE</span>
            </div>
            <div className="terminal-body">
              <div><b>$</b> cti.collect --sources=all</div>
              <div className="terminal-muted">→ {formatNumber(sourceCount)} enabled feeds <em>CONFIGURED</em></div>
              <div className="terminal-muted">→ typed IOC extraction <em>IP / DOMAIN / URL / HASH</em></div>
              <div className="terminal-muted">→ rdap enrichment .... <em>READY</em></div>
              <div className="terminal-divider" />
              <div><b>✓</b> <span className="terminal-green">{formatNumber(total)}</span> indicators indexed</div>
              <div><b>✓</b> <span className="terminal-cyan">{formatNumber(multiSource)}</span> cross-source matches</div>
              <div className="terminal-cursor">_</div>
            </div>
          </div>
        </section>

        <section className="stat-grid">
          <div className="metric-card metric-blue">
            <div className="metric-icon"><Icon name="database" /></div>
            <div className="metric-label">TOTAL IOCs</div>
            <div className="metric-value">{loading ? "—" : formatNumber(total)}</div>
            <div className="metric-foot">stored indicators <span>● LIVE</span></div>
          </div>
          <div className="metric-card metric-cyan">
            <div className="metric-icon"><Icon name="link" /></div>
            <div className="metric-label">MULTI-SOURCE</div>
            <div className="metric-value">{loading ? "—" : formatNumber(multiSource)}</div>
            <div className="metric-foot">observed across feeds <span>↗ correlated</span></div>
          </div>
          <div className="metric-card metric-red">
            <div className="metric-icon"><Icon name="activity" /></div>
            <div className="metric-label">HIGH PRIORITY</div>
            <div className="metric-value">{loading ? "—" : formatNumber(priority.High)}</div>
            <div className="metric-foot">research triage signal <span>ATTENTION</span></div>
          </div>
          <div className="metric-card metric-purple">
            <div className="metric-icon"><Icon name="layers" /></div>
            <div className="metric-label">ENABLED FEEDS</div>
            <div className="metric-value">{loading ? "—" : sourceCount}</div>
            <div className="metric-foot">{sourceCatalog.length || stats?.configured_source_count || 0} catalogued sources <span>FEED PROFILE</span></div>
          </div>
        </section>

        <section className="section-block">
          <div className="section-title-row">
            <div>
              <div className="section-kicker">01 / TELEMETRY</div>
              <h2>Threat landscape <span>at a glance</span></h2>
            </div>
            <div className="mini-legend"><span className="legend-dot cyan" /> live dataset</div>
          </div>

          <div className="chart-grid">
            <div className="panel chart-panel">
              <div className="panel-head">
                <div><span className="panel-icon"><Icon name="layers" size={15} /></span><strong>IOC DISTRIBUTION</strong></div>
                <span className="panel-tag">BY TYPE</span>
              </div>
              <div className="chart-wrap">
                {chartData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="47%" innerRadius={72} outerRadius={108} paddingAngle={3} stroke="none">
                        {chartData.map((_, i) => <Cell key={i} fill={["#37e8ff","#6d5dfc","#ff4fd8","#ff9f43","#67f59b","#9b8cff"][i % 6]} />)}
                      </Pie>
                      <RechartsTooltip contentStyle={{ background:"#101522", border:"1px solid #27334a", borderRadius:12, color:"#fff" }} />
                      <Legend verticalAlign="bottom" height={32} iconType="circle" wrapperStyle={{fontSize:11, color:"#8794aa"}} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <div className="empty-chart">No IOC data available.</div>}
              </div>
              <div className="chart-total"><b>{formatNumber(total)}</b> <span>total indicators</span></div>
            </div>

            <div className="panel chart-panel">
              <div className="panel-head">
                <div><span className="panel-icon purple"><Icon name="activity" size={15} /></span><strong>PRIORITY DISTRIBUTION</strong></div>
                <span className="panel-tag">TRIAGE</span>
              </div>
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={priorityData} margin={{ top: 15, right: 8, left: -22, bottom: 8 }}>
                    <CartesianGrid stroke="#202a3d" strokeDasharray="3 5" vertical={false} />
                    <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill:"#78869d", fontSize:11 }} />
                    <YAxis axisLine={false} tickLine={false} allowDecimals={false} tick={{ fill:"#78869d", fontSize:10 }} />
                    <RechartsTooltip contentStyle={{ background:"#101522", border:"1px solid #27334a", borderRadius:12, color:"#fff" }} />
                    <Bar dataKey="count" radius={[8,8,2,2]} maxBarSize={64}>
                      {priorityData.map((x) => <Cell key={x.name} fill={x.name === "High" ? "#ff4d6d" : x.name === "Medium" ? "#ffb84d" : "#53e6a7"} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="priority-strip">
                <span><i className="dot red" /> High <b>{formatNumber(priority.High)}</b></span>
                <span><i className="dot amber" /> Medium <b>{formatNumber(priority.Medium)}</b></span>
                <span><i className="dot green" /> Low <b>{formatNumber(priority.Low)}</b></span>
              </div>
            </div>
          </div>
        </section>

        <section id="records" className="section-block">
          <div className="section-title-row">
            <div>
              <div className="section-kicker">02 / INDICATORS</div>
              <h2>Threat intelligence <span>records</span></h2>
            </div>
            <div className="record-chip">{formatNumber(filtered.length)} shown · {formatNumber(recordTotal)} matching type</div>
          </div>

          <div className="panel table-panel">
            <div className="table-toolbar">
              <div className="table-controls">
                <div className="search-box">
                  <Icon name="search" size={17} />
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search within this page..." />
                  {search && <button onClick={() => setSearch("")}>×</button>}
                </div>
                <select
                  className="type-filter"
                  value={typeFilter}
                  onChange={(e) => handleTypeFilterChange(e.target.value)}
                  aria-label="Filter indicators by IOC type"
                >
                  <option value="all">All IOC types</option>
                  <option value="ip">IP address</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="sha256">SHA-256 hash</option>
                  <option value="sha1">SHA-1 hash</option>
                  <option value="md5">MD5 hash</option>
                  <option value="cve">CVE</option>
                </select>
              </div>
              <div className="toolbar-note"><span /> click any row to investigate</div>
            </div>

            {loading ? (
              <div className="table-empty"><div className="loader-ring" /><b>Syncing CTI records…</b><span>Loading the local intelligence index.</span></div>
            ) : filtered.length === 0 ? (
              <div className="table-empty"><Icon name="search" size={24} /><b>No matching indicators</b><span>Try another search term.</span></div>
            ) : (
              <div className="table-scroll">
                <table className="intel-table">
                  <thead><tr><th>Indicator</th><th>Type</th><th>Sources</th><th>Confidence</th><th>Score</th><th>Priority</th></tr></thead>
                  <tbody>
                    {filtered.map((record, index) => {
                      const sources = safeSourceCount(record);
                      return (
                        <tr key={`${record.ioc_type}-${record.ioc_value}-${index}`} onClick={() => openIOC(record)}>
                          <td><code className="ioc-code">{record.ioc_value}</code></td>
                          <td><span className="type-chip">{record.ioc_type}</span></td>
                          <td><span className="source-count">{sources}<small>{sources === 1 ? " source" : " sources"}</small></span></td>
                          <td><div className="confidence-cell"><span>{record.confidence || 0}%</span><div><i style={{width:`${Math.min(Number(record.confidence || 0),100)}%`}} /></div></div></td>
                          <td><b className="score-number">{record.priority_score ?? 0}</b></td>
                          <td><span className={`priority-chip ${priorityClass(record.priority)}`}><i />{record.priority || "Low"}</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <div className="table-pagination">
              <span>
                Page {Math.floor(pageOffset / 100) + 1}
                {recordTotal > 0 ? ` · ${formatNumber(recordTotal)} records for this type` : " · No records"}
              </span>
              <div>
                <button
                  type="button"
                  onClick={() => handlePageChange(pageOffset - 100)}
                  disabled={pageOffset <= 0}
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => handlePageChange(pageOffset + 100)}
                  disabled={pageOffset + records.length >= recordTotal || records.length === 0}
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </section>

        <section id="correlation" className="section-block">
          <div className="section-title-row">
            <div>
              <div className="section-kicker">03 / CORRELATION</div>
              <h2>Cross-source <span>matches</span></h2>
            </div>
            <div className="correlation-count"><Icon name="link" size={14} /> {formatNumber(multiSource)} MATCHES</div>
          </div>

          <div className="panel correlation-panel">
            <div className="correlation-intro">
              <div className="correlation-orbit"><Icon name="link" size={21} /></div>
              <div><b>Evidence overlap detected</b><span>These indicators appear in at least two configured CTI sources.</span></div>
            </div>
            <div className="correlation-list">
              {correlated.slice(0, 12).map((record, index) => (
                <button key={`${record.ioc_value}-${index}`} onClick={() => openIOC(record)}>
                  <code>{record.ioc_value}</code>
                  <span>{record.ioc_type}</span>
                  <em>{safeSourceCount(record)} sources</em>
                  <strong className={priorityClass(record.priority)}>{record.priority || "Low"}</strong>
                  <Icon name="arrow" size={15} />
                </button>
              ))}
              {!correlated.length && <div className="table-empty"><b>No correlated records</b><span>Run CTI collection to refresh the dataset.</span></div>}
            </div>
          </div>
        </section>


        <section id="sources" className="section-block">
          <div className="section-title-row">
            <div>
              <div className="section-kicker">04 / SOURCE INTELLIGENCE</div>
              <h2>Feed coverage <span>& health</span></h2>
            </div>
            <div className="mini-legend"><span className="legend-dot cyan" /> {enabledFeedCount || sourceCount} enabled · {sourceCatalog.length} catalogued</div>
          </div>

          {lastCollection && (
            <div className="collection-summary panel">
              <div><small>LAST COLLECTION</small><b>{String(lastCollection.status).toUpperCase()} · {lastCollection.successful} / {sourceStatuses.length} feeds</b></div>
              <div><small>RAW OBSERVATIONS</small><b>{formatNumber(lastCollection.collected)}</b></div>
              <div><small>CORRELATED RECORDS</small><b>{formatNumber(lastCollection.correlated)}</b></div>
              <div><small>FEED ERRORS</small><b className={lastCollection.failed ? "source-error-text" : "source-ok-text"}>{lastCollection.failed}</b></div>
            </div>
          )}

          <div className="panel source-panel">
            <div className="panel-head">
              <div><span className="panel-icon"><Icon name="globe" size={15} /></span><strong>PUBLIC CTI SOURCE REGISTRY</strong></div>
              <span className="panel-tag">AUDITABLE</span>
            </div>
            <p className="source-explainer">Configured sources are not assumed to be reachable. Status is based on the most recent collection attempt; sources requiring credentials or not enabled for automatic collection are clearly identified.</p>
            <div className="source-grid">
              {sourceCatalog.map((source) => {
                const latest = sourceStatuses.find((item) => item.source_name === source.name);
                const state = latest?.status || (source.enabled ? "enabled" : (source.license === "API key" ? "key required" : "catalog only"));
                return (
                  <div className="source-row" key={source.name}>
                    <div className="source-row-main">
                      <b>{source.name}</b>
                      <span>{(source.types || []).join(" · ")}</span>
                    </div>
                    <span className={`source-state source-state-${String(state).replaceAll(" ", "-")}`}>{state}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section id="research" className="section-block">
          <div className="section-title-row">
            <div>
              <div className="section-kicker">05 / RESEARCH</div>
              <h2>Research <span>& evaluation</span></h2>
            </div>
            <div className="mini-legend"><span className="legend-dot cyan" /> calculated from live dataset</div>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: "14px",
            marginBottom: "18px"
          }}>
            {evaluationCards.map((card) => (
              <div key={card.label} className={`panel evaluation-card evaluation-${card.tone}`} style={{padding:"22px", minHeight:"145px"}}>
                <div style={{fontSize:"10px", letterSpacing:".16em", color:"#73819a", marginBottom:"12px"}}>{card.label}</div>
                <div style={{fontSize:"30px", fontWeight:800, letterSpacing:"-.04em", color:"#eef5ff"}}>{card.value}</div>
                <div style={{fontSize:"11px", color:"#71809a", marginTop:"8px"}}>{card.note}</div>
              </div>
            ))}
          </div>

          <div style={{
            display:"grid",
            gridTemplateColumns:"1.25fr .75fr",
            gap:"18px"
          }}>
            <div className="panel" style={{padding:"24px"}}>
              <div className="panel-head" style={{marginBottom:"20px"}}>
                <div><span className="panel-icon"><Icon name="activity" size={15} /></span><strong>EXPERIMENTAL EVIDENCE</strong></div>
                <span className="panel-tag">LIVE</span>
              </div>

              <div style={{display:"grid", gap:"16px"}}>
                <div>
                  <div style={{display:"flex", justifyContent:"space-between", gap:"12px", marginBottom:"7px"}}>
                    <span style={{color:"#b7c3d8", fontSize:"12px"}}>Stored-dataset cross-source rate</span>
                    <b style={{color:"#37e8ff", fontSize:"12px"}}>{correlationRate.toFixed(2)}%</b>
                  </div>
                  <div style={{height:"7px", background:"#172238", borderRadius:"99px", overflow:"hidden"}}>
                    <div style={{height:"100%", width:`${Math.min(correlationRate,100)}%`, background:"linear-gradient(90deg,#37e8ff,#6d5dfc)", borderRadius:"99px"}} />
                  </div>
                  <small style={{display:"block", color:"#64728a", marginTop:"6px"}}>{formatNumber(multiSource)} stored indicators are associated with at least two configured sources.</small>
                  {evaluationRecorded && (
                    <small style={{display:"block", color:"#64728a", marginTop:"4px"}}>Latest run: {formatNumber(latestCrossSourceMatches)} cross-source matches across {formatNumber(measuredUnique)} correlated records ({latestCorrelationRate.toFixed(2)}%).</small>
                  )}
                </div>

                <div style={{display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:"10px"}}>
                  <div style={{padding:"13px", border:"1px solid #243149", borderRadius:"10px", background:"#0b1220"}}><small style={{display:"block", color:"#71809a", fontSize:"9px", letterSpacing:".14em"}}>HIGH</small><b style={{display:"block", marginTop:"5px", fontSize:"20px", color:"#eef5ff"}}>{formatNumber(priority.High)}</b></div>
                  <div style={{padding:"13px", border:"1px solid #243149", borderRadius:"10px", background:"#0b1220"}}><small style={{display:"block", color:"#71809a", fontSize:"9px", letterSpacing:".14em"}}>MEDIUM</small><b style={{display:"block", marginTop:"5px", fontSize:"20px", color:"#eef5ff"}}>{formatNumber(priority.Medium)}</b></div>
                  <div style={{padding:"13px", border:"1px solid #243149", borderRadius:"10px", background:"#0b1220"}}><small style={{display:"block", color:"#71809a", fontSize:"9px", letterSpacing:".14em"}}>LOW</small><b style={{display:"block", marginTop:"5px", fontSize:"20px", color:"#eef5ff"}}>{formatNumber(priority.Low)}</b></div>
                </div>

                <div style={{padding:"14px 16px", border:"1px solid #25324a", borderRadius:"12px", background:"rgba(12,18,30,.7)"}}>
                  <div style={{fontSize:"10px", letterSpacing:".14em", color:"#6f7f99", marginBottom:"7px"}}>INTERPRETATION</div>
                  <div style={{fontSize:"13px", lineHeight:1.65, color:"#aebbd0"}}>
                    Cross-source occurrence is treated as supporting evidence for analyst triage. Stored-dataset statistics and latest-run measurements are shown separately. Cross-source occurrence is not treated as proof that an IOC is malicious.
                  </div>
                </div>
              </div>
            </div>

            <div className="panel" style={{padding:"24px"}}>
              <div className="panel-head" style={{marginBottom:"18px"}}>
                <div><span className="panel-icon purple"><Icon name="layers" size={15} /></span><strong>METRIC READINESS</strong></div>
                <span className="panel-tag">METHOD</span>
              </div>

              <div style={{display:"grid", gap:"10px"}}>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Extraction pipeline</span><b className="status-ok">IMPLEMENTED</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Normalization / dedup</span><b className="status-ok">IMPLEMENTED</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Multi-source correlation</span><b className="status-ok">IMPLEMENTED</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>RDAP enrichment</span><b className="status-muted">ON-DEMAND</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>ATT&CK mapping</span><b className="status-muted">ON-DEMAND</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Pre-dedup baseline</span><b className={evaluationRecorded ? "status-ok" : "status-muted"}>{evaluationRecorded ? formatNumber(measuredRaw) : "NOT RECORDED"}</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Duplicate reduction</span><b className={evaluationRecorded ? "status-ok" : "status-muted"}>{evaluationRecorded ? `${measuredReduction.toFixed(2)}%` : "NOT RECORDED"}</b></div>
                <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:"10px", padding:"11px 0", borderBottom:"1px solid #1d293d"}}><span style={{color:"#aebbd0", fontSize:"12px"}}>Pipeline timing</span><b className={evaluationRecorded ? "status-ok" : "status-muted"}>{evaluationRecorded ? `${measuredSeconds.toFixed(2)} s` : "NOT RECORDED"}</b></div>
              </div>

              <div style={{marginTop:"18px", padding:"13px 15px", borderRadius:"11px", border:"1px dashed #2a3954", color:"#687790", fontSize:"11px", lineHeight:1.55}}>
                Implementation status is shown separately from measured research results. Precision, recall, F1 and correlation ground-truth accuracy require a labelled validation set; they are not fabricated from the live IOC feed.
              </div>
            </div>
          </div>

          <div style={{marginTop:"18px", display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:"14px"}}>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">MEASURED RUN</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Latest raw collection</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>{evaluationRecorded ? `${formatNumber(measuredRaw)} feed-level IOC observations were collected in the latest measured run. This is not the total stored dataset.` : "Run Collect CTI once to create a measured baseline."}</p>
            </div>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">DEDUPLICATION</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Latest correlation reduction</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>{evaluationRecorded ? `${formatNumber(measuredUnique)} correlated records remained from ${formatNumber(measuredRaw)} raw observations; ${formatNumber(measuredRemoved)} overlap records were removed (${measuredReduction.toFixed(2)}%).` : "No measured collection baseline is available yet."}</p>
            </div>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">PERFORMANCE</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Pipeline throughput</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>{evaluationRecorded ? `${formatNumber(measuredThroughput)} records/sec over ${measuredSeconds.toFixed(2)} seconds.` : "Run a real collection to measure throughput."}</p>
            </div>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">REPRODUCIBILITY</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Latest measurement</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>{evaluationRecorded ? `Recorded ${evaluation.recorded_at}. Values come from the latest actual CTI collection run.` : "Metrics are intentionally blank until an actual collection run is recorded."}</p>
            </div>
          </div>

          <div style={{marginTop:"18px", display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:"14px"}}>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">DATA QUALITY</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Normalization & deduplication</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>The latest collection run now records a feed-level baseline and the correlated unique set. This allows the dashboard to report the observed overlap / duplicate reduction for that run.</p>
            </div>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">ENRICHMENT</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Contextual evidence</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>RDAP is executed when an analyst investigates an IOC. The selected IOC drawer therefore provides direct enrichment evidence without pretending that all {formatNumber(total)} records were enriched.</p>
            </div>
            <div className="panel" style={{padding:"20px"}}>
              <div className="section-kicker">ATT&CK</div>
              <h3 style={{margin:"7px 0 6px", color:"#e9f1ff"}}>Behavioral mapping</h3>
              <p style={{margin:0, color:"#71809a", fontSize:"12px", lineHeight:1.6}}>ATT&CK mappings are evidence-based and behavior-driven. An IOC itself is not automatically assigned a technique.</p>
            </div>
          </div>

          <div style={{marginTop:"14px", color:"#596981", fontSize:"10px", letterSpacing:".1em"}}>
            CURRENT ANALYSIS WINDOW: {loadedAnalysisCount} RECORDS · DATASET: {formatNumber(total)} IOCs · SOURCES: {sourceCount}
          </div>
        </section>

        <section className="method-strip">
          <div><span className="method-no">01</span><b>COLLECT</b><small>public CTI feeds</small></div>
          <div className="method-line" />
          <div><span className="method-no">02</span><b>NORMALIZE</b><small>standardized IOCs</small></div>
          <div className="method-line" />
          <div><span className="method-no">03</span><b>CORRELATE</b><small>cross-source evidence</small></div>
          <div className="method-line" />
          <div><span className="method-no">04</span><b>ENRICH</b><small>RDAP context</small></div>
          <div className="method-line" />
          <div><span className="method-no">05</span><b>MAP</b><small>MITRE ATT&CK</small></div>
          <div className="method-line" />
          <div><span className="method-no">06</span><b>PRIORITIZE</b><small>transparent scoring</small></div>
        </section>
      </main>

      <footer className="footer">
        <span>CTI<span>CORE</span> · Automated Multi-Source CTI</span>
        <span>Academic Research MVP · FastAPI + React</span>
        <span>LOCAL CONSOLE / 2026</span>
      </footer>

      {selected && (
        <div className="drawer-backdrop" onClick={() => !analyzing && setSelected(null)}>
          <aside className="investigator-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-head">
              <div>
                <div className="drawer-kicker"><span className="live-dot" /> IOC INVESTIGATION</div>
                <h2>{selected.ioc_value}</h2>
                <div className="drawer-meta"><span>{selected.ioc_type}</span><span>•</span><span>{safeSourceCount(selected)} source{safeSourceCount(selected) === 1 ? "" : "s"}</span></div>
              </div>
              <button className="drawer-close" onClick={() => setSelected(null)}><Icon name="close" /></button>
            </div>

            {analyzing ? (
              <div className="analysis-loading">
                <div className="loader-ring large" />
                <b>Running IOC analysis</b>
                <span>RDAP enrichment → behavioral mapping → research priority</span>
              </div>
            ) : (
              <>
                <div className="drawer-metrics">
                  <div><small>CONFIDENCE</small><b>{selectedAnalysis?.confidence ?? selected.confidence ?? 0}%</b></div>
                  <div><small>PRIORITY SCORE</small><b>{selectedAnalysis?.priority?.score ?? selected.priority_score ?? 0}</b></div>
                  <div><small>PRIORITY</small><strong className={`priority-chip ${priorityClass(selectedAnalysis?.priority?.priority || selected.priority)}`}><i />{selectedAnalysis?.priority?.priority || selected.priority || "Low"}</strong></div>
                </div>

                <div className="drawer-section">
                  <div className="drawer-section-head"><div><span className="section-kicker">01 / ENRICHMENT</span><h3>RDAP registration intelligence</h3></div><span className={enrichment?.rdap_status === "success" ? "status-ok" : "status-muted"}>{enrichment?.rdap_status === "success" ? "● DATA AVAILABLE" : "● NO DATA"}</span></div>
                  {enrichment?.rdap_status === "success" ? (
                    <>
                      <div className="rdap-grid">
                        <div><small>ORGANIZATION / NAME</small><b>{enrichment.name || "Not available"}</b></div>
                        <div><small>NETWORK HANDLE</small><b>{enrichment.handle || "Not available"}</b></div>
                        <div><small>COUNTRY</small><b>{countryName(enrichment.country)}</b></div>
                        <div><small>ALLOCATION TYPE</small><b>{enrichment.type || "Not available"}</b></div>
                        <div><small>START ADDRESS</small><b>{enrichment.start_address || "Not available"}</b></div>
                        <div><small>END ADDRESS</small><b>{enrichment.end_address || "Not available"}</b></div>
                      </div>
                      <div className="entity-row"><small>REGISTERED ENTITIES</small><div>{(enrichment.entities || []).length ? enrichment.entities.map((x, i) => <span key={`${x}-${i}`}>{x}</span>) : <em>None returned</em>}</div></div>
                    </>
                  ) : (
                    <div className="subtle-message">{enrichment?.error || "No RDAP registration data was available for this IOC."}</div>
                  )}
                </div>

                <div className="drawer-section">
                  <div className="drawer-section-head"><div><span className="section-kicker">02 / BEHAVIOR</span><h3>MITRE ATT&CK mapping</h3></div><span className="status-muted">EVIDENCE-BASED</span></div>
                  <div className="behavior-box">
                    <div className="behavior-label"><Icon name="terminal" size={14} /> CTI BEHAVIORAL EVIDENCE — SOURCE-SUPPLIED ONLY</div>
                    <textarea
                      value={behavior}
                      onChange={(e) => setBehavior(e.target.value)}
                      placeholder="No source-supplied behavioral evidence is stored for this IOC. Paste evidence from a CTI report only if available."
                    />
                    <button className="map-button" onClick={remapBehavior} disabled={analyzing || !behavior.trim()}><Icon name="zap" size={14} /> MAP TO ATT&CK</button>
                  </div>

                  <div className="attack-results-modern">
                    <div className="result-count">{mappings.length} technique{mappings.length === 1 ? "" : "s"} identified</div>
                    {!mappings.length && (
                      <div className="subtle-message">No source-supplied behavioral evidence was available, so no MITRE ATT&CK techniques were inferred for this IOC.</div>
                    )}
                    {mappings.length ? mappings.map((mapping, i) => {
                      const conf = Math.round(Number(mapping.mapping_confidence ?? mapping.confidence ?? 0) * 100);
                      const tactics = mapping.tactics?.length ? mapping.tactics.map(formatTactic).join(", ") : mapping.tactic ? formatTactic(mapping.tactic) : "Not available";
                      const keywords = mapping.evidence?.matched_keywords || mapping.matched_keywords || [];
                      return (
                        <div className="attack-modern-card" key={`${mapping.technique_id}-${i}`}>
                          <div className="attack-modern-top"><code>{mapping.technique_id || "UNKNOWN"}</code><b>{conf}%</b></div>
                          <h4>{mapping.technique_name || mapping.name || "Unknown Technique"}</h4>
                          <div className="attack-tactic"><span>TACTIC</span><b>{tactics}</b></div>
                          <div className="attack-evidence-row"><span>MATCHED EVIDENCE</span><div>{(Array.isArray(keywords) ? keywords : [keywords]).map((k, j) => <em key={`${k}-${j}`}>{k}</em>)}</div></div>
                        </div>
                      );
                    }) : <div className="subtle-message">No ATT&CK techniques identified by the configured evidence-based rules.</div>}
                  </div>
                </div>

                <div className="drawer-section">
                  <div className="drawer-section-head"><div><span className="section-kicker">03 / SCORING</span><h3>Transparent priority model</h3></div><span className="status-muted">100 PT MAX</span></div>
                  <div className="score-modern">
                    {Object.entries(components).map(([key, value]) => <div key={key}><small>{formatKey(key)}</small><b>{value}</b></div>)}
                  </div>
                </div>

                {selected.sources?.length > 0 && (
                  <div className="drawer-section">
                    <div className="drawer-section-head"><div><span className="section-kicker">04 / PROVENANCE</span><h3>Observed sources</h3></div></div>
                    <div className="entity-row"><div>{selected.sources.map((x) => <span key={x}>{x}</span>)}</div></div>
                    {selected.source_url && <a className="source-link" href={selected.source_url} target="_blank" rel="noreferrer">{selected.source_url}</a>}
                  </div>
                )}
              </>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

export default App;
