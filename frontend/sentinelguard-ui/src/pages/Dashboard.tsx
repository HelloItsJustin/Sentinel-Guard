import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { getIncidents } from "../api/sentinelguard";
import type { Incident, PolicyConfig } from "../api/types";
import { SeverityChip } from "../components/SeverityChip";
import { IssueChip, IssueChipList } from "../components/IssueChip";
import { Modal } from "../components/Modal";
import { CopyButton } from "../components/CopyButton";
import { Icon, type IconName } from "../components/Icon";

const PROTECTED_STORAGE_MARKER = "[PROTECTED ORIGINAL STORED AS SANITIZED PREVIEW]";
const HAS_TIMEZONE_RE = /(?:Z|[+-]\d{2}:?\d{2})$/;

function formatTs(ts: string): string {
  const normalizedTs = HAS_TIMEZONE_RE.test(ts) ? ts : `${ts}Z`;
  const date = new Date(normalizedTs);
  if (Number.isNaN(date.getTime())) return ts;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  }).format(date);
}

function parseIssues(issuesJson: string): string[] {
  try {
    const parsed = JSON.parse(issuesJson);
    return Array.isArray(parsed) ? parsed.map(String) : [String(parsed)];
  } catch {
    return issuesJson ? [issuesJson] : [];
  }
}

function parsePolicySnapshot(snapshot: string | null): PolicyConfig | null {
  if (!snapshot) return null;
  try {
    const parsed = JSON.parse(snapshot);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as PolicyConfig;
  } catch {
    return null;
  }
}

function sourceLabel(source: string): string {
  return source === "AI_WORKSPACE" ? "AI Workspace" : "IDE Guard";
}

function originalTextLabel(incident: Incident): string {
  return incident.original_text.startsWith(PROTECTED_STORAGE_MARKER)
    ? "Protected original preview"
    : "Original text";
}

function policyStateLabel(enabled: boolean, onText = "Redact", offText = "Allow"): string {
  return enabled ? onText : offText;
}

function buildRemediation(issues: string[], decision: string): { title: string; bullets: string[] } {
  const bullets: string[] = [];
  const hasCreds = issues.some((i) => i === "CREDENTIALS" || i.startsWith("CREDENTIALS_"));
  const hasDb = issues.includes("DB_CONN_STRING");
  const hasPii = issues.some((i) => i.startsWith("PII_"));
  const hasFinancial = issues.some((i) => i.startsWith("FINANCIAL_") || i.startsWith("GOVERNMENT_"));
  const hasCommerce = issues.some((i) => i.startsWith("COMMERCE_"));
  const hasHealth = issues.some((i) => i.startsWith("HEALTH_"));
  const hasLegal = issues.some((i) => i.startsWith("LEGAL_"));
  const hasHr = issues.some((i) => i.startsWith("HR_"));
  const hasConfidential = issues.includes("BUSINESS_CONFIDENTIAL");
  const hasEntropy = issues.includes("SECRET_HIGH_ENTROPY");

  if (hasCreds) {
    bullets.push("Rotate exposed keys or tokens immediately.");
    bullets.push("Move secrets into a vault or environment-level secret manager.");
    bullets.push("Add pre-commit and CI scanning to reduce repeat exposure.");
  }
  if (hasDb) {
    bullets.push("Replace database URIs with placeholders before using AI tools.");
    bullets.push("Prefer short-lived credentials and role-based access.");
  }
  if (hasPii) {
    bullets.push("Use synthetic customer data in prompts, tickets, and demos.");
    bullets.push("Keep redaction templates available for support and engineering teams.");
  }
  if (hasFinancial) {
    bullets.push("Redact tax IDs, bank details, payment-card data, and government identifiers before sharing.");
    bullets.push("Use fictional finance examples for demonstrations and model testing.");
  }
  if (hasCommerce) {
    bullets.push("Replace customer, order, invoice, shipment, and account IDs with stable placeholders.");
    bullets.push("Avoid combining commerce identifiers with names, addresses, or payment details.");
  }
  if (hasHealth) {
    bullets.push("Treat patient, medical record, prescription, and insurance identifiers as protected health data.");
    bullets.push("Use synthetic patient scenarios unless an approved clinical workflow requires otherwise.");
  }
  if (hasLegal) {
    bullets.push("Do not paste privileged legal content, case numbers, docket IDs, or matter details into AI tools.");
    bullets.push("Use neutral summaries and placeholders for legal references.");
  }
  if (hasHr) {
    bullets.push("Anonymize employee, payroll, salary, bonus, and compensation details.");
  }
  if (hasConfidential) {
    bullets.push("Keep confidential pricing, forecasts, contracts, proposals, and proprietary strategy out of prompts.");
  }
  if (hasEntropy && !hasCreds) {
    bullets.push("Review the high-entropy value and rotate it if it is a real secret.");
  }
  if (!bullets.length) {
    bullets.push("No remediation is required for this policy decision.");
  }

  const title =
    decision === "BLOCK"
      ? "Containment steps"
      : decision === "REDACT"
        ? "Redaction guidance"
        : "Review notes";

  return { title, bullets };
}

function MetricCard({
  label,
  value,
  caption,
  icon,
  tone = "neutral"
}: {
  label: string;
  value: number | string;
  caption: string;
  icon: IconName;
  tone?: "neutral" | "success" | "warning" | "danger" | "info";
}) {
  return (
    <div className={`metricCard tone-${tone}`}>
      <div className="metricTop">
        <span className="metricIcon">
          <Icon name={icon} size={17} />
        </span>
        <span>{label}</span>
      </div>
      <div className="metricValue">{value}</div>
      <div className="metricCaption">{caption}</div>
    </div>
  );
}

export function DashboardPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [source, setSource] = useState<string>("ALL");
  const [risk, setRisk] = useState<string>("ALL");
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);
  const incidentParam = searchParams.get("incident");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await getIncidents({
          source: source === "ALL" ? undefined : source,
          risk_level: risk === "ALL" ? undefined : risk
        });
        if (!cancelled) setItems(data);
      } catch (e: any) {
        if (!cancelled) setError(e?.message ?? "Failed to load incidents");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [source, risk, refreshToken]);

  useEffect(() => {
    if (!incidentParam || !items.length) return;
    const incidentId = Number(incidentParam);
    if (!Number.isFinite(incidentId)) return;
    const match = items.find((item) => item.id === incidentId);
    if (match) {
      setSelected(match);
      setSearchParams({}, { replace: true });
    }
  }, [incidentParam, items, setSearchParams]);

  const filteredItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => {
      const issues = parseIssues(it.issues).join(" ").toLowerCase();
      return (
        it.source.toLowerCase().includes(q) ||
        sourceLabel(it.source).toLowerCase().includes(q) ||
        it.user_id.toLowerCase().includes(q) ||
        it.decision.toLowerCase().includes(q) ||
        it.risk_level.toLowerCase().includes(q) ||
        issues.includes(q)
      );
    });
  }, [items, query]);

  const counts = useMemo(() => {
    const c = { LOW: 0, MEDIUM: 0, HIGH: 0 };
    for (const it of filteredItems) {
      const riskLevel = (it.risk_level || "").toUpperCase();
      if (riskLevel === "HIGH") c.HIGH++;
      else if (riskLevel === "MEDIUM") c.MEDIUM++;
      else c.LOW++;
    }
    return c;
  }, [filteredItems]);

  const decisionCounts = useMemo(() => {
    const c = { ALLOW: 0, REDACT: 0, BLOCK: 0 };
    for (const it of filteredItems) {
      const decision = (it.decision || "").toUpperCase();
      if (decision === "BLOCK") c.BLOCK++;
      else if (decision === "REDACT") c.REDACT++;
      else c.ALLOW++;
    }
    return c;
  }, [filteredItems]);

  const highRate = filteredItems.length ? Math.round((counts.HIGH / filteredItems.length) * 100) : 0;
  const interventionCount = decisionCounts.BLOCK + decisionCounts.REDACT;
  const interventionRate = filteredItems.length ? Math.round((interventionCount / filteredItems.length) * 100) : 0;

  return (
    <div className="dashboardPage">
      <section className="dashboardTop">
        <div className="dashTitleRow">
          <div>
            <p className="heroEyebrow">Audit and incident review</p>
            <h2 className="dashTitle">Security decisions across workspace and IDE traffic.</h2>
            <p className="dashSubtitle">
              {loading ? "Refreshing incident stream..." : `${filteredItems.length} incident(s) in view`}
              {items.length !== filteredItems.length ? ` from ${items.length} total` : ""}
            </p>
          </div>
          <button className="btn btnPrimary" type="button" onClick={() => setRefreshToken((t) => t + 1)}>
            <Icon name="refresh" size={16} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="metricsGrid">
          <MetricCard label="High risk" value={counts.HIGH} caption={`${highRate}% of current view`} icon="alert" tone="danger" />
          <MetricCard label="Redacted" value={decisionCounts.REDACT} caption="Prompts sanitized" icon="file" tone="warning" />
          <MetricCard label="Blocked" value={decisionCounts.BLOCK} caption="Secrets contained" icon="lock" tone="danger" />
          <MetricCard label="Intervention rate" value={`${interventionRate}%`} caption={`${interventionCount} policy actions`} icon="activity" tone="info" />
        </div>

        <div className="filterDock" aria-label="Incident filters">
          <label className="fieldGroup">
            <span>Source</span>
            <select className="filterSelect" value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="ALL">All sources</option>
              <option value="AI_WORKSPACE">AI Workspace</option>
              <option value="IDE_GUARD">IDE Guard</option>
            </select>
          </label>

          <label className="fieldGroup">
            <span>Risk</span>
            <select className="filterSelect" value={risk} onChange={(e) => setRisk(e.target.value)}>
              <option value="ALL">All risks</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
            </select>
          </label>

          <label className="fieldGroup searchGroup">
            <span>Search</span>
            <div className="searchInputWrap">
              <Icon name="search" size={16} />
              <input
                className="filterSearch"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Issue, user, decision..."
              />
            </div>
          </label>
        </div>
      </section>

      {error ? (
        <div className="inlineError dashboardError">
          <Icon name="alert" size={16} />
          <span>{error}</span>
        </div>
      ) : null}

      <section className="dashboardBody">
        <div className="tablePane">
          <table className="incidentTable">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Source</th>
                <th>Risk</th>
                <th>Issues</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {loading && !filteredItems.length
                ? Array.from({ length: 5 }).map((_, index) => (
                    <tr key={`skeleton-${index}`} className="skeletonRow">
                      <td colSpan={5}>
                        <span />
                      </td>
                    </tr>
                  ))
                : null}

              {filteredItems.map((it) => {
                const issues = parseIssues(it.issues);
                const isSelected = selected?.id === it.id;
                return (
                  <tr key={it.id} className={isSelected ? "rowSelected" : ""} onClick={() => setSelected(it)}>
                    <td>
                      <div className="incidentCell">
                        <span className="incidentId">#{it.id}</span>
                        <span>{formatTs(it.timestamp)}</span>
                      </div>
                    </td>
                    <td>
                      <span className="sourcePill">
                        <Icon name={it.source === "AI_WORKSPACE" ? "message" : "terminal"} size={14} />
                        {sourceLabel(it.source)}
                      </span>
                    </td>
                    <td>
                      <SeverityChip risk={it.risk_level} />
                    </td>
                    <td>
                      <div className="chipList">
                        {issues.length ? issues.slice(0, 3).map((issue) => <IssueChip key={issue} issue={issue} />) : <span className="issueChip">None</span>}
                        {issues.length > 3 ? <span className="issueChip mutedChip">+{issues.length - 3} more</span> : null}
                      </div>
                    </td>
                    <td>
                      <span className={`badge badge-${it.decision.toLowerCase()}`}>{it.decision}</span>
                    </td>
                  </tr>
                );
              })}

              {!filteredItems.length && !loading ? (
                <tr>
                  <td colSpan={5} className="noResults">
                    <div className="emptyTable">
                      <Icon name="search" size={22} />
                      <span>No incidents match the active filters.</span>
                    </div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <Modal title={selected ? `Incident #${selected.id}` : "Incident"} open={!!selected} onClose={() => setSelected(null)}>
        {selected ? (
          <div className="dashModal">
            {(() => {
              const policySnapshot = parsePolicySnapshot(selected.policy_snapshot);
              return (
                <>
            <div className="detailHero">
              <div>
                <span className="detailSectionLabel">Decision</span>
                <div className="detailHeroTitle">{selected.decision}</div>
              </div>
              <div className="resultBadges">
                <SeverityChip risk={selected.risk_level} />
                <span className={`badge badge-${selected.decision.toLowerCase()}`}>{selected.decision}</span>
                <span className="sourcePill">
                  <Icon name={selected.source === "AI_WORKSPACE" ? "message" : "terminal"} size={14} />
                  {sourceLabel(selected.source)}
                </span>
              </div>
            </div>

            <div className="detailSection">
              <span className="detailSectionLabel">Policy snapshot</span>
              {policySnapshot ? (
                <div className="policySnapshotGrid">
                  <span className="policySnapshotPill">Credentials: {policySnapshot.block_credentials ? "Block" : "Redact"}</span>
                  <span className="policySnapshotPill">PII: {policyStateLabel(policySnapshot.redact_pii)}</span>
                  <span className="policySnapshotPill">Financial: {policyStateLabel(policySnapshot.redact_financial)}</span>
                  <span className="policySnapshotPill">Gov IDs: {policyStateLabel(policySnapshot.redact_government_ids)}</span>
                  <span className="policySnapshotPill">Health: {policyStateLabel(policySnapshot.redact_health)}</span>
                  <span className="policySnapshotPill">Legal: {policyStateLabel(policySnapshot.redact_legal)}</span>
                  <span className="policySnapshotPill">HR: {policyStateLabel(policySnapshot.redact_hr)}</span>
                  <span className="policySnapshotPill">Commerce: {policyStateLabel(policySnapshot.redact_commerce)}</span>
                  <span className="policySnapshotPill">Business: {policyStateLabel(policySnapshot.redact_business_confidential)}</span>
                  <span className="policySnapshotPill">Audit: {policySnapshot.audit_storage === "PROTECTED" ? "Protected" : "Full text"}</span>
                </div>
              ) : (
                <div className="detailValue">No policy snapshot was recorded for this older incident.</div>
              )}
            </div>

            <div className="detailGrid">
              <div className="detailSection">
                <span className="detailSectionLabel">User</span>
                <div className="detailValue">{selected.user_id}</div>
              </div>
              <div className="detailSection">
                <span className="detailSectionLabel">Timestamp</span>
                <div className="detailValue">{formatTs(selected.timestamp)}</div>
              </div>
            </div>

            <div className="detailSection">
              <span className="detailSectionLabel">Detected issues</span>
              <div className="chipList">
                <IssueChipList issues={parseIssues(selected.issues)} />
              </div>
            </div>

            <div className="dashModalGrid">
              <div className="detailSection">
                <div className="codePanelHeader">
                  <span className="detailSectionLabel">{originalTextLabel(selected)}</span>
                  <CopyButton text={selected.original_text} label="Copy" small />
                </div>
                <textarea className="detailTextarea" readOnly value={selected.original_text} />
              </div>

              <div className="detailSection">
                <div className="codePanelHeader">
                  <span className="detailSectionLabel">Sanitized output</span>
                  {selected.sanitized_text ? <CopyButton text={selected.sanitized_text} label="Copy" small /> : null}
                </div>
                <textarea className="detailTextarea" readOnly value={selected.sanitized_text ?? "No sanitized output available."} />
              </div>
            </div>

            <div className="dashTips">
              {(() => {
                const tips = buildRemediation(parseIssues(selected.issues), selected.decision);
                return (
                  <>
                    <span className="detailSectionLabel">{tips.title}</span>
                    <ul className="tipsList">
                      {tips.bullets.map((bullet) => (
                        <li key={bullet}>{bullet}</li>
                      ))}
                    </ul>
                  </>
                );
              })()}
            </div>

            <div className="detailSection">
              <span className="detailSectionLabel">Hash-chain proof</span>
              <div className="hashCodeWrap">{selected.hash_chain}</div>
            </div>
                </>
              );
            })()}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
