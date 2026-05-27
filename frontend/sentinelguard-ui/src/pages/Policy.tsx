import { useEffect, useMemo, useRef, useState } from "react";
import { getPolicy, updatePolicy } from "../api/sentinelguard";
import type { PolicyConfig } from "../api/types";
import { Icon } from "../components/Icon";
import { Toast, type ToastKind } from "../components/Toast";

type PolicyKey = Exclude<keyof PolicyConfig, "audit_storage">;

const DEFAULT_POLICY: PolicyConfig = {
  block_credentials: true,
  redact_high_entropy: true,
  redact_pii: true,
  redact_financial: true,
  redact_government_ids: true,
  redact_health: true,
  redact_legal: true,
  redact_hr: true,
  redact_commerce: true,
  redact_business_confidential: true,
  audit_storage: "PROTECTED"
};

const POLICY_CONTROLS: Array<{ key: PolicyKey; title: string; body: string; tone: "danger" | "warning" | "info" }> = [
  {
    key: "block_credentials",
    title: "Block credentials and connection strings",
    body: "Stops API keys, bearer tokens, private keys, passwords, and database URLs before they can be sent.",
    tone: "danger"
  },
  {
    key: "redact_high_entropy",
    title: "Redact unknown high-entropy values",
    body: "Treats unexplained tokens as possible secrets when they look random or credential-like.",
    tone: "warning"
  },
  {
    key: "redact_pii",
    title: "Redact personal information",
    body: "Masks email addresses, phone numbers, addresses, DOBs, SSNs, passports, and driver's license patterns.",
    tone: "warning"
  },
  {
    key: "redact_financial",
    title: "Redact financial data",
    body: "Protects payment cards, routing and account numbers, IBANs, SWIFT codes, VAT IDs, and GSTINs.",
    tone: "danger"
  },
  {
    key: "redact_government_ids",
    title: "Redact government identifiers",
    body: "Covers Aadhaar, PAN, EIN, and other government-issued identity or tax patterns.",
    tone: "danger"
  },
  {
    key: "redact_health",
    title: "Redact health identifiers",
    body: "Masks medical record, patient, insurance member, and prescription identifiers.",
    tone: "danger"
  },
  {
    key: "redact_legal",
    title: "Redact legal markers",
    body: "Keeps case numbers, docket identifiers, and privileged legal content out of AI-bound prompts.",
    tone: "warning"
  },
  {
    key: "redact_hr",
    title: "Redact HR and compensation data",
    body: "Protects employee IDs, payroll IDs, salary, bonus, and compensation details.",
    tone: "warning"
  },
  {
    key: "redact_commerce",
    title: "Redact customer operations data",
    body: "Masks order IDs, invoice IDs, shipment tracking numbers, customer IDs, and account references.",
    tone: "info"
  },
  {
    key: "redact_business_confidential",
    title: "Redact confidential business content",
    body: "Covers roadmaps, pricing, revenue, forecasts, contracts, proposals, and proprietary strategy markers.",
    tone: "info"
  }
];

export function PolicyPage() {
  const [policy, setPolicy] = useState<PolicyConfig>(DEFAULT_POLICY);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toastOpen, setToastOpen] = useState(false);
  const [toastKind, setToastKind] = useState<ToastKind>("info");
  const [toastTitle, setToastTitle] = useState("");
  const [toastMsg, setToastMsg] = useState("");
  const saveSeq = useRef(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await getPolicy();
        if (!cancelled) setPolicy(data);
      } catch (e: any) {
        if (!cancelled) setError(e?.message ?? "Failed to load policy");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const activeCount = useMemo(
    () => POLICY_CONTROLS.filter((item) => policy[item.key]).length,
    [policy]
  );

  function showToast(kind: ToastKind, title: string, message: string) {
    setToastKind(kind);
    setToastTitle(title);
    setToastMsg(message);
    setToastOpen(true);
  }

  async function applyPolicy(nextPolicy: PolicyConfig, toast?: { kind: ToastKind; title: string; message: string }) {
    const seq = saveSeq.current + 1;
    saveSeq.current = seq;
    setPolicy(nextPolicy);
    setSaving(true);
    setError(null);
    try {
      const saved = await updatePolicy(nextPolicy);
      if (seq === saveSeq.current) {
        setPolicy(saved);
        if (toast) showToast(toast.kind, toast.title, toast.message);
      }
    } catch (e: any) {
      const message = e?.message ?? "Failed to save policy";
      setError(message);
      showToast("danger", "Live policy update failed", message);
    } finally {
      if (seq === saveSeq.current) setSaving(false);
    }
  }

  function togglePolicy(key: PolicyKey) {
    const nextPolicy = { ...policy, [key]: !policy[key] };
    void applyPolicy(nextPolicy);
  }

  function savePolicy() {
    void applyPolicy(policy, {
      kind: "safe",
      title: "Policy synced",
      message: "The active backend policy already matches this view."
    });
  }

  function resetPolicy() {
    void applyPolicy(DEFAULT_POLICY, {
      kind: "safe",
      title: "Defaults applied",
      message: "The baseline enterprise policy is active now."
    });
  }

  function setAuditStorage(auditStorage: PolicyConfig["audit_storage"]) {
    void applyPolicy({ ...policy, audit_storage: auditStorage });
  }

  return (
    <div className="policyPage">
      <Toast open={toastOpen} kind={toastKind} title={toastTitle} message={toastMsg} onClose={() => setToastOpen(false)} />

      <section className="policyHero">
        <div>
          <p className="heroEyebrow">Policy Center</p>
          <h2 className="dashTitle">Tune what SentinelGuard blocks, redacts, stores, and allows.</h2>
          <p className="dashSubtitle">
            {loading
              ? "Loading active backend policy..."
              : saving
                ? "Applying live policy update..."
                : `${activeCount} of ${POLICY_CONTROLS.length} protection controls enabled and live`}
          </p>
        </div>
        <div className="policyHeroActions">
          <button className="btn" type="button" onClick={resetPolicy} disabled={saving}>
            <Icon name="refresh" size={16} />
            <span>Reset</span>
          </button>
          <button className="btn btnPrimary" type="button" onClick={savePolicy} disabled={saving}>
            <Icon name={saving ? "activity" : "check"} size={16} />
            <span>{saving ? "Applying" : "Live policy"}</span>
          </button>
        </div>
      </section>

      {error ? (
        <div className="inlineError policyError">
          <Icon name="alert" size={16} />
          <span>{error}</span>
        </div>
      ) : null}

      <section className="policySummaryGrid">
        <div className="policySummary">
          <span className="sectionKicker">Enforcement mode</span>
          <strong>{policy.block_credentials ? "Block-first" : "Redact-first"}</strong>
          <p>Credential findings are {policy.block_credentials ? "blocked before send" : "sanitized and allowed through the redaction path"}.</p>
        </div>
        <div className="policySummary">
          <span className="sectionKicker">Audit storage</span>
          <strong>{policy.audit_storage === "PROTECTED" ? "Protected" : "Full text"}</strong>
          <p>{policy.audit_storage === "PROTECTED" ? "Sensitive incidents store sanitized previews by default." : "Incident review stores full original prompts."}</p>
        </div>
        <div className="policySummary">
          <span className="sectionKicker">Coverage</span>
          <strong>{activeCount}/{POLICY_CONTROLS.length}</strong>
          <p>Enabled controls participate in every workspace and IDE analysis.</p>
        </div>
      </section>

      <section className="policyStoragePanel">
        <div>
          <span className="sectionKicker">Audit storage mode</span>
          <h3>Choose how much original content the incident log retains.</h3>
        </div>
        <div className="storageSegment" aria-label="Audit storage mode">
          <button
            type="button"
            className={policy.audit_storage === "PROTECTED" ? "active" : ""}
            onClick={() => setAuditStorage("PROTECTED")}
          >
            Protected
          </button>
          <button
            type="button"
            className={policy.audit_storage === "FULL_TEXT" ? "active" : ""}
            onClick={() => setAuditStorage("FULL_TEXT")}
          >
            Full text
          </button>
        </div>
      </section>

      <section className="policyGrid">
        {POLICY_CONTROLS.map((item) => (
          <label key={item.key} className={`policyToggle tone-${item.tone}`}>
            <span className="policyToggleIcon">
              <Icon name={policy[item.key] ? "check" : "x"} size={16} />
            </span>
            <span className="policyToggleCopy">
              <span className="policyToggleTitle">{item.title}</span>
              <span className="policyToggleBody">{item.body}</span>
            </span>
            <input type="checkbox" checked={policy[item.key]} onChange={() => togglePolicy(item.key)} />
          </label>
        ))}
      </section>
    </div>
  );
}
