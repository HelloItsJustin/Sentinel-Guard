import { useEffect, useMemo, useRef, useState } from "react";
import { analyze, getPolicy } from "../api/sentinelguard";
import type { AnalyzeResponse, Decision, PolicyConfig, RiskLevel } from "../api/types";
import { Toast, type ToastKind } from "../components/Toast";
import { CopyButton } from "../components/CopyButton";
import { Icon } from "../components/Icon";
import { IssueChipList } from "../components/IssueChip";
import type { ChatMessage, ChatSession } from "../types/chat";

const MIN_ANALYZE_MS = 900;
const THINKING_LABELS = ["Scanning prompt", "Classifying risk", "Applying policy", "Writing audit event"];
type PromptStyleId = "guarded" | "brief" | "analyst" | "support";

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

const PROMPT_STYLES: Array<{ id: PromptStyleId; label: string }> = [
  { id: "guarded", label: "Guarded" },
  { id: "brief", label: "Brief" },
  { id: "analyst", label: "Analyst" },
  { id: "support", label: "Support" }
];

const SAMPLE_PROMPTS = [
  {
    label: "Credential leak",
    text: "Can you debug this request? api_key=sk-demo1234567890abcdef and contact alex@company.com if it fails."
  },
  {
    label: "Customer data",
    text: "Draft a reply to Priya at priya@example.com. Her phone number is +1 415 555 0198."
  },
  {
    label: "Database URI",
    text: "Summarize this config: postgres://admin:supersecret@prod-db.internal:5432/customers"
  }
];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function makeMessageId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function makeTitle(text: string): string {
  const compact = text.replace(/\s+/g, " ").trim();
  if (!compact) return "New preflight";
  return compact.length > 42 ? `${compact.slice(0, 39)}...` : compact;
}

function getDecisionMeta(decision: Decision, risk: RiskLevel) {
  if (decision === "BLOCK") {
    return {
      tone: "danger",
      icon: "lock" as const,
      title: "Blocked before external send",
      body: "High-risk data was found. Keep this content inside the trusted environment.",
      score: 94
    };
  }
  if (decision === "REDACT") {
    return {
      tone: "warning",
      icon: "file" as const,
      title: "Redacted for safer sharing",
      body: "Sensitive personal data was masked so the prompt can be reviewed safely.",
      score: risk === "HIGH" ? 78 : 58
    };
  }
  return {
    tone: "success",
    icon: "check" as const,
    title: "Allowed by policy",
    body: "No protected data patterns were detected in this prompt.",
    score: 14
  };
}

function decisionLabel(decision: Decision): string {
  if (decision === "ALLOW") return "Allow";
  if (decision === "REDACT") return "Redact";
  return "Block";
}

function riskLabel(risk: RiskLevel): string {
  if (risk === "HIGH") return "High risk";
  if (risk === "MEDIUM") return "Medium risk";
  return "Low risk";
}

function formatTime(ts: number): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(ts);
}

function policyModeLabel(enabled: boolean): string {
  return enabled ? "Redact" : "Allow";
}

function activePolicyCount(policy: PolicyConfig): number {
  return [
    policy.block_credentials,
    policy.redact_high_entropy,
    policy.redact_pii,
    policy.redact_financial,
    policy.redact_government_ids,
    policy.redact_health,
    policy.redact_legal,
    policy.redact_hr,
    policy.redact_commerce,
    policy.redact_business_confidential
  ].filter(Boolean).length;
}

function policyLinesForIssues(issues: string[]): string[] {
  const lines = new Set<string>();
  const hasCredentials = issues.some((issue) => issue === "CREDENTIALS" || issue.startsWith("CREDENTIALS_"));
  const hasDatabase = issues.includes("DB_CONN_STRING");
  const hasPii = issues.some((issue) => issue.startsWith("PII_"));
  const hasGovernment = issues.some((issue) => issue.startsWith("GOVERNMENT_"));
  const hasFinancial = issues.some((issue) => issue.startsWith("FINANCIAL_"));
  const hasCommerce = issues.some((issue) => issue.startsWith("COMMERCE_"));
  const hasHealth = issues.some((issue) => issue.startsWith("HEALTH_"));
  const hasLegal = issues.some((issue) => issue.startsWith("LEGAL_"));
  const hasHr = issues.some((issue) => issue.startsWith("HR_"));
  const hasConfidential = issues.includes("BUSINESS_CONFIDENTIAL");
  const hasEntropy = issues.includes("SECRET_HIGH_ENTROPY");

  if (hasCredentials) lines.add("Never include real credentials, API keys, bearer tokens, private keys, session tokens, or passwords.");
  if (hasDatabase) lines.add("Replace connection strings and host credentials with placeholders such as [DATABASE_URI].");
  if (hasPii) lines.add("Use synthetic names and placeholders for emails, phone numbers, IDs, and personal details.");
  if (hasGovernment) lines.add("Keep tax IDs, national identifiers, and government-issued numbers redacted.");
  if (hasFinancial) lines.add("Keep financial identifiers redacted and use fictional sample values only when an example is necessary.");
  if (hasCommerce) lines.add("Avoid exposing real customer, order, invoice, shipment, or account identifiers.");
  if (hasHealth) lines.add("Treat patient, medical record, prescription, and insurance identifiers as protected health information.");
  if (hasLegal) lines.add("Do not reveal privileged legal markers, case identifiers, docket numbers, or matter details.");
  if (hasHr) lines.add("Keep employee, payroll, salary, bonus, and compensation details anonymized.");
  if (hasConfidential) lines.add("Do not disclose confidential roadmaps, pricing, revenue, margins, proposals, contracts, or proprietary strategy.");
  if (hasEntropy) lines.add("Treat unexplained high-entropy strings as secrets and keep them as [REDACTED].");

  lines.add("Preserve all [REDACTED] placeholders and do not infer or recreate hidden values.");
  lines.add("If a hidden value is required, ask for a non-sensitive placeholder or describe the expected format.");
  return Array.from(lines);
}

function buildPolicySafePrompt(sanitizedText: string, issues: string[], decision: Decision, style: PromptStyleId): string {
  const policyLines = policyLinesForIssues(issues);
  const contextLine = decision === "BLOCK" ? "The original request was blocked. Use only this sanitized context." : "Use this sanitized context as the complete source of truth.";

  if (style === "brief") {
    return [
      "Answer the request below using only the sanitized details.",
      "",
      sanitizedText,
      "",
      "Rules: preserve every [REDACTED] placeholder, do not infer hidden values, avoid real identifiers, and ask for a safe placeholder if a missing value is required."
    ].join("\n");
  }

  if (style === "analyst") {
    return [
      "You are a careful security-aware analyst. Complete the task using the sanitized context and produce a structured answer.",
      "",
      "Context:",
      sanitizedText,
      "",
      "Analysis constraints:",
      ...policyLines.map((line) => `- ${line}`),
      "",
      "Output format:",
      "- Summary",
      "- Key findings or recommended action",
      "- Any assumptions made because sensitive values were redacted"
    ].join("\n");
  }

  if (style === "support") {
    return [
      "Create a helpful, customer-safe response from the sanitized request below.",
      "",
      "Sanitized customer context:",
      sanitizedText,
      "",
      "Communication rules:",
      ...policyLines.map((line) => `- ${line}`),
      "- Keep the tone clear, professional, and action-oriented.",
      "- Do not expose internal notes, customer identifiers, payment details, health details, or legal identifiers."
    ].join("\n");
  }

  return [
    "Rewrite and answer this request using only SentinelGuard-approved context.",
    "",
    contextLine,
    "",
    "Sanitized request:",
    sanitizedText,
    "",
    "Policy requirements:",
    ...policyLines.map((line) => `- ${line}`),
    "",
    "Response goal:",
    "Provide the most helpful answer possible while following the policy requirements exactly."
  ].join("\n");
}

interface WorkspacePageProps {
  session: ChatSession;
  updateSession: (updater: (session: ChatSession) => ChatSession) => void;
}

export function WorkspacePage({ session, updateSession }: WorkspacePageProps) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [toastOpen, setToastOpen] = useState(false);
  const [toastKind, setToastKind] = useState<ToastKind>("info");
  const [toastTitle, setToastTitle] = useState("");
  const [toastMsg, setToastMsg] = useState("");
  const [thinkingIndex, setThinkingIndex] = useState(0);
  const [lastError, setLastError] = useState<string | null>(null);
  const [regeneratedPrompts, setRegeneratedPrompts] = useState<Record<string, string>>({});
  const [regeneratedStyles, setRegeneratedStyles] = useState<Record<string, PromptStyleId>>({});
  const [activePolicy, setActivePolicy] = useState<PolicyConfig>(DEFAULT_POLICY);
  const [policyStatus, setPolicyStatus] = useState<"syncing" | "live" | "offline">("syncing");

  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const visibleMessages = useMemo(() => session.messages, [session.messages]);
  const hasConversation = visibleMessages.some((m) => m.role === "user" || m.role === "sentinel");

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = "auto";
    textarea.style.height = `${Math.min(textarea.scrollHeight, 190)}px`;
  }, [input]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [visibleMessages]);

  useEffect(() => {
    if (!loading) return;
    const timer = window.setInterval(() => {
      setThinkingIndex((i) => (i + 1) % THINKING_LABELS.length);
    }, 620);
    return () => window.clearInterval(timer);
  }, [loading]);

  async function refreshActivePolicy(showSync = false): Promise<PolicyConfig | null> {
    try {
      if (showSync) setPolicyStatus("syncing");
      const policy = await getPolicy();
      setActivePolicy(policy);
      setPolicyStatus("live");
      return policy;
    } catch {
      setPolicyStatus("offline");
      return null;
    }
  }

  useEffect(() => {
    void refreshActivePolicy(true);
    const timer = window.setInterval(() => {
      void refreshActivePolicy();
    }, 5_000);
    const onFocus = () => {
      void refreshActivePolicy();
    };
    window.addEventListener("focus", onFocus);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", onFocus);
    };
  }, []);

  function showToast(kind: ToastKind, title: string, message: string) {
    setToastKind(kind);
    setToastTitle(title);
    setToastMsg(message);
    setToastOpen(true);
  }

  function updateMessages(updater: (messages: ChatMessage[]) => ChatMessage[], titleFrom?: string) {
    updateSession((current) => {
      const nextMessages = updater(current.messages);
      const shouldRename = current.title === "New preflight" && !!titleFrom;
      return {
        ...current,
        title: shouldRename ? makeTitle(titleFrom) : current.title,
        updatedAt: Date.now(),
        messages: nextMessages
      };
    });
  }

  async function onAnalyze(promptOverride?: string) {
    if (loading) return;
    const prompt = (promptOverride ?? input).trim();
    if (!prompt) {
      showToast("info", "Add content to scan", "SentinelGuard is waiting for a prompt.");
      return;
    }

    const now = Date.now();
    const userMsg: ChatMessage = { id: makeMessageId("u"), role: "user", text: prompt, ts: now };
    const thinkingMsg: ChatMessage = { id: makeMessageId("t"), role: "thinking", step: 0, ts: now + 1 };

    updateMessages((messages) => [...messages, userMsg, thinkingMsg], prompt);
    setInput("");
    setLoading(true);
    setLastError(null);
    setThinkingIndex(0);
    const attemptStart = Date.now();

    try {
      await refreshActivePolicy(true);
      const start = Date.now();
      const response = await analyze({
        source: "AI_WORKSPACE",
        user_id: "demo-user",
        text: prompt
      });

      const elapsed = Date.now() - start;
      if (elapsed < MIN_ANALYZE_MS) await sleep(MIN_ANALYZE_MS - elapsed);

      const responseMsg: ChatMessage = {
        id: makeMessageId("s"),
        role: "sentinel",
        original: prompt,
        response,
        ts: Date.now()
      };

      updateMessages((messages) => [...messages.filter((m) => m.id !== thinkingMsg.id), responseMsg]);

      const issues = response.issues.length ? response.issues.join(", ") : "No issues";
      if (response.decision === "BLOCK") showToast("danger", "Prompt blocked", issues);
      else if (response.decision === "REDACT") showToast("warn", "Prompt redacted", issues);
      else showToast("safe", "Prompt allowed", "No protected data patterns detected.");
    } catch (err: any) {
      const elapsed = Date.now() - attemptStart;
      if (elapsed < MIN_ANALYZE_MS) await sleep(MIN_ANALYZE_MS - elapsed);
      updateMessages((messages) => messages.filter((m) => m.id !== thinkingMsg.id));
      const message = err?.message || "Backend error";
      setLastError(message);
      showToast("danger", "Analysis failed", message);
    } finally {
      setLoading(false);
    }
  }

  function getSelectedStyle(messageId: string): PromptStyleId {
    return regeneratedStyles[messageId] ?? "guarded";
  }

  function selectPromptStyle(messageId: string, style: PromptStyleId, response: AnalyzeResponse) {
    setRegeneratedStyles((current) => ({ ...current, [messageId]: style }));
    const safeSource = response.sanitized_text?.trim();
    if (!safeSource) return;
    setRegeneratedPrompts((current) => {
      if (!current[messageId]) return current;
      return { ...current, [messageId]: buildPolicySafePrompt(safeSource, response.issues, response.decision, style) };
    });
  }

  function regeneratePrompt(messageId: string, response: AnalyzeResponse) {
    const safeSource = response.sanitized_text?.trim();
    if (!safeSource) {
      showToast("warn", "No sanitized content", "Run a prompt with sanitized output before regenerating.");
      return;
    }

    const engineered = buildPolicySafePrompt(safeSource, response.issues, response.decision, getSelectedStyle(messageId));
    setRegeneratedPrompts((current) => ({ ...current, [messageId]: engineered }));
    showToast("safe", "Policy-safe prompt generated", "You can copy it, edit it, or analyze it directly.");
  }

  function useRegeneratedPrompt(prompt: string) {
    setInput(prompt);
    window.setTimeout(() => textareaRef.current?.focus(), 0);
  }

  function sendApprovedPrompt(message: Extract<ChatMessage, { role: "sentinel" }>) {
    const { response } = message;
    if (response.decision === "BLOCK") {
      showToast("danger", "Send blocked", "The AI gateway refused this prompt because high-risk data was detected.");
      return;
    }

    const payload = response.decision === "REDACT" ? response.sanitized_text?.trim() || "" : message.original;
    const receipt: ChatMessage = {
      id: makeMessageId("g"),
      role: "gateway",
      incidentId: response.incident_id,
      decision: response.decision,
      ts: Date.now(),
      text: [
        response.decision === "REDACT"
          ? "AI gateway accepted the sanitized prompt generated by SentinelGuard."
          : "AI gateway accepted the original prompt after SentinelGuard allowed it.",
        `Approved payload length: ${payload.length} characters.`
      ].join("\n")
    };
    updateMessages((messages) => [...messages, receipt]);
    showToast("safe", "Approved send completed", `Incident #${response.incident_id} passed the policy gate.`);
  }

  function renderSentinelResult(message: Extract<ChatMessage, { role: "sentinel" }>) {
    const response: AnalyzeResponse = message.response;
    const meta = getDecisionMeta(response.decision, response.risk_level);
    const sanitizedText = response.sanitized_text || "";
    const showSanitized = response.decision !== "ALLOW" || !!sanitizedText;
    const regeneratedPrompt = regeneratedPrompts[message.id];
    const selectedStyle = getSelectedStyle(message.id);

    return (
      <article className={`resultCard tone-${meta.tone}`} key={message.id}>
        <div className="resultCardHeader">
          <div className="resultIdentity">
            <span className="resultIcon">
              <Icon name={meta.icon} size={17} />
            </span>
            <div>
              <div className="resultTitle">{meta.title}</div>
              <div className="resultSubline">Incident #{response.incident_id}</div>
            </div>
          </div>
          <div className="resultBadges">
            <span className={`badge badge-${response.risk_level.toLowerCase()}`}>{riskLabel(response.risk_level)}</span>
            <span className={`badge badge-${response.decision.toLowerCase()}`}>{decisionLabel(response.decision)}</span>
          </div>
        </div>

        <div className="resultCardBody">
          <div className="decisionSummary">
            <div>
              <div className="sectionKicker">Policy decision</div>
              <p>{meta.body}</p>
            </div>
            <div className="riskMeter" aria-label={`Risk score ${meta.score}`}>
              <span>{meta.score}</span>
              <small>risk score</small>
            </div>
          </div>

          <div className="pipelineSteps" aria-label="Analysis pipeline">
            <span>Classifier</span>
            <span>Policy</span>
            <span>Audit log</span>
          </div>

          <div className="resultSection">
            <div className="sectionHeader">
              <span className="sectionKicker">Detected issues</span>
              <span className="mutedText">{response.issues.length || 0} finding(s)</span>
            </div>
            <div className="chipList">
              <IssueChipList issues={response.issues} />
            </div>
          </div>

          <div className={showSanitized ? "promptCompare" : "promptCompare single"}>
            <div className="codePanel">
              <div className="codePanelHeader">
                <span>Original prompt</span>
                <CopyButton text={message.original} label="Copy" small />
              </div>
              <pre>{message.original}</pre>
            </div>

            {showSanitized ? (
              <div className="codePanel safe">
                <div className="codePanelHeader">
                  <span>Sanitized output</span>
                  {sanitizedText ? <CopyButton text={sanitizedText} label="Copy" small /> : null}
                </div>
                <pre>{sanitizedText || "No sanitized output was produced for this policy decision."}</pre>
              </div>
            ) : null}
          </div>

          {showSanitized ? (
            <div className="regenSection">
              <div className="regenPromptBar">
                <div>
                  <span className="sectionKicker">Policy-safe rewrite</span>
                  <p>Pick a style and create a fresh prompt from the sanitized output.</p>
                </div>
                <div className="regenControls">
                  <div className="styleSegment" aria-label="Prompt rewrite style">
                    {PROMPT_STYLES.map((style) => (
                      <button
                        key={style.id}
                        type="button"
                        className={selectedStyle === style.id ? "active" : ""}
                        onClick={() => selectPromptStyle(message.id, style.id, response)}
                      >
                        {style.label}
                      </button>
                    ))}
                  </div>
                  <button className="btn regenButton" type="button" onClick={() => regeneratePrompt(message.id, response)} disabled={loading || !sanitizedText}>
                    <Icon name="wand" size={16} />
                    <span>{regeneratedPrompt ? "Regenerate" : "Generate"}</span>
                  </button>
                </div>
              </div>

              {regeneratedPrompt ? (
                <div className="codePanel engineered">
                  <div className="codePanelHeader">
                    <span>Engineered safe prompt</span>
                    <CopyButton text={regeneratedPrompt} label="Copy" small />
                  </div>
                  <pre>{regeneratedPrompt}</pre>
                  <div className="engineeredActions">
                    <button className="btn" type="button" onClick={() => useRegeneratedPrompt(regeneratedPrompt)} disabled={loading}>
                      <Icon name="message" size={16} />
                      <span>Use in composer</span>
                    </button>
                    <button className="btn btnPrimary" type="button" onClick={() => onAnalyze(regeneratedPrompt)} disabled={loading}>
                      <Icon name="upload" size={16} />
                      <span>Analyze directly</span>
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          <div className={`gatewayPanel gate-${response.decision.toLowerCase()}`}>
            <div>
              <span className="sectionKicker">AI gateway enforcement</span>
              <p>
                {response.decision === "BLOCK"
                  ? "The prompt cannot be sent while this policy decision is active."
                  : response.decision === "REDACT"
                    ? "Only the sanitized prompt is approved for external AI use."
                    : "This prompt is approved for external AI use."}
              </p>
            </div>
            <button
              className={response.decision === "BLOCK" ? "btn" : "btn btnPrimary"}
              type="button"
              onClick={() => sendApprovedPrompt(message)}
              disabled={loading || response.decision === "BLOCK"}
            >
              <Icon name={response.decision === "BLOCK" ? "lock" : "send"} size={16} />
              <span>{response.decision === "BLOCK" ? "Send blocked" : "Send approved"}</span>
            </button>
          </div>
        </div>
      </article>
    );
  }

  return (
    <div className="workspacePage">
      <Toast open={toastOpen} kind={toastKind} title={toastTitle} message={toastMsg} onClose={() => setToastOpen(false)} />

      <div className="messagesContainer">
        <div className="chatColumn">
          <section className={`activePolicyStrip policy-${policyStatus}`} aria-label="Active policy">
            <div className="activePolicyLead">
              <span className="statusDot" />
              <div>
                <span className="sectionKicker">Active policy</span>
                <strong>
                  {policyStatus === "offline"
                    ? "Backend policy unavailable"
                    : policyStatus === "syncing"
                      ? "Syncing policy"
                      : `${activePolicyCount(activePolicy)}/10 controls enabled`}
                </strong>
              </div>
            </div>
            <div className="activePolicyPills">
              <span className="policyMiniPill">Credentials: {activePolicy.block_credentials ? "Block" : "Redact"}</span>
              <span className="policyMiniPill">PII: {policyModeLabel(activePolicy.redact_pii)}</span>
              <span className="policyMiniPill">Financial: {policyModeLabel(activePolicy.redact_financial)}</span>
              <span className="policyMiniPill">Audit: {activePolicy.audit_storage === "PROTECTED" ? "Protected" : "Full text"}</span>
            </div>
          </section>

          {!hasConversation ? (
            <section className="workspaceHero" aria-label="Workspace introduction">
              <div className="heroMark">
                <Icon name="spark" size={22} />
              </div>
              <div className="heroCopy">
                <p className="heroEyebrow">Enterprise AI preflight</p>
                <h2>Catch secrets and private data before prompts leave the workspace.</h2>
                <p>
                  SentinelGuard classifies prompt content, applies allow/redact/block policy, and records every decision for audit review.
                </p>
              </div>

              <div className="quickPromptGrid">
                {SAMPLE_PROMPTS.map((sample) => (
                  <button key={sample.label} type="button" className="quickPrompt" onClick={() => setInput(sample.text)}>
                    <Icon name={sample.label === "Database URI" ? "database" : sample.label === "Credential leak" ? "terminal" : "file"} size={16} />
                    <span>{sample.label}</span>
                  </button>
                ))}
              </div>
            </section>
          ) : null}

          {visibleMessages.map((message) => {
            if (message.role === "system") {
              return hasConversation ? (
                <div className="systemLine" key={message.id}>
                  <Icon name="shield" size={14} />
                  <span>{message.text}</span>
                </div>
              ) : null;
            }

            if (message.role === "user") {
              return (
                <div className="messageRow userRow" key={message.id}>
                  <div className="messageMeta">You / {formatTime(message.ts)}</div>
                  <div className="userBubble">{message.text}</div>
                </div>
              );
            }

            if (message.role === "thinking") {
              return (
                <div className="thinkingPanel" key={message.id}>
                  <div className="thinkingDots" aria-hidden="true">
                    <span />
                    <span />
                    <span />
                  </div>
                  <span>{THINKING_LABELS[thinkingIndex]}</span>
                </div>
              );
            }

            if (message.role === "gateway") {
              return (
                <div className="gatewayReceipt" key={message.id}>
                  <div className="gatewayReceiptHeader">
                    <span className="resultIcon">
                      <Icon name="send" size={17} />
                    </span>
                    <div>
                      <div className="resultTitle">Approved AI send</div>
                      <div className="resultSubline">Incident #{message.incidentId} / {formatTime(message.ts)}</div>
                    </div>
                  </div>
                  <pre>{message.text}</pre>
                </div>
              );
            }

            return renderSentinelResult(message);
          })}

          {lastError ? (
            <div className="inlineError">
              <Icon name="alert" size={16} />
              <span>{lastError}</span>
            </div>
          ) : null}

          <div ref={bottomRef} />
        </div>
      </div>

      <div className="inputSection">
        <div className="inputWrapper">
          <textarea
            ref={textareaRef}
            className="promptInput"
            placeholder="Message SentinelGuard..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                onAnalyze();
              }
            }}
            disabled={loading}
            rows={1}
          />
          <button className="submitBtn" onClick={() => onAnalyze()} disabled={loading || !input.trim()} aria-label="Analyze prompt">
            <Icon name={loading ? "activity" : "arrowUp"} size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}
