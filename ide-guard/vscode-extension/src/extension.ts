import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";

type Decision = "ALLOW" | "REDACT" | "BLOCK" | string;
type PromptStyle = "guarded" | "brief" | "analyst" | "support";

type AnalyzeResponse = {
  risk_level: string;
  issues: string[];
  decision: Decision;
  sanitized_text: string | null;
  incident_id: number;
};

type ScanTarget = {
  text: string;
  label: string;
  range?: vscode.Range;
  documentUri?: vscode.Uri;
  truncated: boolean;
};

type ScanArtifact = {
  target: ScanTarget;
  response: AnalyzeResponse;
  sanitizedText: string;
  promptVariants: Record<PromptStyle, string>;
  timestamp: number;
};

type GatewayDecision = {
  allowed: boolean;
  payload: string;
  title: string;
  detail: string;
  payloadKind: "original" | "sanitized" | "none";
  requiresVerification: boolean;
};

const MAX_BACKEND_TEXT_LENGTH = 50_000;
const PROMPT_STYLES: Array<{ id: PromptStyle; label: string }> = [
  { id: "guarded", label: "Guarded" },
  { id: "brief", label: "Brief" },
  { id: "analyst", label: "Analyst" },
  { id: "support", label: "Support" }
];

let output: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let reportPanel: vscode.WebviewPanel | undefined;
let lastScan: ScanArtifact | undefined;

function getConfig() {
  const cfg = vscode.workspace.getConfiguration("sentinelguard");
  return {
    apiBaseUrl: cfg.get<string>("apiBaseUrl", "http://localhost:8000").replace(/\/+$/, ""),
    userId: cfg.get<string>("userId", "vs-code-user"),
    timeoutMs: cfg.get<number>("timeoutMs", 15_000),
    autoOpenReport: cfg.get<"never" | "onRisk" | "always">("autoOpenReport", "onRisk"),
    showStatusBar: cfg.get<boolean>("showStatusBar", true),
    diagnosticsEnabled: cfg.get<boolean>("diagnosticsEnabled", true),
    frontendBaseUrl: cfg.get<string>("frontendBaseUrl", "http://127.0.0.1:5173").replace(/\/+$/, "")
  };
}

function buildUrl(path: string): string {
  return `${getConfig().apiBaseUrl}${path}`;
}

function requestJson<T>(method: "GET" | "POST", url: string, body?: unknown, timeoutMs = 15_000): Promise<T> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const payload = body == null ? undefined : Buffer.from(JSON.stringify(body), "utf8");

    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80,
        path: `${u.pathname}${u.search}`,
        method,
        headers: payload
          ? {
              "Content-Type": "application/json",
              "Content-Length": payload.length
            }
          : undefined
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          const ok = res.statusCode != null && res.statusCode >= 200 && res.statusCode < 300;
          if (!ok) {
            reject(new Error(`HTTP ${res.statusCode ?? "ERR"} ${res.statusMessage ?? ""}${text ? `: ${text}` : ""}`));
            return;
          }
          if (!text.trim()) {
            resolve({} as T);
            return;
          }
          try {
            resolve(JSON.parse(text) as T);
          } catch (error: any) {
            reject(new Error(`Invalid JSON response: ${error?.message ?? String(error)}`));
          }
        });
      }
    );

    req.on("error", reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error("Request timed out")));
    if (payload) req.write(payload);
    req.end();
  });
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

function buildPromptVariant(sanitizedText: string, issues: string[], decision: Decision, style: PromptStyle): string {
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

function buildPromptVariants(sanitizedText: string, response: AnalyzeResponse): Record<PromptStyle, string> {
  return {
    guarded: buildPromptVariant(sanitizedText, response.issues || [], response.decision, "guarded"),
    brief: buildPromptVariant(sanitizedText, response.issues || [], response.decision, "brief"),
    analyst: buildPromptVariant(sanitizedText, response.issues || [], response.decision, "analyst"),
    support: buildPromptVariant(sanitizedText, response.issues || [], response.decision, "support")
  };
}

function fullDocumentRange(document: vscode.TextDocument): vscode.Range {
  const lastLine = Math.max(document.lineCount - 1, 0);
  const end = document.lineAt(lastLine).range.end;
  return new vscode.Range(new vscode.Position(0, 0), end);
}

async function normalizeTarget(target: Omit<ScanTarget, "truncated">): Promise<ScanTarget | undefined> {
  if (target.text.length <= MAX_BACKEND_TEXT_LENGTH) {
    return { ...target, truncated: false };
  }

  const choice = await vscode.window.showWarningMessage(
    `SentinelGuard accepts up to ${MAX_BACKEND_TEXT_LENGTH.toLocaleString()} characters. Scan the first ${MAX_BACKEND_TEXT_LENGTH.toLocaleString()} characters?`,
    "Scan First 50k",
    "Cancel"
  );

  if (choice !== "Scan First 50k") return undefined;
  return { ...target, text: target.text.slice(0, MAX_BACKEND_TEXT_LENGTH), truncated: true };
}

async function getSelectionTarget(): Promise<ScanTarget | undefined> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage("Open a file and select text to scan.");
    return undefined;
  }

  const selectedText = editor.document.getText(editor.selection);
  if (!selectedText.trim()) {
    vscode.window.showInformationMessage("Select text to scan with SentinelGuard.");
    return undefined;
  }

  return normalizeTarget({
    text: selectedText,
    label: "Selected text",
    range: editor.selection,
    documentUri: editor.document.uri
  });
}

async function getDocumentTarget(): Promise<ScanTarget | undefined> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage("Open a file to scan.");
    return undefined;
  }

  const documentText = editor.document.getText();
  if (!documentText.trim()) {
    vscode.window.showInformationMessage("The active document is empty.");
    return undefined;
  }

  return normalizeTarget({
    text: documentText,
    label: `${editor.document.fileName.split(/[\\/]/).pop() ?? "Active file"}`,
    range: fullDocumentRange(editor.document),
    documentUri: editor.document.uri
  });
}

function updateStatus(kind: "idle" | "scanning" | "allow" | "redact" | "block" | "offline", detail?: string) {
  if (!statusBar) return;

  const config = getConfig();
  if (!config.showStatusBar) {
    statusBar.hide();
    return;
  }

  const map = {
    idle: { text: "$(shield) SentinelGuard", tooltip: "SentinelGuard IDE Guard is ready" },
    scanning: { text: "$(sync~spin) SentinelGuard", tooltip: "Scanning with SentinelGuard..." },
    allow: { text: "$(pass) SentinelGuard: Allow", tooltip: detail ?? "Last scan was allowed" },
    redact: { text: "$(warning) SentinelGuard: Redact", tooltip: detail ?? "Last scan was redacted" },
    block: { text: "$(error) SentinelGuard: Block", tooltip: detail ?? "Last scan was blocked" },
    offline: { text: "$(circle-slash) SentinelGuard: Offline", tooltip: detail ?? "Backend is not reachable" }
  } satisfies Record<typeof kind, { text: string; tooltip: string }>;

  statusBar.text = map[kind].text;
  statusBar.tooltip = map[kind].tooltip;
  statusBar.command = "sentinelguard.scanSelection";
  statusBar.show();
}

function setDiagnostics(artifact: ScanArtifact) {
  const documentUri = artifact.target.documentUri;
  const range = artifact.target.range;
  if (!getConfig().diagnosticsEnabled || !documentUri || !range) return;

  const { response } = artifact;
  if (response.decision === "ALLOW" && response.risk_level === "LOW") {
    diagnostics.set(documentUri, []);
    return;
  }

  const severity =
    response.decision === "BLOCK"
      ? vscode.DiagnosticSeverity.Error
      : response.decision === "REDACT"
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

  const issues = response.issues?.join(", ") || "No issues";
  const diagnostic = new vscode.Diagnostic(
    range,
    `SentinelGuard ${response.decision}: ${issues}`,
    severity
  );
  diagnostic.source = "SentinelGuard";
  diagnostic.code = `incident-${response.incident_id}`;
  diagnostics.set(documentUri, [diagnostic]);
}

function appendOutputReport(artifact: ScanArtifact) {
  const issues = artifact.response.issues?.join(", ") || "No issues";
  const gateway = buildGatewayDecision(artifact);
  output.appendLine("");
  output.appendLine("================================================================================");
  output.appendLine("SentinelGuard IDE Guard Scan");
  output.appendLine("================================================================================");
  output.appendLine(`Target:      ${artifact.target.label}`);
  output.appendLine(`Incident:    #${artifact.response.incident_id}`);
  output.appendLine(`Decision:    ${artifact.response.decision}`);
  output.appendLine(`Risk:        ${artifact.response.risk_level}`);
  output.appendLine(`Issues:      ${issues}`);
  output.appendLine(`Characters:  ${artifact.target.text.length}${artifact.target.truncated ? " (truncated)" : ""}`);
  output.appendLine("--------------------------------------------------------------------------------");
  output.appendLine("Sanitized output:");
  output.appendLine(artifact.sanitizedText);
  output.appendLine("--------------------------------------------------------------------------------");
  output.appendLine("AI enforcement gateway:");
  output.appendLine(gateway.title);
  output.appendLine(gateway.detail);
  output.appendLine("--------------------------------------------------------------------------------");
  output.appendLine("Guarded prompt:");
  output.appendLine(artifact.promptVariants.guarded);
  output.appendLine("================================================================================");
}

function buildGatewayDecision(artifact: ScanArtifact): GatewayDecision {
  const { response, target, sanitizedText } = artifact;

  if (response.decision === "BLOCK") {
    const payload = sanitizedText.trim();
    if (payload && payload !== target.text.trim()) {
      return {
        allowed: true,
        payload,
        payloadKind: "sanitized",
        requiresVerification: true,
        title: "Gateway will verify the sanitized prompt.",
        detail: `Incident #${response.incident_id} blocked the original content. SentinelGuard can only send the sanitized payload after a fresh policy check.`
      };
    }

    return {
      allowed: false,
      payload: "",
      payloadKind: "none",
      requiresVerification: false,
      title: "Gateway blocked the prompt.",
      detail: `Incident #${response.incident_id} cannot be sent because no safer sanitized payload is available.`
    };
  }

  if (response.decision === "REDACT") {
    const payload = sanitizedText.trim();
    return {
      allowed: !!payload,
      payload,
      payloadKind: payload ? "sanitized" : "none",
      requiresVerification: !!payload,
      title: payload ? "Gateway approved the sanitized prompt." : "Gateway could not find sanitized content to send.",
      detail: payload
        ? `Incident #${response.incident_id} may proceed only with SentinelGuard's sanitized payload after a fresh policy check.`
        : `Incident #${response.incident_id} requires redaction, but no sanitized payload was available.`
    };
  }

  const payload = target.text.trim();
  return {
    allowed: !!payload,
    payload,
    payloadKind: payload ? "original" : "none",
    requiresVerification: false,
    title: payload ? "Gateway approved the original prompt." : "Gateway found no prompt content to send.",
    detail: payload
      ? `Incident #${response.incident_id} was allowed by policy, so the original scanned content is approved.`
      : `Incident #${response.incident_id} was allowed, but the scanned content is empty.`
  };
}

async function runScan(target: ScanTarget) {
  const config = getConfig();
  updateStatus("scanning");
  output.appendLine(`Scanning ${target.label} (${target.text.length} chars)...`);

  let response: AnalyzeResponse;
  try {
    response = await requestJson<AnalyzeResponse>(
      "POST",
      buildUrl("/analyze"),
      { source: "IDE_GUARD", user_id: config.userId, text: target.text },
      config.timeoutMs
    );
  } catch (error: any) {
    const message = error?.message ?? String(error);
    output.appendLine(`Backend error: ${message}`);
    updateStatus("offline", message);
    vscode.window.showErrorMessage("SentinelGuard backend is not reachable. Start the FastAPI service and try again.");
    return;
  }

  const sanitizedText = response.sanitized_text || target.text;
  const artifact: ScanArtifact = {
    target,
    response,
    sanitizedText,
    promptVariants: buildPromptVariants(sanitizedText, response),
    timestamp: Date.now()
  };
  lastScan = artifact;

  const statusKind = response.decision === "BLOCK" ? "block" : response.decision === "REDACT" ? "redact" : "allow";
  updateStatus(statusKind, `Incident #${response.incident_id}: ${response.risk_level} risk`);
  setDiagnostics(artifact);
  appendOutputReport(artifact);
  renderReport(artifact);

  const shouldOpen =
    config.autoOpenReport === "always" ||
    (config.autoOpenReport === "onRisk" && (response.decision === "BLOCK" || response.decision === "REDACT"));
  if (shouldOpen) {
    reportPanel?.reveal(vscode.ViewColumn.Beside);
  }

  const issues = response.issues?.join(", ") || "No issues";
  const action = await vscode.window.showInformationMessage(
    `SentinelGuard ${response.decision} (${response.risk_level}) - ${issues}`,
    "AI Gateway",
    "Open Report",
    "Copy Safe Prompt",
    response.decision !== "ALLOW" && target.range ? "Replace with Sanitized" : "Copy Sanitized"
  );

  if (action === "AI Gateway") {
    vscode.commands.executeCommand("sentinelguard.sendThroughGateway");
  } else if (action === "Open Report") {
    vscode.commands.executeCommand("sentinelguard.openReport");
  } else if (action === "Copy Safe Prompt") {
    vscode.commands.executeCommand("sentinelguard.copyPrompt", "guarded");
  } else if (action === "Replace with Sanitized") {
    vscode.commands.executeCommand("sentinelguard.replaceWithSanitized");
  } else if (action === "Copy Sanitized") {
    vscode.commands.executeCommand("sentinelguard.copySanitized");
  }
}

function requireLastScan(): ScanArtifact | undefined {
  if (!lastScan) {
    vscode.window.showInformationMessage("Run a SentinelGuard scan first.");
    return undefined;
  }
  return lastScan;
}

async function copySanitized() {
  const artifact = requireLastScan();
  if (!artifact) return;
  await vscode.env.clipboard.writeText(artifact.sanitizedText);
  vscode.window.showInformationMessage("Sanitized output copied.");
}

async function sendThroughGateway() {
  const artifact = requireLastScan();
  if (!artifact) return;

  const config = getConfig();
  const gateway = buildGatewayDecision(artifact);
  output.appendLine("");
  output.appendLine("--------------------------------------------------------------------------------");
  output.appendLine("SentinelGuard AI Enforcement Gateway");
  output.appendLine(gateway.title);
  output.appendLine(gateway.detail);

  if (!gateway.allowed) {
    updateStatus("block", gateway.detail);
    vscode.window.showWarningMessage(gateway.title);
    return;
  }

  let approvedPayload = gateway.payload;
  let approvalTitle = gateway.title;
  let approvalDetail = gateway.detail;

  if (gateway.requiresVerification) {
    updateStatus("scanning", "Re-checking sanitized gateway payload");
    output.appendLine("Re-checking sanitized payload before AI send...");

    let verification: AnalyzeResponse;
    try {
      verification = await requestJson<AnalyzeResponse>(
        "POST",
        buildUrl("/analyze"),
        { source: "IDE_GUARD", user_id: config.userId, text: gateway.payload },
        config.timeoutMs
      );
    } catch (error: any) {
      const message = error?.message ?? String(error);
      output.appendLine(`Gateway verification failed: ${message}`);
      updateStatus("offline", message);
      vscode.window.showErrorMessage("SentinelGuard gateway verification failed. Check the backend and try again.");
      return;
    }

    output.appendLine(`Verification incident: #${verification.incident_id}`);
    output.appendLine(`Verification decision: ${verification.decision}`);
    output.appendLine(`Verification risk: ${verification.risk_level}`);
    output.appendLine(`Verification issues: ${verification.issues?.join(", ") || "No issues"}`);

    if (verification.decision === "BLOCK") {
      const issues = verification.issues?.join(", ") || "policy risk";
      const detail = `Sanitized payload was still blocked by incident #${verification.incident_id}: ${issues}`;
      output.appendLine(detail);
      updateStatus("block", detail);
      vscode.window.showWarningMessage("Gateway blocked the sanitized payload after verification.");
      return;
    }

    approvedPayload = verification.decision === "REDACT"
      ? verification.sanitized_text?.trim() || gateway.payload
      : gateway.payload;
    approvalTitle = verification.decision === "REDACT"
      ? "Gateway approved the re-sanitized prompt."
      : "Gateway approved the sanitized prompt.";
    approvalDetail = `Verification incident #${verification.incident_id} returned ${verification.decision}.`;
    updateStatus(verification.decision === "REDACT" ? "redact" : "allow", approvalDetail);
  } else {
    updateStatus("allow", approvalDetail);
  }

  await vscode.env.clipboard.writeText(approvedPayload);
  output.appendLine(approvalTitle);
  output.appendLine(approvalDetail);
  output.appendLine(`Approved payload type: ${gateway.payloadKind}`);
  output.appendLine(`Approved payload length: ${approvedPayload.length} characters.`);
  output.appendLine("The approved payload was copied to the clipboard.");

  const action = await vscode.window.showInformationMessage(
    `${approvalTitle} Approved payload copied to clipboard.`,
    "Open Report",
    "Copy Safe Prompt"
  );
  if (action === "Open Report") {
    vscode.commands.executeCommand("sentinelguard.openReport");
  } else if (action === "Copy Safe Prompt") {
    vscode.commands.executeCommand("sentinelguard.copyPrompt", "guarded");
  }
}

async function copyPrompt(style: PromptStyle = "guarded") {
  const artifact = requireLastScan();
  if (!artifact) return;
  await vscode.env.clipboard.writeText(artifact.promptVariants[style] ?? artifact.promptVariants.guarded);
  vscode.window.showInformationMessage(`${styleLabel(style)} prompt copied.`);
}

async function insertPrompt(style: PromptStyle = "guarded") {
  const artifact = requireLastScan();
  const editor = vscode.window.activeTextEditor;
  if (!artifact || !editor) {
    if (!editor) vscode.window.showInformationMessage("Open an editor to insert the prompt.");
    return;
  }

  await editor.edit((edit) => {
    edit.insert(editor.selection.active, artifact.promptVariants[style] ?? artifact.promptVariants.guarded);
  });
  vscode.window.showInformationMessage(`${styleLabel(style)} prompt inserted.`);
}

async function replaceWithSanitized() {
  const artifact = requireLastScan();
  if (!artifact) return;
  if (artifact.target.truncated) {
    vscode.window.showWarningMessage("This scan was truncated, so SentinelGuard will not replace editor content automatically.");
    return;
  }
  if (!artifact.target.documentUri || !artifact.target.range) {
    vscode.window.showWarningMessage("No editor range is available for the last scan.");
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  edit.replace(artifact.target.documentUri, artifact.target.range, artifact.sanitizedText);
  const ok = await vscode.workspace.applyEdit(edit);
  if (ok) {
    vscode.window.showInformationMessage("Selection replaced with sanitized output.");
  } else {
    vscode.window.showErrorMessage("Could not replace the selection with sanitized output.");
  }
}

async function openDashboardIncident() {
  const artifact = requireLastScan();
  if (!artifact) return;
  const url = vscode.Uri.parse(`${getConfig().frontendBaseUrl}/dashboard?incident=${artifact.response.incident_id}`);
  await vscode.env.openExternal(url);
}

async function checkHealth() {
  try {
    await requestJson<{ status: string }>("GET", buildUrl("/health"), undefined, getConfig().timeoutMs);
    updateStatus(statusKindForLastScan(), "Backend health check passed");
    vscode.window.showInformationMessage("SentinelGuard backend is online.");
  } catch (error: any) {
    const message = error?.message ?? String(error);
    updateStatus("offline", message);
    vscode.window.showErrorMessage(`SentinelGuard backend is offline: ${message}`);
  }
}

function statusKindForLastScan(): "idle" | "allow" | "redact" | "block" {
  if (!lastScan) return "idle";
  if (lastScan.response.decision === "BLOCK") return "block";
  if (lastScan.response.decision === "REDACT") return "redact";
  return "allow";
}

async function refreshHealthSilently() {
  try {
    await requestJson<{ status: string }>("GET", buildUrl("/health"), undefined, getConfig().timeoutMs);
    updateStatus(statusKindForLastScan());
  } catch (error: any) {
    updateStatus("offline", error?.message ?? String(error));
  }
}

function styleLabel(style: PromptStyle): string {
  return PROMPT_STYLES.find((item) => item.id === style)?.label ?? "Guarded";
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function commandUri(command: string, args: unknown[] = []): string {
  return `command:${command}?${encodeURIComponent(JSON.stringify(args))}`;
}

function renderReport(artifact: ScanArtifact) {
  if (!reportPanel) {
    reportPanel = vscode.window.createWebviewPanel(
      "sentinelguard.report",
      "SentinelGuard Report",
      vscode.ViewColumn.Beside,
      { enableCommandUris: true, retainContextWhenHidden: true }
    );
    reportPanel.onDidDispose(() => {
      reportPanel = undefined;
    });
  }

  reportPanel.title = `SentinelGuard #${artifact.response.incident_id}`;
  reportPanel.webview.html = buildReportHtml(artifact);
}

function issuePills(issues: string[]): string {
  if (!issues.length) return `<span class="pill">No issues</span>`;
  return issues.map((issue) => `<span class="pill">${escapeHtml(issue)}</span>`).join("");
}

function promptCards(artifact: ScanArtifact): string {
  return PROMPT_STYLES.map((style) => {
    const prompt = artifact.promptVariants[style.id];
    return `
      <section class="prompt-card">
        <div class="panel-head">
          <div>
            <div class="eyebrow">${escapeHtml(style.label)} prompt</div>
            <h3>${escapeHtml(style.label)}</h3>
          </div>
          <div class="actions">
            <a href="${commandUri("sentinelguard.copyPrompt", [style.id])}">Copy</a>
            <a href="${commandUri("sentinelguard.insertPrompt", [style.id])}">Insert</a>
          </div>
        </div>
        <pre>${escapeHtml(prompt)}</pre>
      </section>
    `;
  }).join("");
}

function buildReportHtml(artifact: ScanArtifact): string {
  const { response } = artifact;
  const tone = response.decision === "BLOCK" ? "danger" : response.decision === "REDACT" ? "warning" : "success";
  const issues = response.issues || [];
  const generatedAt = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(artifact.timestamp);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelGuard Report</title>
  <style>
    :root {
      --bg: #0f1110;
      --surface: #171a18;
      --surface-2: #202620;
      --border: #2f3830;
      --text: #edf3ea;
      --muted: #9aa798;
      --accent: #22c59b;
      --danger: #ff867d;
      --warning: #ffc36d;
      --success: #59dcb8;
    }
    body {
      margin: 0;
      color: var(--text);
      background: linear-gradient(180deg, #151816, #0f1110);
      font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      max-width: 1060px;
      margin: 0 auto;
      padding: 24px;
    }
    .hero, .panel, .prompt-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
    }
    .hero {
      display: grid;
      gap: 18px;
      padding: 22px;
      margin-bottom: 14px;
    }
    .hero-top, .panel-head, .actions, .metric-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .eyebrow {
      color: var(--accent);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    h1, h2, h3, p {
      margin: 0;
    }
    h1 {
      font-size: 28px;
      line-height: 1.1;
    }
    h2, h3 {
      font-size: 15px;
    }
    .decision {
      min-width: 112px;
      text-align: center;
      border-radius: 8px;
      padding: 12px;
      font-size: 18px;
      font-weight: 850;
    }
    .decision.danger { color: var(--danger); background: rgba(255, 134, 125, 0.12); }
    .decision.warning { color: var(--warning); background: rgba(255, 195, 109, 0.12); }
    .decision.success { color: var(--success); background: rgba(89, 220, 184, 0.12); }
    .metrics {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
    }
    .metric {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
    }
    .metric b {
      display: block;
      font-size: 18px;
      margin-top: 3px;
    }
    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }
    .pill {
      color: var(--text);
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 999px;
      font-size: 11px;
      font-weight: 750;
      padding: 5px 9px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 14px;
    }
    .prompt-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 14px;
    }
    .panel, .prompt-card {
      overflow: hidden;
    }
    .panel-head {
      border-bottom: 1px solid var(--border);
      background: rgba(255, 255, 255, 0.03);
      padding: 12px 14px;
    }
    pre {
      margin: 0;
      max-height: 360px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: #e8f4ef;
      background: #090d0b;
      padding: 14px;
      font: 12px/1.6 "SFMono-Regular", Consolas, monospace;
    }
    a {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 30px;
      color: #06130f;
      background: var(--accent);
      border-radius: 7px;
      font-weight: 800;
      padding: 0 10px;
      text-decoration: none;
    }
    a.secondary {
      color: var(--text);
      background: var(--surface-2);
      border: 1px solid var(--border);
    }
    .actions {
      justify-content: flex-end;
    }
    .muted {
      color: var(--muted);
    }
    @media (max-width: 760px) {
      main { padding: 14px; }
      .grid, .prompt-grid, .metrics { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-top">
        <div>
          <div class="eyebrow">SentinelGuard IDE Guard</div>
          <h1>Incident #${escapeHtml(String(response.incident_id))}</h1>
          <p class="muted">${escapeHtml(artifact.target.label)} / ${escapeHtml(generatedAt)}</p>
        </div>
        <div class="decision ${tone}">${escapeHtml(response.decision)}</div>
      </div>
      <div class="metrics">
        <div class="metric"><span class="muted">Risk</span><b>${escapeHtml(response.risk_level)}</b></div>
        <div class="metric"><span class="muted">Issues</span><b>${issues.length}</b></div>
        <div class="metric"><span class="muted">Characters</span><b>${artifact.target.text.length}${artifact.target.truncated ? "+" : ""}</b></div>
      </div>
      <div class="pill-row">${issuePills(issues)}</div>
      <div class="actions">
        <a href="${commandUri("sentinelguard.sendThroughGateway")}">AI Gateway</a>
        <a href="${commandUri("sentinelguard.copySanitized")}">Copy Sanitized</a>
        <a class="secondary" href="${commandUri("sentinelguard.replaceWithSanitized")}">Replace Selection</a>
        <a class="secondary" href="${commandUri("sentinelguard.openDashboardIncident")}">Open Dashboard</a>
      </div>
    </section>

    <section class="grid">
      <article class="panel">
        <div class="panel-head">
          <h2>Original</h2>
        </div>
        <pre>${escapeHtml(artifact.target.text)}</pre>
      </article>
      <article class="panel">
        <div class="panel-head">
          <h2>Sanitized</h2>
        </div>
        <pre>${escapeHtml(artifact.sanitizedText)}</pre>
      </article>
    </section>

    <section class="prompt-grid">
      ${promptCards(artifact)}
    </section>
  </main>
</body>
</html>`;
}

export function activate(context: vscode.ExtensionContext) {
  output = vscode.window.createOutputChannel("SentinelGuard");
  diagnostics = vscode.languages.createDiagnosticCollection("sentinelguard");
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 96);
  updateStatus("idle");
  refreshHealthSilently().then(undefined, () => undefined);

  const healthTimer = setInterval(() => {
    refreshHealthSilently().then(undefined, () => undefined);
  }, 60_000);

  context.subscriptions.push(
    output,
    diagnostics,
    statusBar,
    { dispose: () => clearInterval(healthTimer) },
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("sentinelguard")) {
        updateStatus(statusKindForLastScan());
      }
    }),
    vscode.commands.registerCommand("sentinelguard.scanSelection", async () => {
      const target = await getSelectionTarget();
      if (target) await runScan(target);
    }),
    vscode.commands.registerCommand("sentinelguard.scanDocument", async () => {
      const target = await getDocumentTarget();
      if (target) await runScan(target);
    }),
    vscode.commands.registerCommand("sentinelguard.openReport", () => {
      const artifact = requireLastScan();
      if (!artifact) return;
      renderReport(artifact);
      reportPanel?.reveal(vscode.ViewColumn.Beside);
    }),
    vscode.commands.registerCommand("sentinelguard.copySanitized", copySanitized),
    vscode.commands.registerCommand("sentinelguard.sendThroughGateway", sendThroughGateway),
    vscode.commands.registerCommand("sentinelguard.copyPrompt", copyPrompt),
    vscode.commands.registerCommand("sentinelguard.insertPrompt", insertPrompt),
    vscode.commands.registerCommand("sentinelguard.replaceWithSanitized", replaceWithSanitized),
    vscode.commands.registerCommand("sentinelguard.openDashboardIncident", openDashboardIncident),
    vscode.commands.registerCommand("sentinelguard.checkHealth", checkHealth),
    vscode.commands.registerCommand("sentinelguard.clearDiagnostics", () => {
      diagnostics.clear();
      vscode.window.showInformationMessage("SentinelGuard diagnostics cleared.");
    })
  );
}

export function deactivate() {}
