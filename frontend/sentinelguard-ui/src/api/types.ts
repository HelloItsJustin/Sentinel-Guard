export type SourceType = "AI_WORKSPACE" | "IDE_GUARD";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";
export type Decision = "ALLOW" | "BLOCK" | "REDACT";
export type AuditStorageMode = "PROTECTED" | "FULL_TEXT";

export type AnalyzeRequest = {
  source: SourceType;
  user_id: string;
  text: string;
};

export type AnalyzeResponse = {
  risk_level: RiskLevel;
  issues: string[];
  decision: Decision;
  sanitized_text: string | null;
  incident_id: number;
};

export type PolicyConfig = {
  block_credentials: boolean;
  redact_high_entropy: boolean;
  redact_pii: boolean;
  redact_financial: boolean;
  redact_government_ids: boolean;
  redact_health: boolean;
  redact_legal: boolean;
  redact_hr: boolean;
  redact_commerce: boolean;
  redact_business_confidential: boolean;
  audit_storage: AuditStorageMode;
};

export type Incident = {
  id: number;
  timestamp: string;
  source: string;
  user_id: string;
  original_text: string;
  sanitized_text: string | null;
  risk_level: string;
  issues: string; // JSON string
  decision: string;
  policy_snapshot: string | null;
  hash_chain: string;
};
