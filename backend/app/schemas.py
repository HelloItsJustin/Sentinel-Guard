from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


SourceType = Literal["AI_WORKSPACE", "IDE_GUARD"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]
Decision = Literal["ALLOW", "BLOCK", "REDACT"]
AuditStorageMode = Literal["PROTECTED", "FULL_TEXT"]

# Issue type descriptions for UI tooltips
ISSUE_DESCRIPTIONS = {
    "CREDENTIALS": "Authentication credentials detected (API keys, tokens, passwords)",
    "CREDENTIALS_AWS_ACCESS_KEY_ID": "AWS Access Key ID detected",
    "CREDENTIALS_AWS_SECRET_ACCESS_KEY": "AWS secret access key detected",
    "CREDENTIALS_AWS_SESSION_TOKEN": "AWS session token detected",
    "CREDENTIALS_ALIBABA_KEY": "Alibaba Cloud access key detected",
    "CREDENTIALS_AZURE_CLIENT_SECRET": "Azure client secret detected",
    "CREDENTIALS_AZURE_SAS_TOKEN": "Azure SAS token detected",
    "CREDENTIALS_OPENAI_KEY": "OpenAI API key detected",
    "CREDENTIALS_ANTHROPIC_KEY": "Anthropic API key detected",
    "CREDENTIALS_DISCORD_TOKEN": "Discord authentication token detected",
    "CREDENTIALS_TWITCH_TOKEN": "Twitch OAuth token detected",
    "CREDENTIALS_GITHUB_TOKEN": "GitHub authentication token detected",
    "CREDENTIALS_GITLAB_PAT": "GitLab Personal Access Token detected",
    "CREDENTIALS_SLACK_TOKEN": "Slack authentication token detected",
    "CREDENTIALS_STRIPE_KEY": "Stripe API key detected",
    "CREDENTIALS_GOOGLE_API_KEY": "Google API key detected",
    "CREDENTIALS_GOOGLE_OAUTH_SECRET": "Google OAuth secret detected",
    "CREDENTIALS_JWT_TOKEN": "JWT authentication token detected",
    "CREDENTIALS_PRIVATE_KEY": "Private cryptographic key detected (RSA, EC, DSA, OpenSSH)",
    "CREDENTIALS_KEY_VALUE": "Key-value pair credential detected",
    "CREDENTIALS_TWILIO_SID": "Twilio Account SID detected",
    "CREDENTIALS_TWILIO_TOKEN": "Twilio authentication token detected",
    "CREDENTIALS_SENDGRID_KEY": "SendGrid API key detected",
    "CREDENTIALS_NPM_TOKEN": "npm authentication token detected",
    "CREDENTIALS_VAULT_TOKEN": "HashiCorp Vault token detected",
    "CREDENTIALS_NEW_RELIC_KEY": "New Relic API key detected",
    "CREDENTIALS_DIGITAL_OCEAN_PAT": "DigitalOcean Personal Access Token detected",
    "CREDENTIALS_MAILCHIMP_KEY": "Mailchimp API key detected",
    "CREDENTIALS_SQUARE_KEY": "Square API key detected",
    "CREDENTIALS_AZURE_STORAGE": "Azure Storage connection string detected",
    "CREDENTIALS_DATADOG_KEY": "Datadog API key detected",
    "CREDENTIALS_PAGERDUTY_KEY": "PagerDuty API key detected",
    "CREDENTIALS_HEROKU_KEY": "Heroku API key detected",
    "CREDENTIALS_MONGODB_URI": "MongoDB connection URI with credentials detected",
    "CREDENTIALS_REDIS_URI": "Redis connection URI with credentials detected",
    "CREDENTIALS_CRYPTO_PRIVATE_KEY": "Hex-format private key detected",
    "DB_CONN_STRING": "Database connection string detected",
    "FINANCIAL_SWIFT_CODE": "Bank SWIFT / BIC code detected",
    "PII_EMAIL": "Email address detected",
    "PII_PHONE": "Phone number detected",
    "PII_SSN": "Social Security Number detected",
    "PII_UK_NIN": "UK National Insurance Number detected",
    "PII_PASSPORT": "Passport number detected",
    "PII_DRIVERS_LICENSE": "Driver's license number detected",
    "PII_DOB": "Date of birth detected",
    "PII_DATE": "Sensitive date detected in a personal, commerce, or security context",
    "PII_NAME": "Personal name detected in a sensitive record",
    "PII_IP_ADDRESS": "IP address detected in a login or security context",
    "PII_ADDRESS": "Physical mailing or billing address detected",
    "GOVERNMENT_AADHAAR": "Aadhaar / UIDAI identifier detected",
    "GOVERNMENT_INDIA_PAN": "India PAN tax identifier detected",
    "GOVERNMENT_US_EIN": "US EIN / federal tax identifier detected",
    "GOVERNMENT_GENERIC_ID": "Government-like identifier detected",
    "GOVERNMENT_KYC_DOCUMENT": "KYC document marker detected",
    "FINANCIAL_CARD": "Payment card number detected (validated with Luhn)",
    "FINANCIAL_CARD_SECURITY_CODE": "Payment card CVV / CVC detected",
    "FINANCIAL_CARD_EXPIRY": "Payment card expiration date detected",
    "FINANCIAL_ROUTING_NUMBER": "Bank routing number detected",
    "FINANCIAL_ACCOUNT_NUMBER": "Bank account number detected",
    "FINANCIAL_IBAN": "International Bank Account Number (IBAN) detected",
    "FINANCIAL_UK_SORT_CODE": "UK bank sort code detected",
    "FINANCIAL_VAT_ID": "VAT tax identifier detected",
    "FINANCIAL_GSTIN": "India GSTIN tax identifier detected",
    "FINANCIAL_UPI_ID": "UPI / VPA payment identifier detected",
    "COMMERCE_INVOICE_ID": "Invoice identifier detected",
    "COMMERCE_ORDER_ID": "Order or purchase-order identifier detected",
    "COMMERCE_TRACKING_NUMBER": "Shipment or tracking number detected",
    "COMMERCE_CUSTOMER_ID": "Customer, client, account, or subscriber identifier detected",
    "HEALTH_MEDICAL_RECORD": "Medical record or patient identifier detected",
    "HEALTH_INSURANCE_MEMBER_ID": "Health insurance member or policy identifier detected",
    "HEALTH_PRESCRIPTION_ID": "Prescription / Rx identifier detected",
    "LEGAL_CASE_NUMBER": "Legal case, docket, or matter identifier detected",
    "LEGAL_PRIVILEGED_CONTENT": "Privileged legal content marker detected",
    "BUSINESS_CONFIDENTIAL": "Confidential business information marker detected",
    "HR_EMPLOYEE_ID": "Employee identifier detected",
    "HR_PAYROLL_ID": "Payroll identifier detected",
    "HR_COMPENSATION": "Compensation or salary amount detected",
    "SECRET_HIGH_ENTROPY": "High-entropy string detected (possible secret)",
}


class AnalyzeRequest(BaseModel):
    source: SourceType
    user_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=0, max_length=50_000)


class AnalyzeResponse(BaseModel):
    risk_level: RiskLevel
    issues: list[str]
    decision: Decision
    sanitized_text: str | None
    incident_id: int


class PolicyConfig(BaseModel):
    block_credentials: bool = True
    redact_high_entropy: bool = True
    redact_pii: bool = True
    redact_financial: bool = True
    redact_government_ids: bool = True
    redact_health: bool = True
    redact_legal: bool = True
    redact_hr: bool = True
    redact_commerce: bool = True
    redact_business_confidential: bool = True
    audit_storage: AuditStorageMode = "PROTECTED"


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source: str
    user_id: str
    original_text: str
    sanitized_text: str | None
    risk_level: str
    issues: str
    decision: str
    policy_snapshot: str | None = None
    hash_chain: str
