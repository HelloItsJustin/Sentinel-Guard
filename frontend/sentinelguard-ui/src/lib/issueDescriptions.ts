export const ISSUE_DESCRIPTIONS: Record<string, string> = {
  // Umbrella tags
  CREDENTIALS: "API key, token, or password detected",
  DB_CONN_STRING: "Database connection string with embedded credentials",
  SECRET_HIGH_ENTROPY: "High-entropy token that may be a secret or API key",

  // PII / government IDs
  PII_EMAIL: "Email address - personal data",
  PII_PHONE: "Phone number - personal data",
  PII_SSN: "US Social Security Number - highly sensitive PII",
  PII_PASSPORT: "Passport number - highly sensitive PII",
  PII_DOB: "Date of birth - personal data",
  PII_DATE: "Sensitive date in a personal, commerce, or security context",
  PII_NAME: "Personal name in a sensitive record",
  PII_IP_ADDRESS: "IP address in a login or security context",
  PII_DRIVERS_LICENSE: "Driver licence number - personal data",
  PII_UK_NIN: "UK National Insurance Number - personal data",
  PII_ADDRESS: "Physical address - shipping, billing, or mailing data",
  GOVERNMENT_AADHAAR: "Aadhaar / UIDAI government identifier",
  GOVERNMENT_INDIA_PAN: "India PAN tax identifier",
  GOVERNMENT_US_EIN: "US EIN / federal tax identifier",
  GOVERNMENT_GENERIC_ID: "Government-like identity number",
  GOVERNMENT_KYC_DOCUMENT: "KYC document marker",

  // Cloud / platform credentials
  CREDENTIALS_AWS_ACCESS_KEY_ID: "AWS Access Key ID (AKIA or ASIA prefix)",
  CREDENTIALS_AWS_SECRET_ACCESS_KEY: "AWS secret access key",
  CREDENTIALS_AWS_SESSION_TOKEN: "AWS session token",
  CREDENTIALS_ALIBABA_KEY: "Alibaba Cloud access key",
  CREDENTIALS_AZURE_CLIENT_SECRET: "Azure client secret",
  CREDENTIALS_AZURE_SAS_TOKEN: "Azure SAS token",
  CREDENTIALS_OPENAI_KEY: "OpenAI API key (sk- prefix)",
  CREDENTIALS_ANTHROPIC_KEY: "Anthropic API key (sk-ant- prefix)",
  CREDENTIALS_GITHUB_TOKEN: "GitHub personal access token or fine-grained PAT",
  CREDENTIALS_GITLAB_PAT: "GitLab personal access token (glpat- prefix)",
  CREDENTIALS_SLACK_TOKEN: "Slack bot or app token (xox prefix)",
  CREDENTIALS_STRIPE_KEY: "Stripe secret or restricted API key",
  CREDENTIALS_GOOGLE_API_KEY: "Google API key (AIza prefix)",
  CREDENTIALS_GOOGLE_OAUTH_SECRET: "Google OAuth client secret (GOCSPX prefix)",
  CREDENTIALS_JWT_TOKEN: "JSON Web Token or Bearer authorization header",
  CREDENTIALS_PRIVATE_KEY: "PEM-encoded private key (RSA, EC, DSA, or OpenSSH)",
  CREDENTIALS_KEY_VALUE: "Generic key=value secret pattern (password, token, api_key)",
  CREDENTIALS_DISCORD_TOKEN: "Discord authentication token",
  CREDENTIALS_TWITCH_TOKEN: "Twitch OAuth token",
  CREDENTIALS_CRYPTO_PRIVATE_KEY: "Crypto private key",

  // Cloud providers
  CREDENTIALS_AZURE_STORAGE: "Azure Storage connection string with account key",
  CREDENTIALS_DIGITAL_OCEAN_PAT: "DigitalOcean personal access token (dop_v1_ prefix)",
  CREDENTIALS_TWILIO_SID: "Twilio Account SID (AC prefix + 32 hex chars)",
  CREDENTIALS_TWILIO_TOKEN: "Twilio Auth Token",
  CREDENTIALS_SENDGRID_KEY: "SendGrid API key (SG. prefix)",
  CREDENTIALS_NPM_TOKEN: "npm access token (npm_ prefix)",
  CREDENTIALS_VAULT_TOKEN: "HashiCorp Vault service token (hvs. prefix)",
  CREDENTIALS_NEW_RELIC_KEY: "New Relic API key (NRAK- prefix)",
  CREDENTIALS_MONGODB_URI: "MongoDB connection URI with embedded credentials",
  CREDENTIALS_REDIS_URI: "Redis connection URI with embedded credentials",
  CREDENTIALS_MAILCHIMP_KEY: "Mailchimp API key (XXXX-usN format)",
  CREDENTIALS_SQUARE_KEY: "Square API access token (EAAA prefix)",
  CREDENTIALS_DATADOG_KEY: "Datadog API or application key",
  CREDENTIALS_PAGERDUTY_KEY: "PagerDuty API key",
  CREDENTIALS_HEROKU_KEY: "Heroku API key",

  // Financial
  FINANCIAL_CARD: "Payment card number (Luhn-validated)",
  FINANCIAL_CARD_SECURITY_CODE: "Payment card CVV / CVC",
  FINANCIAL_CARD_EXPIRY: "Payment card expiration date",
  FINANCIAL_ROUTING_NUMBER: "US ABA bank routing number",
  FINANCIAL_ACCOUNT_NUMBER: "Bank account number",
  FINANCIAL_IBAN: "International Bank Account Number (IBAN)",
  FINANCIAL_UK_SORT_CODE: "UK bank sort code (XX-XX-XX format)",
  FINANCIAL_SWIFT_CODE: "Bank SWIFT / BIC code",
  FINANCIAL_VAT_ID: "VAT tax identifier",
  FINANCIAL_GSTIN: "India GSTIN tax identifier",
  FINANCIAL_UPI_ID: "UPI / VPA payment identifier",

  // Commerce / operations
  COMMERCE_INVOICE_ID: "Invoice identifier",
  COMMERCE_ORDER_ID: "Order or purchase-order identifier",
  COMMERCE_TRACKING_NUMBER: "Shipment or parcel tracking number",
  COMMERCE_CUSTOMER_ID: "Customer, client, account, or subscriber identifier",

  // Health / legal / HR
  HEALTH_MEDICAL_RECORD: "Medical record or patient identifier",
  HEALTH_INSURANCE_MEMBER_ID: "Health insurance member or policy identifier",
  HEALTH_PRESCRIPTION_ID: "Prescription / Rx identifier",
  LEGAL_CASE_NUMBER: "Legal case, docket, or matter identifier",
  LEGAL_PRIVILEGED_CONTENT: "Privileged legal content marker",
  BUSINESS_CONFIDENTIAL: "Confidential business information marker",
  HR_EMPLOYEE_ID: "Employee identifier",
  HR_PAYROLL_ID: "Payroll identifier",
  HR_COMPENSATION: "Compensation or salary amount",
};

export function getIssueDescription(issue: string): string {
  return ISSUE_DESCRIPTIONS[issue] ?? issue.replace(/_/g, " ").toLowerCase();
}
