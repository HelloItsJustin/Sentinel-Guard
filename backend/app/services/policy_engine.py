from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Literal, TypedDict

from ..classifiers.rules import (
    _EMAIL_RE,
    _PHONE_RE,
    _SSN_RE,
    _UK_NIN_RE,
    _PASSPORT_RE,
    _DRIVERS_LICENSE_RE,
    _DOB_RE,
    _ADDRESS_RE,
    _DATE_TOKEN_RE,
    _CONTEXTUAL_PERSON_NAME_RE,
    _CSV_PERSON_NAME_RE,
    _LABELED_PERSON_NAME_RE,
    _SENSITIVE_DATE_CONTEXT_RE,
    _IPV4_RE,
    _IP_ADDRESS_CONTEXT_RE,
    _AADHAAR_RE,
    _INDIA_PAN_RE,
    _US_EIN_RE,
    _GENERIC_GOVERNMENT_ID_RE,
    _KYC_DOCUMENT_RE,
    _AWS_ACCESS_KEY_ID_RE,
    _OPENAI_KEY_RE,
    _ANTHROPIC_KEY_RE,
    _GITHUB_TOKEN_RE,
    _GITHUB_FINE_GRAINED_RE,
    _GITLAB_PAT_RE,
    _SLACK_TOKEN_RE,
    _STRIPE_SECRET_KEY_RE,
    _STRIPE_RESTRICTED_KEY_RE,
    _GOOGLE_API_KEY_RE,
    _GOOGLE_OAUTH_CLIENT_SECRET_RE,
    _PEM_PRIVATE_KEY_RE,
    _PEM_PRIVATE_KEY_BLOCK_RE,
    _JWT_RE,
    _JWT_LIKE_RE,
    _BEARER_TOKEN_RE,
    _AWS_SECRET_ACCESS_KEY_RE,
    _AWS_SESSION_TOKEN_RE,
    _ALIBABA_ACCESS_KEY_RE,
    _AZURE_CLIENT_SECRET_RE,
    _AZURE_SAS_TOKEN_RE,
    _DISCORD_TOKEN_RE,
    _TWITCH_OAUTH_RE,
    _CRYPTO_PRIVATE_KEY_RE,
    _SWIFT_CODE_RE,
    _TWILIO_ACCOUNT_SID_RE,
    _TWILIO_AUTH_TOKEN_RE,
    _SENDGRID_KEY_RE,
    _NPM_TOKEN_RE,
    _VAULT_TOKEN_RE,
    _NEW_RELIC_KEY_RE,
    _DIGITALOCEAN_PAT_RE,
    _MAILCHIMP_KEY_RE,
    _SQUARE_KEY_RE,
    _AZURE_STORAGE_RE,
    _DATADOG_KEY_RE,
    _REDIS_URI_RE,
    _MONGODB_URI_RE,
    _PAGERDUTY_KEY_RE,
    _HEROKU_KEY_RE,
    _UK_SORT_CODE_RE,
    _CARD_CVV_RE,
    _CARD_EXPIRY_RE,
    _VAT_ID_RE,
    _INDIA_GSTIN_RE,
    _UPI_ID_RE,
    _INVOICE_ID_RE,
    _ORDER_ID_RE,
    _TRACKING_NUMBER_RE,
    _CUSTOMER_ID_RE,
    _MEDICAL_RECORD_RE,
    _INSURANCE_MEMBER_RE,
    _PRESCRIPTION_ID_RE,
    _LEGAL_CASE_RE,
    _LEGAL_PRIVILEGED_RE,
    _BUSINESS_CONFIDENTIAL_RE,
    _EMPLOYEE_ID_RE,
    _PAYROLL_ID_RE,
    _COMPENSATION_RE,
    ClassificationResult,
)


Decision = Literal["ALLOW", "BLOCK", "REDACT"]


class PolicyConfigDict(TypedDict, total=False):
    block_credentials: bool
    redact_high_entropy: bool
    redact_pii: bool
    redact_financial: bool
    redact_government_ids: bool
    redact_health: bool
    redact_legal: bool
    redact_hr: bool
    redact_commerce: bool
    redact_business_confidential: bool


class PolicyResult(TypedDict):
    decision: Decision
    sanitized_text: str | None


DEFAULT_POLICY_CONFIG: PolicyConfigDict = {
    "block_credentials": True,
    "redact_high_entropy": True,
    "redact_pii": True,
    "redact_financial": True,
    "redact_government_ids": True,
    "redact_health": True,
    "redact_legal": True,
    "redact_hr": True,
    "redact_commerce": True,
    "redact_business_confidential": True,
}

_REDACTION_TOKEN = "[REDACTED]"

# Extra lightweight redact for common secret key/value patterns.
_SECRET_KV_REDACT_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"client[_-]?secret|azure[_-]?client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"aws_secret_access_key|aws_access_key_id|github_token|openai_api_key|anthropic_api_key|"
    r"stripe_secret_key|database_url|redis_url|discord_token|twitch[_-]?oauth|jwt[_\s-]?signing[_\s-]?secret"
    r")\b(\s*[:=]\s*)(?:\"([^\"]{2,})\"|'([^']{2,})'|([^\s;]{2,}))"
)

_DB_CONN_REDACT_RE = re.compile(r"(?i)\b(?:postgres(?:ql)?://|mysql://|mongodb(?:\+srv)?://|jdbc:|oracle://|sqlserver://|mariadb://|redis://)\S+")

_HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{20,200}\b")
_HEX_TOKEN_RE = re.compile(r"\b[a-f0-9]{32,128}\b", re.IGNORECASE)
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,32}\b")
_PERSON_NAME_SOURCE = r"[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){1,3}"
_HR_EXPORT_ROW_FIELDS_RE = re.compile(
    rf"(?m)^(?P<prefix>\s*)(?P<name>{_PERSON_NAME_SOURCE})(?P<sep1>\s*,\s*)"
    r"(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?P<sep2>\s*,\s*)"
    r"(?P<dob>\d{4}[/\-]\d{1,2}[/\-]\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})(?P<sep3>\s*,\s*)"
    r"(?P<gov_id>[A-Z0-9][A-Z0-9 -]{5,35})(?P<sep4>\s*,\s*)"
    r"(?P<salary>(?:[$€£₹]\s*)?\d[\d,]*(?:\.\d{2})?)(?P<suffix>\s*)$"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def _redact_suspicious_tokens(text: str) -> str:
    keyword_re = re.compile(r"(?i)\b(key|token|secret|password|passwd|pwd|bearer|authorization)\b")

    def redact_line(line: str) -> str:
        has_keyword = bool(keyword_re.search(line))

        def repl(m: re.Match[str]) -> str:
            token = m.group(0)
            if token.isalpha():
                return token
            ent = _shannon_entropy(token)
            if ent >= 3.9 and (has_keyword or len(token) >= 28):
                return _REDACTION_TOKEN
            return token

        def repl_hex(m: re.Match[str]) -> str:
            token = m.group(0)
            ent = _shannon_entropy(token.lower())
            if ent >= 3.2 and (has_keyword or len(token) >= 40):
                return _REDACTION_TOKEN
            return token

        line = _HIGH_ENTROPY_TOKEN_RE.sub(repl, line)
        line = _HEX_TOKEN_RE.sub(repl_hex, line)
        return line

    return "\n".join(redact_line(line) for line in text.splitlines())


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact_payment_cards(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if _luhn_valid(digits):
            return _REDACTION_TOKEN
        return raw

    return _CARD_CANDIDATE_RE.sub(repl, text)


def _aba_routing_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) != 9:
        return False
    weights = (3, 7, 1) * 3
    total = sum((ord(d) - 48) * w for d, w in zip(digits, weights, strict=False))
    return total % 10 == 0


def _redact_routing_and_accounts(text: str) -> str:
    routing_hint = re.compile(r"(?i)\b(routing|aba|rtn)\b")
    account_hint = re.compile(r"(?i)\b(account|acct|a\/c)\b")

    def redact_line(line: str) -> str:
        if routing_hint.search(line):
            line = re.sub(r"\b\d{9}\b", lambda m: _REDACTION_TOKEN if _aba_routing_valid(m.group(0)) else m.group(0), line)
        if account_hint.search(line):
            def repl_account(m: re.Match[str]) -> str:
                digits = re.sub(r"\D", "", m.group(0))
                if 8 <= len(digits) <= 24:
                    return _REDACTION_TOKEN
                return m.group(0)

            line = re.sub(r"\b(?:\d[ -]?){8,24}\b", repl_account, line)
        return line

    return "\n".join(redact_line(line) for line in text.splitlines())


def _redact_iban(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        compact = re.sub(r"\s+", "", raw).upper()
        if 15 <= len(compact) <= 34 and re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
            return _REDACTION_TOKEN
        return raw

    return _IBAN_CANDIDATE_RE.sub(repl, text)


def _redact_contextual_person_names(text: str) -> str:
    text = _CONTEXTUAL_PERSON_NAME_RE.sub(lambda m: f"{m.group(1)}{_REDACTION_TOKEN}", text)
    text = _CSV_PERSON_NAME_RE.sub(_REDACTION_TOKEN, text)
    return _LABELED_PERSON_NAME_RE.sub(lambda m: m.group(0).replace(m.group(1), _REDACTION_TOKEN), text)


def _redact_contextual_dates(text: str) -> str:
    def redact_line(line: str) -> str:
        if _SENSITIVE_DATE_CONTEXT_RE.search(line):
            return _DATE_TOKEN_RE.sub(_REDACTION_TOKEN, line)
        return line

    return "\n".join(redact_line(line) for line in text.splitlines())


def _redact_contextual_ip_addresses(text: str) -> str:
    def redact_line(line: str) -> str:
        if _IP_ADDRESS_CONTEXT_RE.search(line):
            return _IPV4_RE.sub(_REDACTION_TOKEN, line)
        return line

    return "\n".join(redact_line(line) for line in text.splitlines())


def _redact_structured_hr_export(text: str, policy_config: Mapping[str, object] | None) -> str:
    pii_enabled = _policy_enabled(policy_config, "redact_pii")
    gov_enabled = _policy_enabled(policy_config, "redact_government_ids")
    hr_enabled = _policy_enabled(policy_config, "redact_hr")

    def repl(m: re.Match[str]) -> str:
        name = _REDACTION_TOKEN if pii_enabled else m.group("name")
        email = _REDACTION_TOKEN if pii_enabled else m.group("email")
        dob = _REDACTION_TOKEN if pii_enabled else m.group("dob")
        gov_id = _REDACTION_TOKEN if gov_enabled else m.group("gov_id")
        salary = _REDACTION_TOKEN if hr_enabled else m.group("salary")
        return (
            f"{m.group('prefix')}{name}{m.group('sep1')}{email}{m.group('sep2')}"
            f"{dob}{m.group('sep3')}{gov_id}{m.group('sep4')}{salary}{m.group('suffix')}"
        )

    return _HR_EXPORT_ROW_FIELDS_RE.sub(repl, text)


def _redact_pii(text: str) -> str:
    text = _redact_contextual_person_names(text)
    text = _redact_contextual_dates(text)
    text = _redact_contextual_ip_addresses(text)
    text = _EMAIL_RE.sub(_REDACTION_TOKEN, text)
    text = _PHONE_RE.sub(_REDACTION_TOKEN, text)
    text = _SSN_RE.sub(_REDACTION_TOKEN, text)
    text = _UK_NIN_RE.sub(_REDACTION_TOKEN, text)
    text = _PASSPORT_RE.sub(_REDACTION_TOKEN, text)
    text = _DRIVERS_LICENSE_RE.sub(_REDACTION_TOKEN, text)
    text = _DOB_RE.sub(_REDACTION_TOKEN, text)
    text = _ADDRESS_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_common_secrets(text: str) -> str:
    return _SECRET_KV_REDACT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTION_TOKEN}", text)


def _redact_domain_sensitive(text: str) -> str:
    patterns = (
        _AADHAAR_RE,
        _INDIA_PAN_RE,
        _US_EIN_RE,
        _GENERIC_GOVERNMENT_ID_RE,
        _KYC_DOCUMENT_RE,
        _CARD_CVV_RE,
        _CARD_EXPIRY_RE,
        _VAT_ID_RE,
        _INDIA_GSTIN_RE,
        _UPI_ID_RE,
        _INVOICE_ID_RE,
        _ORDER_ID_RE,
        _TRACKING_NUMBER_RE,
        _CUSTOMER_ID_RE,
        _MEDICAL_RECORD_RE,
        _INSURANCE_MEMBER_RE,
        _PRESCRIPTION_ID_RE,
        _LEGAL_CASE_RE,
        _LEGAL_PRIVILEGED_RE,
        _BUSINESS_CONFIDENTIAL_RE,
        _EMPLOYEE_ID_RE,
        _PAYROLL_ID_RE,
        _COMPENSATION_RE,
    )
    for pattern in patterns:
        text = pattern.sub(_REDACTION_TOKEN, text)
    return text


def _redact_credentials(text: str) -> str:
    sanitized = text

    sanitized = _PEM_PRIVATE_KEY_BLOCK_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _PEM_PRIVATE_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _DB_CONN_REDACT_RE.sub(_REDACTION_TOKEN, sanitized)

    sanitized = _AWS_ACCESS_KEY_ID_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _AWS_SECRET_ACCESS_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _AWS_SESSION_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _ALIBABA_ACCESS_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _OPENAI_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _ANTHROPIC_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _GITHUB_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _GITHUB_FINE_GRAINED_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _GITLAB_PAT_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _SLACK_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _STRIPE_SECRET_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _STRIPE_RESTRICTED_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _GOOGLE_API_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _GOOGLE_OAUTH_CLIENT_SECRET_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _AZURE_CLIENT_SECRET_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _AZURE_SAS_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _DISCORD_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _TWITCH_OAUTH_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _JWT_LIKE_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _JWT_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _BEARER_TOKEN_RE.sub(f"Authorization: Bearer {_REDACTION_TOKEN}", sanitized)
    sanitized = _SWIFT_CODE_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _CRYPTO_PRIVATE_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    
    sanitized = _TWILIO_ACCOUNT_SID_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _TWILIO_AUTH_TOKEN_RE.sub(f"twilio_auth_token={_REDACTION_TOKEN}", sanitized)
    sanitized = _SENDGRID_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _NPM_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _VAULT_TOKEN_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _NEW_RELIC_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _DIGITALOCEAN_PAT_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _MAILCHIMP_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _SQUARE_KEY_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _AZURE_STORAGE_RE.sub(f"DefaultEndpointsProtocol=https;AccountName={_REDACTION_TOKEN};AccountKey={_REDACTION_TOKEN}", sanitized)
    sanitized = _DATADOG_KEY_RE.sub(f"dd-api-key={_REDACTION_TOKEN}", sanitized)
    sanitized = _REDIS_URI_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _MONGODB_URI_RE.sub(_REDACTION_TOKEN, sanitized)
    sanitized = _PAGERDUTY_KEY_RE.sub(f"pagerduty_key={_REDACTION_TOKEN}", sanitized)
    sanitized = _HEROKU_KEY_RE.sub(f"heroku_api_key={_REDACTION_TOKEN}", sanitized)

    return _redact_common_secrets(sanitized)


def _redact_government_ids(text: str) -> str:
    text = _AADHAAR_RE.sub(_REDACTION_TOKEN, text)
    text = _INDIA_PAN_RE.sub(_REDACTION_TOKEN, text)
    text = _US_EIN_RE.sub(_REDACTION_TOKEN, text)
    text = _GENERIC_GOVERNMENT_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _KYC_DOCUMENT_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_financial(text: str) -> str:
    text = _redact_payment_cards(text)
    text = _redact_routing_and_accounts(text)
    text = _redact_iban(text)
    text = _SWIFT_CODE_RE.sub(_REDACTION_TOKEN, text)
    text = _CARD_CVV_RE.sub(_REDACTION_TOKEN, text)
    text = _CARD_EXPIRY_RE.sub(_REDACTION_TOKEN, text)
    text = _VAT_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _INDIA_GSTIN_RE.sub(_REDACTION_TOKEN, text)
    text = _UPI_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _UK_SORT_CODE_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_commerce(text: str) -> str:
    text = _INVOICE_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _ORDER_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _TRACKING_NUMBER_RE.sub(_REDACTION_TOKEN, text)
    text = _CUSTOMER_ID_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_health(text: str) -> str:
    text = _MEDICAL_RECORD_RE.sub(_REDACTION_TOKEN, text)
    text = _INSURANCE_MEMBER_RE.sub(_REDACTION_TOKEN, text)
    text = _PRESCRIPTION_ID_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_legal(text: str) -> str:
    text = _LEGAL_CASE_RE.sub(_REDACTION_TOKEN, text)
    text = _LEGAL_PRIVILEGED_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_hr(text: str) -> str:
    text = _EMPLOYEE_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _PAYROLL_ID_RE.sub(_REDACTION_TOKEN, text)
    text = _COMPENSATION_RE.sub(_REDACTION_TOKEN, text)
    return text


def _redact_business_confidential(text: str) -> str:
    return _BUSINESS_CONFIDENTIAL_RE.sub(_REDACTION_TOKEN, text)


def _has_issue(issues: list[str] | None, *prefixes_or_names: str) -> bool:
    if issues is None:
        return True
    return any(
        issue == item or issue.startswith(item)
        for issue in issues
        for item in prefixes_or_names
    )


def sanitize_text(
    text: str,
    policy_config: Mapping[str, object] | None = None,
    issues: list[str] | None = None,
) -> str:
    sanitized = text

    if _has_issue(issues, "PII_", "GOVERNMENT_", "HR_"):
        sanitized = _redact_structured_hr_export(sanitized, policy_config)

    if _has_issue(issues, "CREDENTIALS", "DB_CONN_STRING"):
        sanitized = _redact_credentials(sanitized)

    if _has_issue(issues, "SECRET_HIGH_ENTROPY") and _policy_enabled(policy_config, "redact_high_entropy"):
        sanitized = _redact_suspicious_tokens(sanitized)

    if _has_issue(issues, "PII_") and _policy_enabled(policy_config, "redact_pii"):
        sanitized = _redact_pii(sanitized)

    if _has_issue(issues, "GOVERNMENT_") and _policy_enabled(policy_config, "redact_government_ids"):
        sanitized = _redact_government_ids(sanitized)

    if _has_issue(issues, "FINANCIAL_") and _policy_enabled(policy_config, "redact_financial"):
        sanitized = _redact_financial(sanitized)

    if _has_issue(issues, "COMMERCE_") and _policy_enabled(policy_config, "redact_commerce"):
        sanitized = _redact_commerce(sanitized)

    if _has_issue(issues, "HEALTH_") and _policy_enabled(policy_config, "redact_health"):
        sanitized = _redact_health(sanitized)

    if _has_issue(issues, "LEGAL_") and _policy_enabled(policy_config, "redact_legal"):
        sanitized = _redact_legal(sanitized)

    if _has_issue(issues, "HR_") and _policy_enabled(policy_config, "redact_hr"):
        sanitized = _redact_hr(sanitized)

    if _has_issue(issues, "BUSINESS_CONFIDENTIAL") and _policy_enabled(policy_config, "redact_business_confidential"):
        sanitized = _redact_business_confidential(sanitized)

    sanitized = re.sub(r"[ \t]{2,}", " ", sanitized)
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized.strip()


def _policy_enabled(config: Mapping[str, object] | None, key: str) -> bool:
    if config is None:
        return bool(DEFAULT_POLICY_CONFIG[key])
    value = config.get(key, DEFAULT_POLICY_CONFIG[key])
    return bool(value)


def evaluate_policy(
    original_text: str,
    classification: ClassificationResult,
    policy_config: Mapping[str, object] | None = None,
) -> PolicyResult:
    issues = classification.get("issues", [])
    sanitized: str | None = None

    def redacted() -> PolicyResult:
        nonlocal sanitized
        sanitized = sanitized if sanitized is not None else sanitize_text(original_text, policy_config, issues)
        return {"decision": "REDACT", "sanitized_text": sanitized}

    if "CREDENTIALS" in issues or "DB_CONN_STRING" in issues:
        sanitized = sanitize_text(original_text, policy_config, issues)
        if _policy_enabled(policy_config, "block_credentials"):
            return {"decision": "BLOCK", "sanitized_text": sanitized}
        return {"decision": "REDACT", "sanitized_text": sanitized}

    if "SECRET_HIGH_ENTROPY" in issues and _policy_enabled(policy_config, "redact_high_entropy"):
        return redacted()

    pii_issues = {i for i in issues if i.startswith("PII_")}
    if pii_issues and _policy_enabled(policy_config, "redact_pii"):
        return redacted()

    financial_issues = {i for i in issues if i.startswith("FINANCIAL_")}
    if financial_issues and _policy_enabled(policy_config, "redact_financial"):
        return redacted()

    government_issues = {i for i in issues if i.startswith("GOVERNMENT_")}
    if government_issues and _policy_enabled(policy_config, "redact_government_ids"):
        return redacted()

    health_issues = {i for i in issues if i.startswith("HEALTH_")}
    if health_issues and _policy_enabled(policy_config, "redact_health"):
        return redacted()

    legal_issues = {i for i in issues if i.startswith("LEGAL_")}
    if legal_issues and _policy_enabled(policy_config, "redact_legal"):
        return redacted()

    commerce_issues = {i for i in issues if i.startswith("COMMERCE_")}
    if commerce_issues and _policy_enabled(policy_config, "redact_commerce"):
        return redacted()

    hr_issues = {i for i in issues if i.startswith("HR_")}
    if hr_issues and _policy_enabled(policy_config, "redact_hr"):
        return redacted()

    if "BUSINESS_CONFIDENTIAL" in issues and _policy_enabled(policy_config, "redact_business_confidential"):
        return redacted()

    return {"decision": "ALLOW", "sanitized_text": original_text.strip()}
