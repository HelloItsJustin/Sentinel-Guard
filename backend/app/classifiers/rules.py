from __future__ import annotations

import math
import re
from typing import Literal, TypedDict


RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class ClassificationResult(TypedDict):
    issues: list[str]
    risk_level: RiskLevel


# ── PII ─────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(
    r"(?<!\w)(?:"
    r"(?:\+?1[-.\\s]?)?(?:\(?\d{3}\)?[-.\\s]?)\d{3}[-.\\s]?\d{4}"
    r"|(?:\+?91[-.\\s]?)?[6-9]\d{4}[-.\\s]?\d{5}"
    r")(?!\w)"
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_UK_NIN_RE = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b")
_DATE_TOKEN_RE = re.compile(r"\b(?:\d{4}[/\-]\d{1,2}[/\-]\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b")
_PASSPORT_RE = re.compile(
    r"(?i)\bpassport\b.{0,60}\b[A-Z]{1,2}[0-9]{6,9}\b", re.DOTALL
)
_DRIVERS_LICENSE_RE = re.compile(
    r"(?i)\b(?:driver.?s?\s+licen[sc]e|dl\s*(?:no|num|number|#))\b.{0,40}\b[A-Z0-9]{6,15}\b"
)
_DOB_RE = re.compile(
    r"(?i)\b(?:date.of.birth|dob|birth\s+date)\b.{0,50}"
    r"\b(?:\d{4}[/\-]\d{1,2}[/\-]\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b"
)
_ADDRESS_RE = re.compile(
    r"(?i)\b(?:address|shipping\s+to|ship\s+to|billing\s+address|mailing\s+address)\b.{0,35}"
    r"\b\d{1,6}\s+[A-Z0-9][A-Z0-9 .'-]{3,70}\s+"
    r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|parkway|pkwy|circle|cir|terrace|ter)\b"
    r"(?:[^\n]{0,40}\b\d{5}(?:-\d{4})?\b)?"
)
_AADHAAR_RE = re.compile(r"(?i)\b(?:aadhaar|aadhar|uidai)\b.{0,35}\b\d{4}[ -]?\d{4}[ -]?\d{4}\b")
_INDIA_PAN_RE = re.compile(r"(?i)\b(?:pan|permanent\s+account\s+number)\b.{0,35}\b[A-Z]{5}\d{4}[A-Z]\b")
_US_EIN_RE = re.compile(r"(?i)\b(?:ein|federal\s+tax\s+id|taxpayer\s+id|tax\s+id)\b.{0,35}\b\d{2}-\d{7}\b")
_GENERIC_GOVERNMENT_ID_RE = re.compile(
    r"(?i)\b(?:government[_\s-]?id|gov(?:ernment)?[_\s-]?id|national[_\s-]?id|identity[_\s-]?number)\b"
    r"\s*[:=]?\s*\b[A-Z0-9][A-Z0-9 -]{5,35}\b"
)
_KYC_DOCUMENT_RE = re.compile(r"(?i)\bkyc\s+(?:documents?|docs?|records?)\b")
_PERSON_NAME_SOURCE = r"[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){1,3}"
_CONTEXTUAL_PERSON_NAME_RE = re.compile(
    rf"(?m)(^\s*(?:\d+[.)]\s*)?)({_PERSON_NAME_SOURCE})(?=\s*\([^)\n]{{0,180}}"
    r"(?:@|\+?\d|pan\b|upi\b|account\b|dob\b|government))"
)
_CSV_PERSON_NAME_RE = re.compile(
    rf"(?m)^({_PERSON_NAME_SOURCE})(?=\s*,\s*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}\s*,)"
)
_LABELED_PERSON_NAME_RE = re.compile(
    rf"(?i)\b(?:full\s+name|customer\s+name|employee\s+name|patient\s+name|legal\s+name)\b\s*[:=]\s*({_PERSON_NAME_SOURCE})"
)
_SENSITIVE_DATE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:dob|date\s+of\s+birth|birth\s+date|transaction(?:s)?|charged|payment|order|kyc|complaint)\b"
    r"[^\n]{0,120}\b(?:\d{4}[/\-]\d{1,2}[/\-]\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IP_ADDRESS_CONTEXT_RE = re.compile(
    r"(?i)\b(?:ip(?:\s+address)?|login\s+from|unauthorized\s+login|source\s+ip)\b[^\n]{0,80}"
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_HR_EXPORT_HEADER_RE = re.compile(
    r"(?im)^\s*full\s+name\s*,\s*email\s*,\s*dob\s*,\s*government[_\s-]?id\s*,\s*salary\b"
)
_HR_EXPORT_ROW_RE = re.compile(
    rf"(?m)^\s*{_PERSON_NAME_SOURCE}\s*,\s*"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*,\s*"
    r"(?:\d{4}[/\-]\d{1,2}[/\-]\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\s*,\s*"
    r"[A-Z0-9][A-Z0-9 -]{5,35}\s*,\s*(?:[$€£₹]\s*)?\d[\d,]*(?:\.\d{2})?\s*$"
)

# ── Cloud / Vendor credentials ───────────────────────────────────────────────

_AWS_ACCESS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|apikey|secret|token|password|passwd|pwd|"
    r"client[_-]?secret|client[_-]?id|access[_-]?token|refresh[_-]?token|"
    r"aws_secret_access_key|aws_access_key_id|github_token|github_pat|"
    r"openai_api_key|anthropic_api_key|stripe_secret_key|"
    r"database_url|redis_url|jwt[_\s-]?signing[_\s-]?secret|authorization"
    r")\b\s*[:=]\s*(?:\"([^\"]{6,})\"|'([^']{6,})'|([^\s;]{6,}))"
)
_SAFE_REDACTED_VALUE_RE = re.compile(
    r"(?i)^\s*(?:"
    r"\[+\s*(?:redacted|masked|removed|hidden|sanitized)\s*\]+|"
    r"<+\s*(?:redacted|masked|removed|hidden|sanitized)\s*>+|"
    r"\{\{\s*(?:redacted|masked|removed|hidden|sanitized)\s*\}\}|"
    r"(?:redacted|masked|removed|hidden|sanitized|xxxxx+|dummy|placeholder|null|none|n/a)"
    r")\s*$"
)

_BEARER_TOKEN_RE = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._\-]{10,})")
_DB_CONN_RE = re.compile(r"(?i)\b(postgres(?:ql)?://|mysql://|mongodb(?:\+srv)?://|jdbc:|oracle://|sqlserver://|mariadb://|redis://)\S+")

# OpenAI / Anthropic
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")
_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9-]{10,}\b")

# GitHub
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")
_GITHUB_FINE_GRAINED_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")

# GitLab
_GITLAB_PAT_RE = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")

# Slack
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")

# Stripe
_STRIPE_SECRET_KEY_RE = re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,64}\b")
_STRIPE_RESTRICTED_KEY_RE = re.compile(r"\brk_(?:live|test)_[0-9A-Za-z]{16,64}\b")

# Google
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_GOOGLE_OAUTH_CLIENT_SECRET_RE = re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b")

# JWT / PEM
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_PEM_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_@+=/\-.]{3,}){2,}\b")

# Twilio
_TWILIO_ACCOUNT_SID_RE = re.compile(r"\bAC[0-9a-f]{32}\b")
_TWILIO_AUTH_TOKEN_RE = re.compile(r"(?i)\btwilio[_-]?auth[_-]?token\s*[=:]\s*[a-f0-9]{32}\b")
# AWS secret / session tokens
_AWS_SECRET_ACCESS_KEY_RE = re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key|aws(?:_|\s+)secret(?:_|\s+)key)\s*[:=]\s*[A-Za-z0-9/+=]{40}\b")
_AWS_SESSION_TOKEN_RE = re.compile(r"(?i)\b(?:aws_session_token|aws_security_token)\s*[:=]\s*[A-Za-z0-9/+=]{16,}\b")

# Alibaba Cloud
_ALIBABA_ACCESS_KEY_RE = re.compile(r"\bLTAI[0-9A-Za-z]{24}\b")

# Azure secrets
_AZURE_CLIENT_SECRET_RE = re.compile(r"(?i)\b(?:azure[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*[A-Za-z0-9_\-]{20,}\b")
_AZURE_SAS_TOKEN_RE = re.compile(
    r"(?i)\bsv=[^&]{2,}&ss=[^&]+&srt=[^&]+&sp=[^&]+&se=[^&]+&st=[^&]+&spr=[^&]+&sig=[A-Za-z0-9%_\-]{20,}\b"
)

# Discord
_DISCORD_TOKEN_RE = re.compile(r"\b(?:mfa\.[A-Za-z0-9_\-]{84}|[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b")

# Twitch
_TWITCH_OAUTH_RE = re.compile(r"(?i)\boauth:[A-Za-z0-9]{30,56}\b")

# Crypto / financial identifiers
_CRYPTO_PRIVATE_KEY_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
_SWIFT_CODE_RE = re.compile(r"(?i)\b(?:swift|bic)\b[^A-Za-z0-9]{0,10}\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
# SendGrid
_SENDGRID_KEY_RE = re.compile(r"\bSG\.[A-Za-z0-9._-]{22,}\.[A-Za-z0-9._-]{43,}\b")

# npm
_NPM_TOKEN_RE = re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")

# HashiCorp Vault
_VAULT_TOKEN_RE = re.compile(r"\bhvs\.[A-Za-z0-9._-]{20,}\b")

# New Relic
_NEW_RELIC_KEY_RE = re.compile(r"\bNRAK-[A-Z0-9]{27}\b")

# DigitalOcean
_DIGITALOCEAN_PAT_RE = re.compile(r"\bdop_v1_[a-f0-9]{64}\b")

# Mailchimp
_MAILCHIMP_KEY_RE = re.compile(r"\b[a-f0-9]{32}-us\d{1,2}\b")

# Square
_SQUARE_KEY_RE = re.compile(r"\bEAAA[A-Za-z0-9]{60,}\b")

# Azure Storage
_AZURE_STORAGE_RE = re.compile(
    r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}"
)

# Datadog
_DATADOG_KEY_RE = re.compile(
    r"(?i)(?:dd[_-]api[_-]key|datadog[_-]api[_-]key|datadog[_-]app[_-]key)\s*[=:]\s*[a-f0-9]{32,40}"
)

# Redis with credentials
_REDIS_URI_RE = re.compile(r"(?i)\brediss?://[^:@\s]+:[^@\s]+@\S+")

# MongoDB with credentials (more specific than DB_CONN_RE)
_MONGODB_URI_RE = re.compile(r"(?i)\bmongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@\S+")

# PagerDuty
_PAGERDUTY_KEY_RE = re.compile(
    r"(?i)pagerduty[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*[A-Za-z0-9+/=_-]{16,}"
)

# Heroku
_HEROKU_KEY_RE = re.compile(
    r"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

# ── Entropy heuristics ───────────────────────────────────────────────────────

_HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{20,200}\b")
_HEX_TOKEN_RE = re.compile(r"\b[a-f0-9]{32,128}\b", re.IGNORECASE)

# ── Financial ────────────────────────────────────────────────────────────────

_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,32}\b")
_UK_SORT_CODE_RE = re.compile(r"(?i)\b(?:sort[_\s-]?code|sc)\b.{0,30}\b\d{2}-\d{2}-\d{2}\b")
_CARD_CVV_RE = re.compile(r"(?i)\b(?:cvv|cvc|card\s+security\s+code|verification\s+code)\b.{0,25}\b\d{3,4}\b")
_CARD_EXPIRY_RE = re.compile(r"(?i)\b(?:exp(?:iry|iration)?|valid\s+thru)\b.{0,25}\b(?:0[1-9]|1[0-2])[/\-](?:\d{2}|\d{4})\b")
_VAT_ID_RE = re.compile(r"(?i)\b(?:vat(?:\s+id|\s+number)?|vatin)\b.{0,35}\b[A-Z]{2}[A-Z0-9]{8,12}\b")
_INDIA_GSTIN_RE = re.compile(r"(?i)\b(?:gstin|gst\s+number)\b.{0,35}\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b")
_UPI_ID_RE = re.compile(r"(?i)\b(?:upi\s*id|upi|vpa)\b\s*[:#-]?\s*[a-z0-9._-]{2,256}@[a-z][a-z0-9._-]{2,64}\b")

# Commerce / customer operations
_ID_QUALIFIER = r"(?:(?:id|no|num|number)\b|#)"
_INVOICE_ID_RE = re.compile(rf"(?i)\b(?:invoice|inv)\b\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{5,24}}\b")
_ORDER_ID_RE = re.compile(rf"(?i)\b(?:order|purchase\s+order|po)\b\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{5,24}}\b")
_TRACKING_NUMBER_RE = re.compile(rf"(?i)\b(?:tracking|shipment|parcel)\b\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9]{{10,34}}\b")
_CUSTOMER_ID_RE = re.compile(rf"(?i)\b(?:customer|client|account|subscriber)\b\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{5,24}}\b")

# Health / insurance
_MEDICAL_RECORD_RE = re.compile(r"(?i)\b(?:medical\s+record|mrn|patient\s+id|patient\s+number)\b.{0,35}\b[A-Z0-9][A-Z0-9_-]{5,24}\b")
_INSURANCE_MEMBER_RE = re.compile(r"(?i)\b(?:insurance\s+(?:member|policy)|member\s+id|policy\s+number)\b.{0,35}\b[A-Z0-9][A-Z0-9_-]{5,24}\b")
_PRESCRIPTION_ID_RE = re.compile(rf"(?i)\b(?:rx|prescription)\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{5,24}}\b")

# Legal / confidential business / HR
_LEGAL_CASE_RE = re.compile(rf"(?i)\b(?:case|docket|matter)\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_./-]{{5,30}}\b")
_LEGAL_PRIVILEGED_RE = re.compile(r"(?i)\b(?:attorney-client\s+privileged|privileged\s+and\s+confidential|legal\s+advice\s+confidential|attorney\s+work\s+product)\b")
_BUSINESS_CONFIDENTIAL_RE = re.compile(
    r"(?i)\b(?:nda|non[-\s]?disclosure|confidential\s+(?:roadmap|pricing|forecast|revenue|margin|m&a|merger|acquisition|bid|proposal|contract)|"
    r"proprietary\s+(?:pricing|algorithm|model|formula|strategy|roadmap))\b"
)
_EMPLOYEE_ID_RE = re.compile(rf"(?i)\b(?:employee|staff|worker)\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{4,20}}\b")
_PAYROLL_ID_RE = re.compile(rf"(?i)\b(?:payroll|salary)\s*{_ID_QUALIFIER}\s*[:#-]?\s*[A-Z0-9][A-Z0-9_-]{{4,20}}\b")
_COMPENSATION_RE = re.compile(r"(?i)\b(?:salary|compensation|bonus|equity\s+grant)\b.{0,40}(?:[$\u20ac\u00a3\u20b9]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*(?:\.\d{2})?\s?(?:usd|eur|gbp|inr)\b)")


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


def _find_suspicious_tokens(text: str) -> bool:
    keyword_re = re.compile(r"(?i)\b(key|token|secret|password|passwd|pwd|bearer|authorization)\b")
    for line in text.splitlines():
        has_keyword = bool(keyword_re.search(line))
        for m in _HIGH_ENTROPY_TOKEN_RE.finditer(line):
            token = m.group(0)
            if token.count("_") + token.count("-") > 10:
                continue
            if token.isalpha():
                continue
            ent = _shannon_entropy(token)
            if ent >= 3.9 and (has_keyword or len(token) >= 28):
                return True
        for m in _HEX_TOKEN_RE.finditer(line):
            token = m.group(0)
            ent = _shannon_entropy(token.lower())
            if ent >= 3.2 and (has_keyword or len(token) >= 40):
                return True
    return False


def _is_safe_redacted_value(value: str) -> bool:
    normalized = value.strip().strip("\"'").strip()
    return bool(_SAFE_REDACTED_VALUE_RE.fullmatch(normalized))


def _find_key_value_secrets(text: str) -> bool:
    for m in _KEY_VALUE_SECRET_RE.finditer(text):
        value = next((group for group in m.groups()[1:] if group is not None), "")
        if not _is_safe_redacted_value(value):
            return True
    return False


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


def _find_payment_cards(text: str) -> bool:
    for m in _CARD_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if _luhn_valid(digits):
            return True
    return False


def _aba_routing_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) != 9:
        return False
    weights = (3, 7, 1) * 3
    total = sum((ord(d) - 48) * w for d, w in zip(digits, weights, strict=False))
    return total % 10 == 0


def _find_routing_numbers(text: str) -> bool:
    routing_hint = re.compile(r"(?i)\b(routing|aba|rtn)\b")
    for line in text.splitlines():
        if not routing_hint.search(line):
            continue
        for m in re.finditer(r"\b\d{9}\b", line):
            if _aba_routing_valid(m.group(0)):
                return True
    return False


def _find_account_numbers(text: str) -> bool:
    account_hint = re.compile(r"(?i)\b(account|acct|a\/c)\b")
    for line in text.splitlines():
        if not account_hint.search(line):
            continue
        for m in re.finditer(r"\b(?:\d[ -]?){8,24}\b", line):
            digits = re.sub(r"\D", "", m.group(0))
            if 8 <= len(digits) <= 24:
                return True
    return False


def _find_iban(text: str) -> bool:
    for m in _IBAN_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        compact = re.sub(r"\s+", "", raw).upper()
        if 15 <= len(compact) <= 34 and re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
            return True
    return False


def classify_text(text: str) -> ClassificationResult:
    issues: set[str] = set()
    found_credentials = False
    found_suspicious_secret = False
    pii_scan_text = _DB_CONN_RE.sub(" ", text)
    pii_scan_text = _MONGODB_URI_RE.sub(" ", pii_scan_text)
    pii_scan_text = _REDIS_URI_RE.sub(" ", pii_scan_text)

    # ── PII ──────────────────────────────────────────────
    if _EMAIL_RE.search(pii_scan_text):
        issues.add("PII_EMAIL")

    if _PHONE_RE.search(text):
        issues.add("PII_PHONE")

    if _SSN_RE.search(text):
        issues.add("PII_SSN")

    if _UK_NIN_RE.search(text):
        issues.add("PII_UK_NIN")

    if _PASSPORT_RE.search(text):
        issues.add("PII_PASSPORT")

    if _DRIVERS_LICENSE_RE.search(text):
        issues.add("PII_DRIVERS_LICENSE")

    if _DOB_RE.search(text):
        issues.add("PII_DOB")

    if _SENSITIVE_DATE_CONTEXT_RE.search(text):
        issues.add("PII_DATE")

    if _ADDRESS_RE.search(text):
        issues.add("PII_ADDRESS")

    if (
        _CONTEXTUAL_PERSON_NAME_RE.search(text)
        or _CSV_PERSON_NAME_RE.search(text)
        or _LABELED_PERSON_NAME_RE.search(text)
    ):
        issues.add("PII_NAME")

    if _IP_ADDRESS_CONTEXT_RE.search(text):
        issues.add("PII_IP_ADDRESS")

    if _AADHAAR_RE.search(text):
        issues.add("GOVERNMENT_AADHAAR")

    if _INDIA_PAN_RE.search(text):
        issues.add("GOVERNMENT_INDIA_PAN")

    if _US_EIN_RE.search(text):
        issues.add("GOVERNMENT_US_EIN")

    if _GENERIC_GOVERNMENT_ID_RE.search(text):
        issues.add("GOVERNMENT_GENERIC_ID")

    if _KYC_DOCUMENT_RE.search(text):
        issues.add("GOVERNMENT_KYC_DOCUMENT")

    if _HR_EXPORT_HEADER_RE.search(text) and _HR_EXPORT_ROW_RE.search(text):
        issues.update({"PII_NAME", "PII_DOB", "GOVERNMENT_GENERIC_ID", "HR_COMPENSATION"})

    # ── Database connections ──────────────────────────────
    if _MONGODB_URI_RE.search(text):
        issues.add("CREDENTIALS_MONGODB_URI")
        found_credentials = True
    elif _DB_CONN_RE.search(text):
        issues.add("DB_CONN_STRING")

    if _REDIS_URI_RE.search(text):
        issues.add("CREDENTIALS_REDIS_URI")
        found_credentials = True

    # ── Cloud credentials ─────────────────────────────────
    if _AWS_ACCESS_KEY_ID_RE.search(text):
        issues.add("CREDENTIALS_AWS_ACCESS_KEY_ID")
        found_credentials = True

    if _OPENAI_KEY_RE.search(text):
        issues.add("CREDENTIALS_OPENAI_KEY")
        found_credentials = True

    if _ANTHROPIC_KEY_RE.search(text):
        issues.add("CREDENTIALS_ANTHROPIC_KEY")
        found_credentials = True

    if _GITHUB_TOKEN_RE.search(text) or _GITHUB_FINE_GRAINED_RE.search(text):
        issues.add("CREDENTIALS_GITHUB_TOKEN")
        found_credentials = True

    if _GITLAB_PAT_RE.search(text):
        issues.add("CREDENTIALS_GITLAB_PAT")
        found_credentials = True

    if _SLACK_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_SLACK_TOKEN")
        found_credentials = True

    if _STRIPE_SECRET_KEY_RE.search(text) or _STRIPE_RESTRICTED_KEY_RE.search(text):
        issues.add("CREDENTIALS_STRIPE_KEY")
        found_credentials = True

    if _GOOGLE_API_KEY_RE.search(text):
        issues.add("CREDENTIALS_GOOGLE_API_KEY")
        found_credentials = True

    if _GOOGLE_OAUTH_CLIENT_SECRET_RE.search(text):
        issues.add("CREDENTIALS_GOOGLE_OAUTH_SECRET")
        found_credentials = True

    if _JWT_RE.search(text) or _JWT_LIKE_RE.search(text) or _BEARER_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_JWT_TOKEN")
        found_credentials = True

    if _PEM_PRIVATE_KEY_RE.search(text) or _PEM_PRIVATE_KEY_BLOCK_RE.search(text):
        issues.add("CREDENTIALS_PRIVATE_KEY")
        found_credentials = True

    if _find_key_value_secrets(text):
        issues.add("CREDENTIALS_KEY_VALUE")
        found_credentials = True

    if _TWILIO_ACCOUNT_SID_RE.search(text):
        issues.add("CREDENTIALS_TWILIO_SID")
        found_credentials = True

    if _TWILIO_AUTH_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_TWILIO_TOKEN")
        found_credentials = True

    if _AWS_SECRET_ACCESS_KEY_RE.search(text):
        issues.add("CREDENTIALS_AWS_SECRET_ACCESS_KEY")
        found_credentials = True

    if _AWS_SESSION_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_AWS_SESSION_TOKEN")
        found_credentials = True

    if _ALIBABA_ACCESS_KEY_RE.search(text):
        issues.add("CREDENTIALS_ALIBABA_KEY")
        found_credentials = True

    if _AZURE_CLIENT_SECRET_RE.search(text):
        issues.add("CREDENTIALS_AZURE_CLIENT_SECRET")
        found_credentials = True

    if _AZURE_SAS_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_AZURE_SAS_TOKEN")
        found_credentials = True

    if _DISCORD_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_DISCORD_TOKEN")
        found_credentials = True

    if _TWITCH_OAUTH_RE.search(text):
        issues.add("CREDENTIALS_TWITCH_TOKEN")
        found_credentials = True

    if _SENDGRID_KEY_RE.search(text):
        issues.add("CREDENTIALS_SENDGRID_KEY")
        found_credentials = True

    if _NPM_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_NPM_TOKEN")
        found_credentials = True

    if _VAULT_TOKEN_RE.search(text):
        issues.add("CREDENTIALS_VAULT_TOKEN")
        found_credentials = True

    if _NEW_RELIC_KEY_RE.search(text):
        issues.add("CREDENTIALS_NEW_RELIC_KEY")
        found_credentials = True

    if _DIGITALOCEAN_PAT_RE.search(text):
        issues.add("CREDENTIALS_DIGITAL_OCEAN_PAT")
        found_credentials = True

    if _MAILCHIMP_KEY_RE.search(text):
        issues.add("CREDENTIALS_MAILCHIMP_KEY")
        found_credentials = True

    if _SQUARE_KEY_RE.search(text):
        issues.add("CREDENTIALS_SQUARE_KEY")
        found_credentials = True

    if _AZURE_STORAGE_RE.search(text):
        issues.add("CREDENTIALS_AZURE_STORAGE")
        found_credentials = True

    if _DATADOG_KEY_RE.search(text):
        issues.add("CREDENTIALS_DATADOG_KEY")
        found_credentials = True

    if _PAGERDUTY_KEY_RE.search(text):
        issues.add("CREDENTIALS_PAGERDUTY_KEY")
        found_credentials = True

    if _HEROKU_KEY_RE.search(text):
        issues.add("CREDENTIALS_HEROKU_KEY")
        found_credentials = True

    # ── Entropy heuristic ─────────────────────────────────
    if _find_suspicious_tokens(text):
        issues.add("SECRET_HIGH_ENTROPY")
        found_suspicious_secret = True

    # ── Financial ─────────────────────────────────────────
    if _find_payment_cards(text):
        issues.add("FINANCIAL_CARD")

    if _find_routing_numbers(text):
        issues.add("FINANCIAL_ROUTING_NUMBER")

    if _find_account_numbers(text):
        issues.add("FINANCIAL_ACCOUNT_NUMBER")

    if _find_iban(text):
        issues.add("FINANCIAL_IBAN")

    if _UK_SORT_CODE_RE.search(text):
        issues.add("FINANCIAL_UK_SORT_CODE")

    if _SWIFT_CODE_RE.search(text):
        issues.add("FINANCIAL_SWIFT_CODE")

    if _UPI_ID_RE.search(text):
        issues.add("FINANCIAL_UPI_ID")

    if _CARD_CVV_RE.search(text):
        issues.add("FINANCIAL_CARD_SECURITY_CODE")

    if _CARD_EXPIRY_RE.search(text):
        issues.add("FINANCIAL_CARD_EXPIRY")

    if _VAT_ID_RE.search(text):
        issues.add("FINANCIAL_VAT_ID")

    if _INDIA_GSTIN_RE.search(text):
        issues.add("FINANCIAL_GSTIN")

    if _CRYPTO_PRIVATE_KEY_RE.search(text):
        issues.add("CREDENTIALS_CRYPTO_PRIVATE_KEY")
        found_credentials = True

    # Commerce / customer operations
    if _INVOICE_ID_RE.search(text):
        issues.add("COMMERCE_INVOICE_ID")

    if _ORDER_ID_RE.search(text):
        issues.add("COMMERCE_ORDER_ID")

    if _TRACKING_NUMBER_RE.search(text):
        issues.add("COMMERCE_TRACKING_NUMBER")

    if _CUSTOMER_ID_RE.search(text):
        issues.add("COMMERCE_CUSTOMER_ID")

    # Health / insurance
    if _MEDICAL_RECORD_RE.search(text):
        issues.add("HEALTH_MEDICAL_RECORD")

    if _INSURANCE_MEMBER_RE.search(text):
        issues.add("HEALTH_INSURANCE_MEMBER_ID")

    if _PRESCRIPTION_ID_RE.search(text):
        issues.add("HEALTH_PRESCRIPTION_ID")

    # Legal / confidential / HR
    if _LEGAL_CASE_RE.search(text):
        issues.add("LEGAL_CASE_NUMBER")

    if _LEGAL_PRIVILEGED_RE.search(text):
        issues.add("LEGAL_PRIVILEGED_CONTENT")

    if _BUSINESS_CONFIDENTIAL_RE.search(text):
        issues.add("BUSINESS_CONFIDENTIAL")

    if _EMPLOYEE_ID_RE.search(text):
        issues.add("HR_EMPLOYEE_ID")

    if _PAYROLL_ID_RE.search(text):
        issues.add("HR_PAYROLL_ID")

    if _COMPENSATION_RE.search(text):
        issues.add("HR_COMPENSATION")

    # ── Umbrella tag ──────────────────────────────────────
    if found_credentials:
        issues.add("CREDENTIALS")

    # ── Risk level ────────────────────────────────────────
    risk_level: RiskLevel
    if "CREDENTIALS" in issues or "DB_CONN_STRING" in issues:
        risk_level = "HIGH"
    elif any(i.startswith("PII_") for i in issues):
        risk_level = "HIGH"
    elif any(i.startswith("FINANCIAL_") for i in issues):
        risk_level = "HIGH"
    elif any(i.startswith("GOVERNMENT_") for i in issues):
        risk_level = "HIGH"
    elif any(i.startswith("HEALTH_") for i in issues):
        risk_level = "HIGH"
    elif any(i.startswith("LEGAL_") for i in issues):
        risk_level = "HIGH"
    elif "BUSINESS_CONFIDENTIAL" in issues:
        risk_level = "MEDIUM"
    elif any(i.startswith("HR_") for i in issues):
        risk_level = "MEDIUM"
    elif any(i.startswith("COMMERCE_") for i in issues):
        risk_level = "MEDIUM"
    elif found_suspicious_secret:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {"issues": sorted(issues), "risk_level": risk_level}
