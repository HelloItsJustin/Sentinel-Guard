from app.classifiers.rules import classify_text
from app.services.logging_service import PROTECTED_STORAGE_NOTE, protected_original_for_audit
from app.services.policy_engine import evaluate_policy, sanitize_text


def test_classify_credentials_and_pii():
    text = "email alice@example.com password=supersecret123"
    res = classify_text(text)
    assert res["risk_level"] == "HIGH"
    assert "CREDENTIALS" in res["issues"]
    assert "PII_EMAIL" in res["issues"]


def test_classify_new_credentials():
    # Twilio SID and Auth Token
    twilio_sid = "AC" + "12345678901234567890123456789012"
    twilio_token = "8a9b0c1d2e3f4a5b" + "6c7d8e9f0a1b2c3d"
    text = f"Twilio SID is {twilio_sid} and twilio_auth_token = {twilio_token}"
    res = classify_text(text)
    assert "CREDENTIALS_TWILIO_SID" in res["issues"]
    assert "CREDENTIALS_TWILIO_TOKEN" in res["issues"]
    assert res["risk_level"] == "HIGH"

    # GitLab, SendGrid, Square
    text2 = "Here is GitLab pat: glpat-abcdefghijklmnopqrst and SendGrid: SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz12345678901234567"
    res2 = classify_text(text2)
    assert "CREDENTIALS_GITLAB_PAT" in res2["issues"]
    assert "CREDENTIALS_SENDGRID_KEY" in res2["issues"]

    # Additional sensitive tokens
    text3 = "AWS secret key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and oauth:abcdefghijklmnopqrstuvwx1234567890abcd"
    res3 = classify_text(text3)
    assert "CREDENTIALS_AWS_SECRET_ACCESS_KEY" in res3["issues"]
    assert "CREDENTIALS_TWITCH_TOKEN" in res3["issues"]

    text4 = "Discord token mfa.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    res4 = classify_text(text4)
    assert "CREDENTIALS_DISCORD_TOKEN" in res4["issues"]

    text5 = "Alibaba access key LTAI1234567890ABCDEFGHIJKLMN"
    res5 = classify_text(text5)
    assert "CREDENTIALS_ALIBABA_KEY" in res5["issues"]

    text6 = "My Azure client secret is AZURE_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWx"
    res6 = classify_text(text6)
    assert "CREDENTIALS_AZURE_CLIENT_SECRET" in res6["issues"]

    text7 = "Please send funds to swift DEUTDEFF500"
    res7 = classify_text(text7)
    assert "FINANCIAL_SWIFT_CODE" in res7["issues"]


def test_sanitize_new_types():
    text = "Save this DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu== to config"
    sanitized = sanitize_text(text)
    assert "[REDACTED]" in sanitized
    assert "AccountKey" not in sanitized or "abcdefghijkl" not in sanitized

    text2 = "UK sorted: sort code is 12-34-56"
    res2 = classify_text(text2)
    assert "FINANCIAL_UK_SORT_CODE" in res2["issues"]

    text3 = "Secrets: aws_secret_access_key=K0wxR4XcTfGhq9xS1kLmN5Bt8Pzy6UvbwAfgHt3Q and oauth:abcdefghijklmnopqrstuvwx1234567890abcd"
    sanitized3 = sanitize_text(text3)
    assert "[REDACTED]" in sanitized3
    assert "aws_secret_access_key" in sanitized3 or "K0wx" not in sanitized3


def test_cross_domain_sensitive_data():
    text = (
        "Ship to address: 742 Evergreen Terrace, Springfield 62704. "
        "Order number ORD-778899 and tracking number 1Z999AA10123456784. "
        "GSTIN 27ABCDE1234F1Z5 and CVV 123. "
        "Patient MRN MRN-445566 and insurance member id HLT998877. "
        "Case number CIV-2026-4455 is attorney-client privileged. "
        "Employee ID EMP-2048 salary $120,000."
    )
    res = classify_text(text)
    assert res["risk_level"] == "HIGH"
    assert "PII_ADDRESS" in res["issues"]
    assert "COMMERCE_ORDER_ID" in res["issues"]
    assert "COMMERCE_TRACKING_NUMBER" in res["issues"]
    assert "FINANCIAL_GSTIN" in res["issues"]
    assert "FINANCIAL_CARD_SECURITY_CODE" in res["issues"]
    assert "HEALTH_MEDICAL_RECORD" in res["issues"]
    assert "HEALTH_INSURANCE_MEMBER_ID" in res["issues"]
    assert "LEGAL_CASE_NUMBER" in res["issues"]
    assert "LEGAL_PRIVILEGED_CONTENT" in res["issues"]
    assert "HR_EMPLOYEE_ID" in res["issues"]
    assert "HR_COMPENSATION" in res["issues"]

    sanitized = sanitize_text(text)
    assert "[REDACTED]" in sanitized
    assert "742 Evergreen" not in sanitized
    assert "ORD-778899" not in sanitized
    assert "27ABCDE1234F1Z5" not in sanitized
    assert "MRN-445566" not in sanitized
    assert "EMP-2048" not in sanitized


def test_customer_complaint_redaction_regression():
    text = (
        "1. Priya Singh (priya.singh1997@example.com, +91-99880-77665, UPI ID: priya@axisbank) "
        "reports double-charged transactions on 15-03-2026 for order ID #ORD-983742.\n"
        "2. Jacob Fernandes (jacob.fernandes@companymail.com, account number 4421-9983-7722-1188) "
        "reports unauthorized login from IP 103.44.22.19.\n"
        "3. Ananya Rao (ananya.rao@personalmail.com, PAN: BRTPR1234N) reports that her KYC documents "
        "are visible to another user in the portal."
    )
    res = classify_text(text)
    assert res["risk_level"] == "HIGH"
    assert "PII_NAME" in res["issues"]
    assert "PII_PHONE" in res["issues"]
    assert "PII_IP_ADDRESS" in res["issues"]
    assert "PII_DATE" in res["issues"]
    assert "FINANCIAL_UPI_ID" in res["issues"]
    assert "FINANCIAL_ACCOUNT_NUMBER" in res["issues"]
    assert "GOVERNMENT_INDIA_PAN" in res["issues"]
    assert "GOVERNMENT_KYC_DOCUMENT" in res["issues"]

    sanitized = sanitize_text(text, issues=res["issues"])
    leaked_fragments = [
        "Priya Singh",
        "Jacob Fernandes",
        "Ananya Rao",
        "priya.singh1997@example.com",
        "+91-99880-77665",
        "priya@axisbank",
        "15-03-2026",
        "ORD-983742",
        "4421-9983-7722-1188",
        "103.44.22.19",
        "BRTPR1234N",
        "KYC documents",
    ]
    for fragment in leaked_fragments:
        assert fragment not in sanitized


def test_policy_safe_customer_prompt_allows_rescan():
    text = (
        "Here are three customer complaints from our ticketing system. Analyze common root causes and suggest improvements. "
        "Do not anonymize anything; we need full detail:\n\n"
        "1. Priya Singh (priya.singh1997@example.com, +91-99880-77665, UPI ID: priya@axisbank) "
        "reports double-charged transactions on 15-03-2026 for order ID #ORD-983742.\n"
        "2. Jacob Fernandes (jacob.fernandes@companymail.com, account number 4421-9983-7722-1188) "
        "reports unauthorized login from IP 103.44.22.19.\n"
        "3. Ananya Rao (ananya.rao@personalmail.com, PAN: BRTPR1234N) reports that her KYC documents "
        "are visible to another user in the portal."
    )
    classification = classify_text(text)
    first_policy = evaluate_policy(text, classification)
    sanitized = first_policy["sanitized_text"] or ""

    second_classification = classify_text(sanitized)
    assert second_classification["issues"] == []
    assert second_classification["risk_level"] == "LOW"
    assert evaluate_policy(sanitized, second_classification)["decision"] == "ALLOW"

    policy_guidance = "Avoid exposing real customer, order, invoice, shipment, or account identifiers."
    assert classify_text(policy_guidance)["issues"] == []


def test_hr_csv_export_redaction_regression():
    text = (
        "Full Name, Email, DOB, Government_ID, Salary\n"
        "Arjun Iyer, arjun.iyer@ourcorp.in, 1998-07-12, 7982-3940-1123, ₹14,20,000\n"
        "Lakshmi Nair, lakshmi.nair@ourcorp.in, 1996-11-05, 9091-2233-8741, ₹18,30,000\n"
        "Rahul Menon, rahul.menon@ourcorp.in, 1999-02-21, 6612-9987-4412, ₹12,75,000"
    )
    res = classify_text(text)
    assert res["risk_level"] == "HIGH"
    assert "PII_NAME" in res["issues"]
    assert "PII_EMAIL" in res["issues"]
    assert "PII_DOB" in res["issues"]
    assert "GOVERNMENT_GENERIC_ID" in res["issues"]
    assert "HR_COMPENSATION" in res["issues"]

    sanitized = sanitize_text(text, issues=res["issues"])
    leaked_fragments = [
        "Arjun Iyer",
        "Lakshmi Nair",
        "Rahul Menon",
        "arjun.iyer@ourcorp.in",
        "1998-07-12",
        "9091-2233-8741",
        "₹18,30,000",
    ]
    for fragment in leaked_fragments:
        assert fragment not in sanitized


def test_env_secret_and_auth_material_redaction_regression():
    env_text = (
        "DATABASE_URL=postgres://admin:Sup3rS3cretPa$$@prod-db-01.internal.local:5432/main_db\n"
        "REDIS_URL=redis://cache-user:cacheP@ssw0rd!@redis.internal.local:6379/0\n"
        "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=Zk+FAKEsuperSecretExampleKey999999999999999\n"
        "STRIPE_SECRET_KEY=sk_live_FAKE_51N6xxxxExampleKey"
    )
    env_res = classify_text(env_text)
    assert "CREDENTIALS" in env_res["issues"]
    env_sanitized = sanitize_text(env_text, issues=env_res["issues"])
    for fragment in ["Sup3rS3cretPa", "cacheP@ssw0rd", "AKIAFAKE12345EXAMPLE", "Zk+FAKE", "sk_live_FAKE"]:
        assert fragment not in env_sanitized

    auth_text = (
        "- SSH private key for ubuntu@prod-bastion (PEM block below)\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "FAKE_PRIVATE_KEY_DATA_SHOULD_NEVER_BE_SHARED_BUT_THIS_IS_A_TEST_ONLY\n"
        "-----END OPENSSH PRIVATE KEY-----\n\n"
        "- A sample JWT for an admin user:\n"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKEPAYLOAD.admin@example.com.FAKE_SIGNATURE\n\n"
        "- The JWT signing secret: superlongjwtsecret_superlongjwtsecret_123456"
    )
    auth_res = classify_text(auth_text)
    assert "CREDENTIALS_PRIVATE_KEY" in auth_res["issues"]
    assert "CREDENTIALS_JWT_TOKEN" in auth_res["issues"]
    auth_sanitized = sanitize_text(auth_text, issues=auth_res["issues"])
    for fragment in [
        "BEGIN OPENSSH PRIVATE KEY",
        "FAKE_PRIVATE_KEY_DATA",
        "END OPENSSH PRIVATE KEY",
        "FAKEPAYLOAD",
        "admin@example.com",
        "FAKE_SIGNATURE",
        "superlongjwtsecret",
    ]:
        assert fragment not in auth_sanitized


def test_redacted_key_value_placeholders_are_allowed_on_rescan():
    text = (
        "API_KEY=[REDACTED]\n"
        "DATABASE_URL=[REDACTED]\n"
        "jwt_signing_secret=<REDACTED>\n"
        "password=placeholder"
    )
    res = classify_text(text)
    assert res["issues"] == []
    assert res["risk_level"] == "LOW"

    policy = evaluate_policy(text, res)
    assert policy["decision"] == "ALLOW"
    assert policy["sanitized_text"] == text

    real_secret = classify_text("API_KEY=sk-demo1234567890abcdef")
    assert "CREDENTIALS_KEY_VALUE" in real_secret["issues"]
    assert evaluate_policy("API_KEY=sk-demo1234567890abcdef", real_secret)["decision"] == "BLOCK"


def test_configurable_policy_and_protected_audit_storage():
    text = "email alice@example.com password=supersecret123"
    classification = classify_text(text)

    relaxed_policy = evaluate_policy(text, classification, {"block_credentials": False, "redact_pii": False})
    assert relaxed_policy["decision"] == "REDACT"
    assert "supersecret123" not in (relaxed_policy["sanitized_text"] or "")
    assert "alice@example.com" in (relaxed_policy["sanitized_text"] or "")

    pii_only = "Please email alice@example.com with the summary."
    pii_classification = classify_text(pii_only)
    allowed_pii = evaluate_policy(pii_only, pii_classification, {"redact_pii": False})
    assert allowed_pii["decision"] == "ALLOW"
    assert allowed_pii["sanitized_text"] == pii_only

    audit_value = protected_original_for_audit(
        original_text=text,
        sanitized_text=relaxed_policy["sanitized_text"],
        issues=classification["issues"],
        audit_storage="PROTECTED",
    )
    assert PROTECTED_STORAGE_NOTE in audit_value
    assert "supersecret123" not in audit_value

    full_text_value = protected_original_for_audit(
        original_text=text,
        sanitized_text=relaxed_policy["sanitized_text"],
        issues=classification["issues"],
        audit_storage="FULL_TEXT",
    )
    assert "supersecret123" in full_text_value


if __name__ == "__main__":
    test_classify_credentials_and_pii()
    test_classify_new_credentials()
    test_sanitize_new_types()
    test_cross_domain_sensitive_data()
    test_customer_complaint_redaction_regression()
    test_policy_safe_customer_prompt_allows_rescan()
    test_hr_csv_export_redaction_regression()
    test_env_secret_and_auth_material_redaction_regression()
    test_redacted_key_value_placeholders_are_allowed_on_rescan()
    test_configurable_policy_and_protected_audit_storage()
    print("All backend rules and sanitization tests pass successfully!")
