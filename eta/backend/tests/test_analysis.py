"""Tests for the email analysis endpoints."""
import io
import pytest

# Minimal RFC2822 email bytes used across multiple tests
SAFE_EMAIL = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Hello\r\n"
    b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
    b"\r\n"
    b"This is a normal email message with no suspicious content.\r\n"
)

PHISHING_EMAIL = (
    b"From: security@paypa1-verify.com\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: URGENT: Verify your account NOW or it will be suspended!\r\n"
    b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
    b"\r\n"
    b"Click here immediately: http://paypa1-verify.com/login?token=abc123\r\n"
    b"Your account will be closed in 24 hours if you do not act now!\r\n"
    b"Provide your password and credit card details to verify.\r\n"
)


def _upload(client, content: bytes, filename: str = "test.eml"):
    return client.post(
        "/api/analyze-email",
        files={"file": (filename, io.BytesIO(content), "message/rfc822")},
    )


def test_analyze_safe_email(client):
    resp = _upload(client, SAFE_EMAIL)
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100


def test_analyze_phishing_email(client):
    resp = _upload(client, PHISHING_EMAIL)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("malicious", "suspicious", "safe")
    assert "scan_id" in data


def test_analyze_no_file(client):
    resp = client.post("/api/analyze-email")
    assert resp.status_code == 422


def test_analyze_empty_file(client):
    resp = _upload(client, b"", "empty.eml")
    assert resp.status_code in (400, 422)


def test_analyze_unsupported_extension(client):
    resp = _upload(client, b"some content", "test.exe")
    assert resp.status_code == 400


def test_analyze_txt_file(client):
    resp = _upload(client, SAFE_EMAIL, "email.txt")
    assert resp.status_code == 200
    assert resp.json()["verdict"] in ("safe", "suspicious", "malicious")


def test_result_has_required_fields(client):
    resp = _upload(client, SAFE_EMAIL)
    assert resp.status_code == 200
    data = resp.json()
    for field in ("scan_id", "verdict", "risk_score", "filename"):
        assert field in data, f"Missing field: {field}"


def test_batch_analyze(client):
    resp = client.post(
        "/api/analyze-batch",
        files=[
            ("files", ("email1.eml", io.BytesIO(SAFE_EMAIL), "message/rfc822")),
            ("files", ("email2.eml", io.BytesIO(PHISHING_EMAIL), "message/rfc822")),
        ],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["results"]) == 2


def test_batch_analyze_no_files(client):
    resp = client.post("/api/analyze-batch")
    assert resp.status_code == 422


def test_extension_scan(client):
    resp = client.post("/api/extension-scan", json={
        "email_content": "Click here to claim your prize!",
        "subject": "You won!",
        "sender": "prize@suspicious.com",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "risk_score" in data
