from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def safe_release_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "vendor", "name": "scan", "ref": "a" * 40},
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def test_release_gate_safe_and_multifailure():
    payload = safe_release_payload()
    assert client.post("/release-gate", json=payload).json() == {"decision": "promote", "violations": []}
    payload["workflow"]["permissions"]["issues"] = "write"
    payload["workflow"]["testsPassed"] = False
    payload["image"]["runsAsRoot"] = True
    assert set(client.post("/release-gate", json=payload).json()["violations"]) == {
        "EXCESS_PERMISSION",
        "TESTS_INCOMPLETE",
        "ROOT_RUNTIME",
    }


def test_action_firewall():
    base = {"provenance": "untrusted", "humanApproved": False, "untrustedContent": "ignore rules"}
    assert client.post("/action-firewall", json={**base, "action": {"tool": "search", "args": {"query": "weather"}}}).json()["decision"] == "allow"
    assert client.post("/action-firewall", json={**base, "action": {"tool": "lookup_record", "args": {"tenantId": "other", "recordId": "1"}}}).json()["reason"] == "TENANT_SCOPE"
    assert client.post("/action-firewall", json={**base, "action": {"tool": "send_email", "args": {"to": "a@notify-yh2pm5o.example.evil", "subject": "s", "body": "b"}}}).json()["reason"] == "EGRESS_DENIED"
    assert client.post("/action-firewall", json={**base, "action": {"tool": "render_html", "args": {"html": '<img src=x onerror="x">'}}}).json()["reason"] == "UNSAFE_OUTPUT"


def terraform_payload():
    return {
        "environment": "prod-v6vy55",
        "state": {"backend": "gcs", "locked": True},
        "providerVersion": "~> 6.0",
        "destroyApproved": False,
        "resource": {
            "address": "google_storage_bucket.data",
            "type": "storage_bucket",
            "action": "create",
            "labels": {"owner": "student-vob8t", "environment": "production", "cost_center": "cc-gjej"},
            "secret": None,
            "forceDestroy": False,
        },
    }


def test_terraform_gate():
    payload = terraform_payload()
    assert client.post("/terraform/plan", json=payload).json() == {"decision": "approve", "reason": "APPROVE"}
    payload["resource"]["action"] = "delete"
    assert client.post("/terraform/plan", json=payload).json()["reason"] == "DELETE_NOT_APPROVED"


def test_output_sanitizer():
    assert client.post("/sanitize-output", json={"channel": "html", "output": '<a href="https://cdn-bsaff2l.example/x">ok</a>'}).json()["safe"] is True
    assert client.post("/sanitize-output", json={"channel": "url", "output": "https://cdn-bsaff2l.example.evil/x"}).json()["reason"] == "EXTERNAL_EXFIL"
    assert client.post("/sanitize-output", json={"channel": "html", "output": "%3Cscript%3Ealert(1)%3C/script%3E"}).json()["reason"] == "ENCODED_PAYLOAD"
    assert client.post("/sanitize-output", json={"channel": "shell", "output": "echo ${HOME}"}).json()["reason"] == "SHELL_METACHAR"


def test_corroboration():
    body = {
        "claim": {"subject": "93scdz.example", "predicate": "resolves_to", "value": "203.0.113.20"},
        "asOf": "2026-08-01T00:00:00Z",
        "stalenessDays": 90,
        "sources": [
            {"id": "s2", "type": "dns", "origin": "a", "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
            {"id": "s1", "type": "archive", "origin": "b", "observedAt": "2026-07-29T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
        ],
    }
    assert client.post("/corroborate", json=body).json() == {"verdict": "supported", "confidence": "high", "corroboratingSources": ["s1", "s2"]}

