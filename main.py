import html
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


app = FastAPI(title="TDS GA7 Policy Gates")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ACTION_TENANT = "tenant-auulvbb"
EMAIL_DOMAIN = "notify-yh2pm5o.example"
TF_WORKSPACE = "prod-v6vy55"
TF_LABELS = {
    "owner": "student-vob8t",
    "environment": "production",
    "cost_center": "cc-gjej",
}
ALLOWED_EXTERNAL_HOSTS = {"cdn-bsaff2l.example", "app-fncwm8v.example"}
OSINT_SUBJECT = "93scdz.example"


async def json_body(request: Request) -> Any:
    try:
        return await request.json()
    except Exception:
        return None


@app.get("/")
def root() -> dict[str, Any]:
    return {"ok": True, "service": "tds-ga7"}


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/release-gate")
async def release_gate(request: Request) -> dict[str, Any]:
    body = await json_body(request)
    if not isinstance(body, dict):
        body = {}

    workflow = body.get("workflow") if isinstance(body.get("workflow"), dict) else {}
    image = body.get("image") if isinstance(body.get("image"), dict) else {}
    violations: list[str] = []

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }
    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    event = body.get("event")
    trigger = workflow.get("trigger")
    if (event == "pull_request" and trigger != "pull_request") or trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    actions = workflow.get("actions")
    mutable_action = not isinstance(actions, list)
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                mutable_action = True
                break
            owner = action.get("owner")
            ref = action.get("ref")
            if owner != "actions" and not (
                isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{40}", ref)
            ):
                mutable_action = True
                break
    if mutable_action:
        violations.append("MUTABLE_ACTION")

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if body.get("target") == "production":
        if event != "push" or trigger != "push" or body.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {"decision": "promote" if not violations else "block", "violations": violations}


def exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


@app.post("/action-firewall")
async def action_firewall(request: Request) -> dict[str, str]:
    body = await json_body(request)
    if not isinstance(body, dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    allowed_top_keys = {"provenance", "humanApproved", "action", "untrustedContent"}
    if not {"provenance", "humanApproved", "action"}.issubset(body) or not set(body).issubset(allowed_top_keys):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}
    if body.get("provenance") not in {"trusted", "untrusted"} or not isinstance(body.get("humanApproved"), bool):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}
    if "untrustedContent" in body and not isinstance(body["untrustedContent"], str):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    action = body.get("action")
    if not exact_keys(action, {"tool", "args"}) or not isinstance(action.get("tool"), str) or not isinstance(action.get("args"), dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    tool = action["tool"]
    args = action["args"]
    if tool not in {"search", "lookup_record", "send_email", "render_html"}:
        return {"decision": "block", "reason": "TOOL_NOT_ALLOWED"}

    if tool == "search":
        valid = exact_keys(args, {"query"}) and isinstance(args.get("query"), str) and 1 <= len(args["query"]) <= 200
    elif tool == "lookup_record":
        valid = (
            exact_keys(args, {"tenantId", "recordId"})
            and isinstance(args.get("tenantId"), str)
            and isinstance(args.get("recordId"), str)
            and bool(args["recordId"])
        )
    elif tool == "send_email":
        valid = (
            exact_keys(args, {"to", "subject", "body"})
            and all(isinstance(args.get(k), str) for k in ("to", "subject", "body"))
        )
    else:
        valid = exact_keys(args, {"html"}) and isinstance(args.get("html"), str)
    if not valid:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    if tool == "lookup_record" and args["tenantId"] != ACTION_TENANT:
        return {"decision": "block", "reason": "TENANT_SCOPE"}

    if tool == "send_email":
        recipient = args["to"]
        parts = recipient.rsplit("@", 1)
        if len(parts) != 2 or not parts[0] or parts[1].lower() != EMAIL_DOMAIN:
            return {"decision": "block", "reason": "EGRESS_DENIED"}
        if body["humanApproved"] is not True:
            return {"decision": "block", "reason": "APPROVAL_REQUIRED"}

    if tool == "render_html":
        rendered = args["html"]
        if (
            re.search(r"<\s*(?:script|iframe)\b", rendered, re.I)
            or re.search(r"\son[a-z0-9_-]+\s*=", rendered, re.I)
            or re.search(r"javascript\s*:", rendered, re.I)
        ):
            return {"decision": "block", "reason": "UNSAFE_OUTPUT"}

    return {"decision": "allow", "reason": "ALLOW"}


@app.post("/terraform/plan")
async def terraform_plan(request: Request) -> dict[str, str]:
    body = await json_body(request)
    if not isinstance(body, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    state = body.get("state")
    resource = body.get("resource")
    valid_types = (
        isinstance(body.get("environment"), str)
        and isinstance(state, dict)
        and isinstance(state.get("backend"), str)
        and isinstance(state.get("locked"), bool)
        and isinstance(body.get("providerVersion"), str)
        and isinstance(body.get("destroyApproved"), bool)
        and isinstance(resource, dict)
        and isinstance(resource.get("address"), str)
        and isinstance(resource.get("type"), str)
        and resource.get("action") in {"create", "update", "delete"}
        and isinstance(resource.get("labels"), dict)
        and (resource.get("secret") is None or isinstance(resource.get("secret"), str))
        and isinstance(resource.get("forceDestroy"), bool)
    )
    if not valid_types:
        return {"decision": "reject", "reason": "INVALID_PLAN"}
    if body["environment"] != TF_WORKSPACE:
        return {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"}
    if state["backend"] not in {"gcs", "s3", "azurerm", "remote"} or state["locked"] is not True:
        return {"decision": "reject", "reason": "STATE_UNSAFE"}
    if not re.fullmatch(r"(?:6\.2\.1|=\s*6\.2\.1|~>\s*6\.0)", body["providerVersion"].strip()):
        return {"decision": "reject", "reason": "UNPINNED_PROVIDER"}
    labels = resource["labels"]
    if any(labels.get(key) != value for key, value in TF_LABELS.items()):
        return {"decision": "reject", "reason": "MISSING_LABELS"}
    secret = resource["secret"]
    if secret is not None and not (secret.startswith("secret://") and len(secret) > len("secret://")):
        return {"decision": "reject", "reason": "PLAINTEXT_SECRET"}
    protected_types = {"storage_bucket", "sql_database", "persistent_disk"}
    if resource["action"] == "delete" and resource["type"] in protected_types and body["destroyApproved"] is not True:
        return {"decision": "reject", "reason": "DELETE_NOT_APPROVED"}
    if resource["type"] == "storage_bucket" and resource["forceDestroy"] is True:
        return {"decision": "reject", "reason": "FORCE_DESTROY"}
    return {"decision": "approve", "reason": "APPROVE"}


def decode_once(value: str) -> str:
    decoded = unquote(value)

    def replace_entity(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.startswith("&#x") or token.startswith("&#X"):
            return chr(int(token[3:-1], 16))
        if token.startswith("&#"):
            return chr(int(token[2:-1], 10))
        named = {
            "&lt;": "<",
            "&gt;": ">",
            "&quot;": '"',
            "&apos;": "'",
            "&amp;": "&",
        }
        return named.get(token.lower(), token)

    decoded = re.sub(r"&#(?:[xX][0-9a-fA-F]+|[0-9]+);|&(?:lt|gt|quot|apos|amp);", replace_entity, decoded, flags=re.I)
    decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded


def extracted_urls(channel: str, output: str) -> list[str]:
    if channel == "html":
        pattern = re.compile(r"(?:src|href)\s*=\s*(['\"])(.*?)\1", re.I | re.S)
        return [match.group(2).strip() for match in pattern.finditer(output)]
    if channel == "markdown":
        return [match.group(1) for match in re.finditer(r"\]\(\s*([^\s)]*)", output) if match.group(1)]
    if channel == "url":
        return [output.strip()]
    return []


SCHEME_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def parse_absolute(candidate: str):
    raw = candidate.strip()
    if re.match(r"^//[^/]", raw):
        raw = "https:" + raw
    elif not SCHEME_PREFIX_RE.match(raw):
        return None

    # Browsers treat backslashes as slashes for special HTTP(S) URLs.
    if re.match(r"^https?:", raw, re.I):
        raw = raw.replace("\\", "/")
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() in {"http", "https"} and not parsed.hostname:
            return None
        return parsed
    except ValueError:
        return None


def dangerous_scheme(output: str, urls: list[str]) -> bool:
    if re.search(r"(?:javascript|data|vbscript)\s*:", output, re.I):
        return True
    for candidate in urls:
        parsed = parse_absolute(candidate)
        if parsed is not None and parsed.scheme.lower() not in {"http", "https"}:
            return True
        if parsed is None and SCHEME_PREFIX_RE.match(candidate.strip()):
            return True
    return False


def external_exfil(urls: list[str]) -> bool:
    for candidate in urls:
        parsed = parse_absolute(candidate)
        if parsed is not None and (parsed.hostname or "").lower() not in ALLOWED_EXTERNAL_HOSTS:
            return True
    return False


def channel_reason(channel: str, output: str) -> str:
    urls = extracted_urls(channel, output)
    if channel == "html":
        if re.search(r"<\s*(?:script|iframe|object|embed)\b", output, re.I):
            return "SCRIPT_TAG"
        if re.search(r"\son[a-z]+\s*=", output, re.I):
            return "EVENT_HANDLER"
        if dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"
        if external_exfil(urls):
            return "EXTERNAL_EXFIL"
    elif channel in {"markdown", "url"}:
        if dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"
        if external_exfil(urls):
            return "EXTERNAL_EXFIL"
    elif channel == "sql":
        if re.search(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", output, re.I):
            return "SQL_METACHAR"
    elif channel == "shell":
        if re.search(r"[;&|`<>]|\$\(|\$\{", output):
            return "SHELL_METACHAR"
    return "SAFE"


@app.post("/sanitize-output")
async def sanitize_output(request: Request) -> dict[str, Any]:
    body = await json_body(request)
    if (
        not isinstance(body, dict)
        or body.get("channel") not in {"html", "markdown", "url", "sql", "shell"}
        or not isinstance(body.get("output"), str)
        or len(body.get("output", "")) > 20_000
    ):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    channel = body["channel"]
    output = body["output"]
    decoded = decode_once(output)
    if decoded != output and channel_reason(channel, decoded) != "SAFE":
        return {"safe": False, "reason": "ENCODED_PAYLOAD"}
    reason = channel_reason(channel, output)
    return {"safe": reason == "SAFE", "reason": reason}


def parse_timestamp(value: str) -> datetime | None:
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return None
        return parsed
    except (TypeError, ValueError):
        return None


@app.post("/corroborate")
async def corroborate(request: Request) -> dict[str, Any]:
    body = await json_body(request)
    if not isinstance(body, dict):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}
    claim = body.get("claim")
    as_of = parse_timestamp(body.get("asOf")) if isinstance(body.get("asOf"), str) else None
    window = body.get("stalenessDays")
    sources = body.get("sources")
    if (
        not isinstance(claim, dict)
        or not isinstance(claim.get("value"), str)
        or as_of is None
        or not isinstance(window, (int, float))
        or isinstance(window, bool)
        or not isinstance(sources, list)
    ):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    valid_types = {"dns", "ct_log", "registry", "archive", "scan"}
    fresh: list[dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        if not all(isinstance(source.get(key), str) for key in ("id", "origin", "value", "observedAt")):
            continue
        if source.get("type") not in valid_types:
            continue
        observed = parse_timestamp(source["observedAt"])
        if observed is None:
            continue
        if as_of - observed <= timedelta(days=window):
            fresh.append(source)

    contradictions = sorted(
        source["id"]
        for source in fresh
        if source.get("authoritative") is True and source["value"] != claim["value"]
    )
    if contradictions:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contradictions,
        }

    representatives: dict[str, dict[str, Any]] = {}
    for source in fresh:
        if source["value"] != claim["value"]:
            continue
        origin = source["origin"]
        if origin not in representatives or source["id"] < representatives[origin]["id"]:
            representatives[origin] = source
    reps = list(representatives.values())
    if len(reps) >= 2:
        confidence = "high" if len({source["type"] for source in reps}) >= 2 else "medium"
        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": sorted(source["id"] for source in reps),
        }
    return {"verdict": "unverified", "confidence": "low", "corroboratingSources": []}
