import hashlib
import json
import secrets

from agent import plan_incident
from database import DatabaseConflict, get_incident, save_incident
from telemetry import new_span_id, new_trace_id


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def content_hash(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def make_id():
    return secrets.token_hex(12)


def start_incident(request):
    data = request.model_dump(mode="json")

    run_id = data["runId"]
    request_hash = content_hash(data)

    # Return the existing result for an identical replay.
    existing = get_incident(run_id)
    if existing:
        if existing["request_hash"] != request_hash:
            raise DatabaseConflict("runId already exists")
        return existing["response"]

    # Sensitive information is deliberately not passed to the model.
    diagnosis_plan = plan_incident(
        incident=data["incident"],
        tool_catalog=data["toolCatalog"],
        policy=data["policy"]
    )

    trace_id = new_trace_id()
    dispatches = []

    for diagnostic in diagnosis_plan["diagnostics"]:
        span_id = new_span_id()

        dispatches.append({
            "actionId": make_id(),
            "callId": make_id(),
            "phase": "diagnostic",
            "toolName": diagnostic["toolName"],
            "arguments": diagnostic["arguments"],
            "evidence": diagnostic["evidence"],
            "attempt": 1,
            "traceparent": (
                f"00-{trace_id}-{span_id}-01"
            )
        })

    response = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": diagnosis_plan["rootCause"],
            "evidence": diagnosis_plan["evidence"]
        },
        "dispatches": dispatches,
        "approvals": []
    }

    state = {
        "phase": "diagnostics",
        "traceId": trace_id,
        "model": diagnosis_plan.get("model"),
        "requestHash": request_hash,
        "request": {
            "incident": data["incident"],
            "policy": data["policy"],
            "toolCatalog": data["toolCatalog"]
        },
        "actionLog": dispatches,
        "receiptLog": [],
        "pendingDispatches": dispatches,
        "pendingApprovals": [],
        "diagnosis": response["diagnosis"]
    }

    save_incident(
        run_id,
        request_hash,
        state,
        response
    )

    return response
