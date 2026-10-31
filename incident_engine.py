import hashlib
import json
import secrets
import uuid

from agent import plan_incident
from database import (
    DatabaseConflict,
    get_incident,
    get_receipt,
    save_incident,
    save_incident_and_receipt,
)
from telemetry import new_span_id, new_trace_id


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False
    )


def content_hash(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def make_id():
    return secrets.token_hex(12)


def approval_digest(arguments):
    return content_hash(arguments)


def response_view(state, run_id):
    response = {
        "runId": run_id,
        "status": state["status"],
        "diagnosis": state["diagnosis"],
        "dispatches": state.get("pendingDispatches", []),
        "approvals": state.get("pendingApprovals", [])
    }

    if state["status"] in ("completed", "failed"):
        response.update({
            "chosenEffect": state.get("chosenEffect"),
            "suppressed": state.get("suppressed", []),
            "actionLog": state.get("actionLog", []),
            "receiptLog": state.get("receiptLog", []),
            "otlp": state.get("otlp", {"resourceSpans": []})
        })

    return response


def start_incident(request):
    data = request.model_dump(mode="json")
    run_id = data["runId"]
    request_hash = content_hash(data)

    existing = get_incident(run_id)
    if existing:
        if existing["request_hash"] != request_hash:
            raise DatabaseConflict("runId content conflict")
        return existing["response"]

    # Never send sensitive data to the model.
    plan = plan_incident(
        incident=data["incident"],
        tool_catalog=data["toolCatalog"],
        policy=data["policy"]
    )

    trace_id = new_trace_id()
    dispatches = []

    for item in plan["diagnostics"]:
        span_id = new_span_id()
        dispatches.append({
            "actionId": make_id(),
            "callId": make_id(),
            "phase": "diagnostic",
            "toolName": item["toolName"],
            "arguments": item["arguments"],
            "evidence": item["evidence"],
            "attempt": 1,
            "traceparent": f"00-{trace_id}-{span_id}-01"
        })

    diagnosis = {
        "rootCause": plan["rootCause"],
        "evidence": plan["evidence"]
    }

    state = {
        "phase": "diagnostics",
        "status": "waiting",
        "traceId": trace_id,
        "model": plan.get("model"),
        "requestHash": request_hash,
        "request": {
            "incident": data["incident"],
            "policy": data["policy"],
            "toolCatalog": data["toolCatalog"]
        },
        "diagnosis": diagnosis,
        "actionLog": dispatches.copy(),
        "receiptLog": [],
        "pendingDispatches": dispatches,
        "pendingApprovals": [],
        "chosenEffect": None,
        "suppressed": [],
        "otlp": {"resourceSpans": []}
    }

    response = response_view(state, run_id)
    save_incident(run_id, request_hash, state, response)
    return response


def find_tool(state, name):
    for tool in state["request"]["toolCatalog"]:
        if tool.get("name") == name:
            return tool
    return None


def select_effect(state):
    policy = state["request"]["policy"]
    allowed_effects = policy.get("effectTools", [])

    # A tool catalog entry must exist before it can be selected.
    candidates = [
        name for name in allowed_effects
        if find_tool(state, name) is not None
    ]

    if not candidates:
        state["status"] = "failed"
        state["phase"] = "finished"
        state["suppressed"].append("No permitted effect tool")
        return

    # This is a placeholder selection rule. It will be replaced
    # with a model-justified effect selection in the next revision.
    chosen = candidates[0]
    state["chosenEffect"] = chosen

    arguments = {}
    action_id = make_id()

    if chosen in policy.get("approvalRequiredFor", []):
        approval = {
            "approvalId": make_id(),
            "actionId": action_id,
            "toolName": chosen,
            "argumentsDigest": approval_digest(arguments)
        }
        state["pendingApprovals"] = [approval]
        state["phase"] = "approval"
        return

    dispatch_effect(state, chosen, arguments, action_id)


def dispatch_effect(state, tool_name, arguments, action_id,
                    approval_id=None, approval_nonce=None):
    span_id = new_span_id()
    dispatch = {
        "actionId": action_id,
        "callId": make_id(),
        "phase": "effect",
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": state["diagnosis"]["evidence"][:1],
        "attempt": 1,
        "traceparent": (
            f"00-{state['traceId']}-{span_id}-01"
        )
    }

    if approval_id:
        dispatch["approvalId"] = approval_id
        dispatch["approvalNonce"] = approval_nonce

    state["pendingDispatches"] = [dispatch]
    state["actionLog"].append(dispatch)
    state["phase"] = "effect"


def process_receipt(run_id, receipt_request):
    receipt = receipt_request.model_dump(mode="json")
    receipt_id = receipt["receiptId"]
    receipt_hash = content_hash(receipt)

    existing_receipt = get_receipt(receipt_id)
    if existing_receipt:
        if (
            existing_receipt["run_id"] != run_id
            or existing_receipt["receipt_hash"] != receipt_hash
        ):
            raise DatabaseConflict("receiptId content conflict")

        incident = get_incident(run_id)
        return incident["response"]

    incident = get_incident(run_id)
    if not incident:
        raise KeyError("Incident not found")

    state = incident["state"]
    request_hash = incident["request_hash"]

    if state["status"] != "waiting":
        raise ValueError("Incident has no pending work")

    if state["phase"] == "approval":
        approvals = receipt["approvals"]
        if receipt["outcomes"] or len(approvals) != 1:
            raise ValueError("Expected one approval outcome")

        pending = state["pendingApprovals"][0]
        outcome = approvals[0]

        if outcome["approvalId"] != pending["approvalId"]:
            raise ValueError("Unknown approval ID")
        if outcome["decision"] != "approved":
            state["status"] = "failed"
            state["phase"] = "finished"
            state["pendingApprovals"] = []
            state["suppressed"].append("Approval denied")
        else:
            state["receiptLog"].append({
                "receiptId": receipt_id,
                "approvalId": outcome["approvalId"],
                "decision": outcome["decision"],
                "nonce": outcome["nonce"]
            })
            state["pendingApprovals"] = []
            dispatch_effect(
                state,
                pending["toolName"],
                {},
                pending["actionId"],
                pending["approvalId"],
                outcome["nonce"]
            )

    else:
        outcomes = receipt["outcomes"]
        if receipt["approvals"] or not outcomes:
            raise ValueError("Expected tool outcomes only")

        pending = state["pendingDispatches"]
        if len(outcomes) != len(pending):
            raise ValueError("Outcome count does not match pending calls")

        retry_dispatches = []
        diagnostic_failed = False
        effect_failed = False

        for outcome in outcomes:
            match = next(
                (
                    item for item in pending
                    if item["actionId"] == outcome["actionId"]
                    and item["callId"] == outcome["callId"]
                    and item["attempt"] == outcome["attempt"]
                ),
                None
            )
            if not match:
                raise ValueError("Outcome does not match a pending call")

            status = outcome["status"]
            state["receiptLog"].append({
                "receiptId": receipt_id,
                **outcome
            })

            if status == 503 and match["attempt"] == 1:
                retry = dict(match)
                retry["attempt"] = 2
                retry["traceparent"] = (
                    f"00-{state['traceId']}-{new_span_id()}-01"
                )
                retry_dispatches.append(retry)
                state["actionLog"].append(retry)
            elif status == 200:
                continue
            else:
                if match["phase"] == "diagnostic":
                    diagnostic_failed = True
                else:
                    effect_failed = True

        state["pendingDispatches"] = retry_dispatches

        if retry_dispatches:
            pass
        elif diagnostic_failed:
            state["status"] = "failed"
            state["phase"] = "finished"
            state["suppressed"].append(
                "Diagnostic prerequisite failed"
            )
        elif state["phase"] == "diagnostics":
            select_effect(state)
        elif effect_failed:
            state["status"] = "failed"
            state["phase"] = "finished"
        else:
            state["status"] = "completed"
            state["phase"] = "finished"
            state["pendingDispatches"] = []

    if state["phase"] == "finished":
        state["pendingDispatches"] = []
        state["pendingApprovals"] = []

    response = response_view(state, run_id)

    save_incident_and_receipt(
        run_id,
        request_hash,
        state,
        response,
        receipt_id,
        receipt_hash,
        receipt
    )

    return response
