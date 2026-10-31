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
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def content_hash(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def make_id():
    return secrets.token_hex(16)


def approval_digest(arguments):
    return content_hash(arguments)


def valid_nonce(value):
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def response_view(state, run_id):
    response = {
        "runId": run_id,
        "status": state["status"],
        "diagnosis": state["diagnosis"],
        "dispatches": state.get("pendingDispatches", []),
        "approvals": state.get("pendingApprovals", []),
    }

    if state["status"] in ("completed", "failed"):
        response.update({
            "chosenEffect": state.get("chosenEffect"),
            "suppressed": state.get("suppressed", []),
            "actionLog": state.get("actionLog", []),
            "receiptLog": state.get("receiptLog", []),
            "otlp": state.get("otlp", {"resourceSpans": []}),
            "dispatches": [],
            "approvals": [],
        })

    return response


def start_incident(request):
    data = request.model_dump(mode="json")

    if data.get("profile") != "ga5-incident-agent/v2":
        raise ValueError("Unsupported incident profile.")

    run_id = data["runId"]
    request_hash = content_hash(data)

    existing = get_incident(run_id)

    if existing:
        if existing["request_hash"] != request_hash:
            raise DatabaseConflict("runId already exists with different content.")
        return existing["response"]

    plan = plan_incident(
        incident=data["incident"],
        tool_catalog=data["toolCatalog"],
        policy=data["policy"],
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
            "traceparent": f"00-{trace_id}-{span_id}-01",
        })

    diagnosis = {
        "rootCause": plan["rootCause"],
        "evidence": plan["evidence"],
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
            "toolCatalog": data["toolCatalog"],
        },
        "diagnosis": diagnosis,
        "proposedEffect": plan["effect"],
        "pendingApprovalArguments": None,
        "actionLog": dispatches.copy(),
        "receiptLog": [],
        "pendingDispatches": dispatches,
        "pendingApprovals": [],
        "chosenEffect": None,
        "suppressed": [],
        "otlp": {"resourceSpans": []},
    }

    response = response_view(state, run_id)

    save_incident(run_id, request_hash, state, response)

    return response


def find_tool(state, name):
    for tool in state["request"]["toolCatalog"]:
        if tool.get("name") == name:
            return tool
    return None


def dispatch_effect(
    state,
    tool_name,
    arguments,
    action_id,
    approval_id=None,
    approval_nonce=None,
):
    trace_id = state["traceId"]
    span_id = new_span_id()

    evidence = state["proposedEffect"]["evidence"]

    dispatch = {
        "actionId": action_id,
        "callId": make_id(),
        "phase": "effect",
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": 1,
        "traceparent": f"00-{trace_id}-{span_id}-01",
    }

    if approval_id is not None:
        dispatch["approvalId"] = approval_id
        dispatch["approvalNonce"] = approval_nonce

    state["pendingDispatches"] = [dispatch]
    state["pendingApprovals"] = []
    state["actionLog"].append(dispatch)
    state["phase"] = "effect"
    state["status"] = "waiting"


def select_effect(state):
    proposed = state.get("proposedEffect")

    if not isinstance(proposed, dict):
        state["status"] = "failed"
        state["phase"] = "finished"
        state["suppressed"].append({
            "reason": "No valid effect was proposed."
        })
        return

    tool_name = proposed.get("toolName")
    arguments = proposed.get("arguments")
    evidence = proposed.get("evidence")

    if (
        not isinstance(tool_name, str)
        or not isinstance(arguments, dict)
        or not isinstance(evidence, list)
        or not evidence
        or find_tool(state, tool_name) is None
    ):
        state["status"] = "failed"
        state["phase"] = "finished"
        state["suppressed"].append({
            "reason": "The proposed effect is invalid."
        })
        return

    policy = state["request"]["policy"]
    allowed_effects = policy.get("effectTools", [])

    if tool_name not in allowed_effects:
        state["status"] = "failed"
        state["phase"] = "finished"
        state["suppressed"].append({
            "reason": "The proposed effect is not permitted."
        })
        return

    action_id = make_id()
    state["chosenEffect"] = tool_name

    if tool_name in policy.get("approvalRequiredFor", []):
        approval_id = make_id()

        state["pendingApprovalArguments"] = arguments
        state["pendingApprovals"] = [{
            "approvalId": approval_id,
            "actionId": action_id,
            "toolName": tool_name,
            "argumentsDigest": approval_digest(arguments),
        }]

        state["pendingDispatches"] = []
        state["phase"] = "approval"
        state["status"] = "waiting"
        return

    dispatch_effect(
        state,
        tool_name,
        arguments,
        action_id,
    )


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
            raise DatabaseConflict(
                "receiptId already exists with different content."
            )

        incident = get_incident(run_id)

        if not incident:
            raise KeyError(run_id)

        return incident["response"]

    incident = get_incident(run_id)

    if not incident:
        raise KeyError(run_id)

    state = incident["state"]
    request_hash = incident["request_hash"]

    if state["status"] != "waiting":
        raise ValueError("This incident is not waiting for a receipt.")

    if state["phase"] == "approval":
        if receipt["outcomes"] or len(receipt["approvals"]) != 1:
            raise ValueError("Expected exactly one approval receipt.")

        approval_result = receipt["approvals"][0]
        pending = state["pendingApprovals"]

        if len(pending) != 1:
            raise ValueError("No pending approval exists.")

        approval = pending[0]

        if approval_result["approvalId"] != approval["approvalId"]:
            raise ValueError("Unexpected approval ID.")

        if approval_result["decision"] not in ("approved", "denied"):
            raise ValueError("Invalid approval decision.")

        if not valid_nonce(approval_result["nonce"]):
            raise ValueError("Invalid approval nonce.")

        state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": approval_result["approvalId"],
            "decision": approval_result["decision"],
            "nonce": approval_result["nonce"],
        })

        state["pendingApprovals"] = []

        if approval_result["decision"] == "denied":
            state["status"] = "failed"
            state["phase"] = "finished"
            state["suppressed"].append({
                "reason": "Effect approval was denied."
            })
        else:
            arguments = state.get("pendingApprovalArguments")

            if not isinstance(arguments, dict):
                raise ValueError("Approved effect arguments are missing.")

            if approval_digest(arguments) != approval["argumentsDigest"]:
                raise ValueError("Approved effect arguments do not match.")

            dispatch_effect(
                state,
                approval["toolName"],
                arguments,
                approval["actionId"],
                approval["approvalId"],
                approval_result["nonce"],
            )

    else:
        if receipt["approvals"] or not receipt["outcomes"]:
            raise ValueError("Expected tool outcome receipts.")

        pending = state.get("pendingDispatches", [])

        if len(receipt["outcomes"]) != len(pending):
            raise ValueError("Receipt does not cover all pending calls.")

        pending_by_call = {
            (item["actionId"], item["callId"], item["attempt"]): item
            for item in pending
        }

        received_keys = set()
        retry_dispatches = []
        failed = False

        for outcome in receipt["outcomes"]:
            key = (
                outcome["actionId"],
                outcome["callId"],
                outcome["attempt"],
            )

            if key not in pending_by_call or key in received_keys:
                raise ValueError("Unexpected or duplicate tool outcome.")

            received_keys.add(key)

            if outcome["status"] not in (0, 200, 503):
                raise ValueError("Unsupported tool outcome status.")

            if outcome["status"] == 0:
                if outcome.get("errorType") != "timeout":
                    raise ValueError("Status 0 requires errorType timeout.")
                failed = True

            elif outcome["status"] == 200:
                if not outcome.get("resultClass"):
                    raise ValueError("Successful outcome needs resultClass.")
                if not valid_nonce(outcome.get("nonce")):
                    raise ValueError("Successful outcome needs a UUID nonce.")

            elif outcome["status"] == 503:
                if outcome["attempt"] != 1:
                    raise ValueError("Only one retry is permitted.")

                original = pending_by_call[key]
                retry = dict(original)
                retry["attempt"] = 2

                trace_id = state["traceId"]
                span_id = new_span_id()
                retry["traceparent"] = (
                    f"00-{trace_id}-{span_id}-01"
                )

                retry_dispatches.append(retry)

            log_entry = {
                "receiptId": receipt_id,
                "actionId": outcome["actionId"],
                "callId": outcome["callId"],
                "attempt": outcome["attempt"],
                "status": outcome["status"],
            }

            if outcome.get("resultClass") is not None:
                log_entry["resultClass"] = outcome["resultClass"]

            if outcome.get("nonce") is not None:
                log_entry["nonce"] = outcome["nonce"]

            if outcome.get("errorType") is not None:
                log_entry["errorType"] = outcome["errorType"]

            state["receiptLog"].append(log_entry)

        if received_keys != set(pending_by_call):
            raise ValueError("Receipt is missing a pending call.")

        state["pendingDispatches"] = retry_dispatches

        if retry_dispatches:
            state["status"] = "waiting"

        elif failed:
            state["status"] = "failed"
            state["phase"] = "finished"
            state["suppressed"].append({
                "reason": "A required tool call timed out."
            })

        elif state["phase"] == "diagnostics":
            select_effect(state)

        elif state["phase"] == "effect":
            state["status"] = "completed"
            state["phase"] = "finished"

        else:
            raise ValueError("Invalid incident phase.")

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
        receipt,
    )

    return response

