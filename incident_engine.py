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
from telemetry import (
    make_otlp,
    make_span,
    new_span_id,
    new_trace_id,
    parse_trace_context,
)


INTERNAL = 1
SERVER = 2
CLIENT = 3
STATUS_OK = 1
STATUS_ERROR = 2


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


def add_span(state, name, kind, attributes=None,
             parent_span_id=None, links=None,
             status_code=0, status_message=""):
    span = make_span(
        trace_id=state["traceId"],
        name=name,
        kind=kind,
        attributes=attributes,
        parent_span_id=parent_span_id,
        links=links,
        status_code=status_code,
        status_message=status_message,
    )
    state["spans"].append(span)
    return span


def make_traceparent(trace_id, span_id, flags="01"):
    return f"00-{trace_id}-{span_id}-{flags}"


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
            "otlp": make_otlp(state.get("spans", [])),
            "dispatches": [],
            "approvals": [],
        })

    return response


def find_tool(state, name):
    for tool in state["request"]["toolCatalog"]:
        if tool.get("name") == name:
            return tool
    return None


def add_tool_dispatch(state, tool_name, arguments, action_id,
                      phase, evidence, attempt=1,
                      approval_id=None, approval_nonce=None):
    agent_span_id = state["agentSpanId"]

    logical_span = add_span(
        state,
        f"execute_tool {tool_name}",
        INTERNAL,
        {
            "ga5.run.id": state["runId"],
            "ga5.public.marker": state["publicMarker"],
            "ga5.action.id": action_id,
            "gen_ai.tool.name": tool_name,
            "gen_ai.tool.call.id": action_id,
            "gen_ai.operation.name": "execute_tool",
        },
        parent_span_id=agent_span_id,
    )

    client_span = add_span(
        state,
        f"POST tool/{tool_name}",
        CLIENT,
        {
            "ga5.run.id": state["runId"],
            "ga5.public.marker": state["publicMarker"],
            "ga5.action.id": action_id,
            "ga5.attempt": attempt,
            "http.request.method": "POST",
            "http.request.resend_count": attempt - 1,
        },
        parent_span_id=logical_span["spanId"],
    )

    dispatch = {
        "actionId": action_id,
        "callId": make_id(),
        "phase": phase,
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": attempt,
        "traceparent": make_traceparent(
            state["traceId"], client_span["spanId"]
        ),
    }

    if approval_id is not None:
        dispatch["approvalId"] = approval_id
        dispatch["approvalNonce"] = approval_nonce

    state["actionLog"].append(dispatch)
    state["pendingDispatches"].append(dispatch)

    return dispatch


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

    if tool_name not in policy.get("effectTools", []):
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

        add_span(
            state,
            "approval_gate",
            INTERNAL,
            {
                "ga5.run.id": state["runId"],
                "ga5.public.marker": state["publicMarker"],
                "ga5.approval.id": approval_id,
            },
            parent_span_id=state["agentSpanId"],
        )

        state["pendingDispatches"] = []
        state["phase"] = "approval"
        state["status"] = "waiting"
        return

    state["pendingDispatches"] = []

    add_tool_dispatch(
        state,
        tool_name,
        arguments,
        action_id,
        "effect",
        evidence,
    )

    state["phase"] = "effect"
    state["status"] = "waiting"


def start_incident(request, traceparent=None, tracestate=None):
    data = request.model_dump(mode="json")

    if data.get("profile") != "ga5-incident-agent/v2":
        raise ValueError("Unsupported incident profile.")

    run_id = data["runId"]
    request_hash = content_hash(data)

    existing = get_incident(run_id)

    if existing:
        if existing["request_hash"] != request_hash:
            raise DatabaseConflict(
                "runId already exists with different content."
            )
        return existing["response"]

    incoming = parse_trace_context(traceparent, tracestate)

    if incoming:
        trace_id = incoming["traceId"]
        remote_parent = incoming["parentSpanId"]
    else:
        trace_id = new_trace_id()
        remote_parent = None

    state = {
        "runId": run_id,
        "publicMarker": data["publicMarker"],
        "traceId": trace_id,
        "spans": [],
        "actionLog": [],
        "receiptLog": [],
        "pendingDispatches": [],
        "pendingApprovals": [],
        "pendingApprovalArguments": None,
        "suppressed": [],
        "chosenEffect": None,
        "status": "waiting",
        "phase": "planning",
        "requestHash": request_hash,
        "request": {
            "incident": data["incident"],
            "policy": data["policy"],
            "toolCatalog": data["toolCatalog"],
        },
        "otlp": {"resourceSpans": []},
    }

    server_span = add_span(
        state,
        "POST /v2/incidents",
        SERVER,
        {
            "ga5.run.id": run_id,
            "ga5.public.marker": data["publicMarker"],
        },
        parent_span_id=remote_parent,
    )

    agent_span = add_span(
        state,
        "invoke_agent incident-response",
        INTERNAL,
        {
            "ga5.run.id": run_id,
            "ga5.public.marker": data["publicMarker"],
        },
        parent_span_id=server_span["spanId"],
    )

    state["agentSpanId"] = agent_span["spanId"]

    model_span = add_span(
        state,
        "chat incident-plan",
        CLIENT,
        {
            "ga5.run.id": run_id,
            "ga5.public.marker": data["publicMarker"],
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "gemini",
        },
        parent_span_id=agent_span["spanId"],
    )

    plan = plan_incident(
        incident=data["incident"],
        tool_catalog=data["toolCatalog"],
        policy=data["policy"],
    )

    model_span["attributes"].append({
        "key": "gen_ai.request.model",
        "value": {
            "stringValue": plan.get("model", "gemini")
        },
    })

    state["diagnosis"] = {
        "rootCause": plan["rootCause"],
        "evidence": plan["evidence"],
    }

    state["proposedEffect"] = plan["effect"]
    state["model"] = plan.get("model")

    diagnostic_dispatches = []

    for item in plan["diagnostics"]:
        dispatch = add_tool_dispatch(
            state,
            item["toolName"],
            item["arguments"],
            make_id(),
            "diagnostic",
            item["evidence"],
        )
        diagnostic_dispatches.append(dispatch)

    if len(diagnostic_dispatches) > 1:
        logical_spans = [
            span for span in state["spans"]
            if span["name"].startswith("execute_tool ")
        ]

        links = [
            {
                "traceId": span["traceId"],
                "spanId": span["spanId"],
            }
            for span in logical_spans
        ]

        add_span(
            state,
            "incident.join",
            INTERNAL,
            {
                "ga5.run.id": run_id,
                "ga5.public.marker": data["publicMarker"],
            },
            parent_span_id=agent_span["spanId"],
            links=links,
        )

    state["phase"] = "diagnostics"

    response = response_view(state, run_id)

    save_incident(run_id, request_hash, state, response)

    return response


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
        raise ValueError("Incident is not waiting for a receipt.")

    if state["phase"] == "approval":
        if receipt["outcomes"] or len(receipt["approvals"]) != 1:
            raise ValueError("Expected one approval receipt.")

        result = receipt["approvals"][0]
        pending = state["pendingApprovals"]

        if len(pending) != 1:
            raise ValueError("No pending approval exists.")

        approval = pending[0]

        if result["approvalId"] != approval["approvalId"]:
            raise ValueError("Unexpected approval ID.")

        if result["decision"] not in ("approved", "denied"):
            raise ValueError("Invalid approval decision.")

        if not valid_nonce(result["nonce"]):
            raise ValueError("Invalid approval nonce.")

        state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": result["approvalId"],
            "decision": result["decision"],
            "nonce": result["nonce"],
        })

        state["pendingApprovals"] = []

        gate_spans = [
            span for span in state["spans"]
            if span["name"] == "approval_gate"
        ]

        if gate_spans:
            gate_spans[-1]["attributes"].append({
                "key": "ga5.approval.nonce",
                "value": {"stringValue": result["nonce"]},
            })

        if result["decision"] == "denied":
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

            state["pendingDispatches"] = []

            add_tool_dispatch(
                state,
                approval["toolName"],
                arguments,
                approval["actionId"],
                "effect",
                state["proposedEffect"]["evidence"],
                approval_id=approval["approvalId"],
                approval_nonce=result["nonce"],
            )

            state["phase"] = "effect"
            state["status"] = "waiting"

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
                    raise ValueError("Status 0 requires timeout errorType.")
                failed = True

            elif outcome["status"] == 200:
                if not outcome.get("resultClass"):
                    raise ValueError("Successful outcome needs resultClass.")
                if not valid_nonce(outcome.get("nonce")):
                    raise ValueError("Successful outcome needs UUID nonce.")

            elif outcome["status"] == 503:
                if outcome["attempt"] != 1:
                    raise ValueError("Only one retry is permitted.")

                original = pending_by_call[key]

                retry = dict(original)
                retry["attempt"] = 2

                retry_dispatches.append(
                    add_retry_span_and_dispatch(state, retry)
                )

            client_spans = [
                span for span in state["spans"]
                if span["kind"] == CLIENT
                and span["spanId"] == extract_span_id(
                    pending_by_call[key]["traceparent"]
                )
            ]

            if client_spans:
                client_span = client_spans[0]

                client_span["attributes"].extend([
                    {
                        "key": "ga5.receipt.id",
                        "value": {"stringValue": receipt_id},
                    },
                    {
                        "key": "ga5.receipt.nonce",
                        "value": {
                            "stringValue": outcome.get("nonce", "")
                        },
                    },
                    {
                        "key": "http.response.status_code",
                        "value": {"intValue": outcome["status"]},
                    },
                ])

                if outcome["status"] in (0, 503):
                    client_span["status"] = {
                        "code": STATUS_ERROR,
                        "message": outcome.get("errorType", str(outcome["status"])),
                    }

                    client_span["attributes"].append({
                        "key": "error.type",
                        "value": {
                            "stringValue": outcome.get(
                                "errorType", str(outcome["status"])
                            )
                        },
                    })

            log_entry = {
                "receiptId": receipt_id,
                "actionId": outcome["actionId"],
                "callId": outcome["callId"],
                "attempt": outcome["attempt"],
                "status": outcome["status"],
            }

            for field in ("resultClass", "nonce", "errorType"):
                if outcome.get(field) is not None:
                    log_entry[field] = outcome[field]

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


def extract_span_id(traceparent):
    try:
        return traceparent.split("-")[2]
    except (AttributeError, IndexError):
        return None


def add_retry_span_and_dispatch(state, original):
    logical_span_id = None

    for span in state["spans"]:
        if (
            span["name"] == f"execute_tool {original['toolName']}"
            and any(
                attribute["key"] == "ga5.action.id"
                and attribute["value"].get("stringValue") == original["actionId"]
                for attribute in span["attributes"]
            )
        ):
            logical_span_id = span["spanId"]
            break

    if not logical_span_id:
        logical_span_id = state["agentSpanId"]

    client_span = add_span(
        state,
        f"POST tool/{original['toolName']}",
        CLIENT,
        {
            "ga5.run.id": state["runId"],
            "ga5.public.marker": state["publicMarker"],
            "ga5.action.id": original["actionId"],
            "ga5.attempt": 2,
            "http.request.method": "POST",
            "http.request.resend_count": 1,
        },
        parent_span_id=logical_span_id,
    )

    retry = dict(original)
    retry["attempt"] = 2
    retry["traceparent"] = make_traceparent(
        state["traceId"], client_span["spanId"]
    )

    state["actionLog"].append(retry)

    return retry

