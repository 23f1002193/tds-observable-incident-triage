
import re
import secrets
import time


TRACEPARENT_PATTERN = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)


def new_trace_id():
    return secrets.token_hex(16)


def new_span_id():
    return secrets.token_hex(8)


def now_ns():
    return str(time.time_ns())


def parse_trace_context(traceparent, tracestate=None):
    """
    Parse a W3C version 00 traceparent.

    Invalid or unsupported context starts a new trace.
    Returns trace ID, parent span ID, flags and optional tracestate.
    """
    if not isinstance(traceparent, str):
        return None

    match = TRACEPARENT_PATTERN.fullmatch(traceparent)

    if not match:
        return None

    trace_id, parent_span_id, flags = match.groups()

    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None

    result = {
        "traceId": trace_id,
        "parentSpanId": parent_span_id,
        "traceFlags": flags,
    }

    if isinstance(tracestate, str) and tracestate.strip():
        result["tracestate"] = tracestate

    return result


def make_span(
    trace_id,
    name,
    kind,
    attributes=None,
    parent_span_id=None,
    links=None,
    status_code=0,
    status_message="",
    start_time=None,
    end_time=None,
):
    start = start_time or now_ns()
    end = end_time or now_ns()

    span_attributes = []

    for key, value in (attributes or {}).items():
        if isinstance(value, bool):
            encoded = {"boolValue": value}
        elif isinstance(value, int):
            encoded = {"intValue": value}
        elif isinstance(value, float):
            encoded = {"doubleValue": value}
        elif isinstance(value, str):
            encoded = {"stringValue": value}
        else:
            continue

        span_attributes.append({
            "key": str(key),
            "value": encoded,
        })

    span = {
        "traceId": trace_id,
        "spanId": new_span_id(),
        "name": name,
        "kind": kind,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": span_attributes,
        "status": {
            "code": status_code,
            "message": status_message,
        },
    }

    if parent_span_id:
        span["parentSpanId"] = parent_span_id

    if links:
        span["links"] = links

    return span


def make_otlp(spans):
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "incident-response",
                        },
                        "spans": spans,
                    }
                ]
            }
        ]
    }

