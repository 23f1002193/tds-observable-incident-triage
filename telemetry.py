
import secrets
import time


def new_trace_id():
    return secrets.token_hex(16)


def new_span_id():
    return secrets.token_hex(8)


def now_ns():
    return str(time.time_ns())


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

