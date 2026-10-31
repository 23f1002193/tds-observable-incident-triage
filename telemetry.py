import secrets


def new_trace_id():
    return secrets.token_hex(16)


def new_span_id():
    return secrets.token_hex(8)


def make_span(
    trace_id,
    name,
    kind,
    attributes=None,
    parent_span_id=None,
    links=None,
    status_code=0,
    status_message=""
):
    span = {
        "traceId": trace_id,
        "spanId": new_span_id(),
        "name": name,
        "kind": kind,
        "startTimeUnixNano": "0",
        "endTimeUnixNano": "1",
        "attributes": [
            {"key": key, "value": {"stringValue": value}}
            if isinstance(value, str)
            else {"key": key, "value": {"intValue": value}}
            for key, value in (attributes or {}).items()
        ],
        "status": {
            "code": status_code,
            "message": status_message
        }
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
                            "name": "incident-response"
                        },
                        "spans": spans
                    }
                ]
            }
        ]
    }
