from fastapi import FastAPI, Header, HTTPException

from database import (
    DatabaseConflict,
    get_incident,
    initialize_database,
)
from incident_engine import start_incident, process_receipt
from models import IncidentRequest, ReceiptRequest


app = FastAPI(title="Observable Incident Triage")


@app.on_event("startup")
def startup():
    initialize_database()


@app.post("/v2/incidents")
def create_incident(
    request: IncidentRequest,
    traceparent: str | None = Header(default=None),
    tracestate: str | None = Header(default=None),
):
    try:
        return start_incident(
            request,
            traceparent=traceparent,
            tracestate=tracestate,
        )

    except DatabaseConflict:
        raise HTTPException(
            status_code=409,
            detail="Run ID already exists with different content.",
        )

    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Incident processing failed.",
        )


@app.get("/v2/incidents/{runId}")
def read_incident(runId: str):
    incident = get_incident(runId)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return incident["response"]


@app.post("/v2/incidents/{runId}/receipts")
def submit_receipt(runId: str, receipt: ReceiptRequest):
    try:
        return process_receipt(runId, receipt)

    except DatabaseConflict:
        raise HTTPException(
            status_code=409,
            detail="Receipt ID already exists with different content.",
        )

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Receipt processing failed.",
        )

