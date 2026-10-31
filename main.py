import logging

from fastapi import FastAPI, Header, HTTPException

from database import (
    DatabaseConflict,
    get_incident,
    initialize_database,
)
from incident_engine import start_incident, process_receipt
from models import IncidentRequest, ReceiptRequest


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            detail="Run ID already exists with different request content.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Incident processing failed")
        raise HTTPException(
            status_code=500,
            detail="Incident processing failed.",
        )


@app.get("/v2/incidents/{runId}")
def read_incident(runId: str):
    incident = get_incident(runId)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return incident


@app.post("/v2/incidents/{runId}/receipts")
def submit_receipt(runId: str, receipt: ReceiptRequest):
    try:
        return process_receipt(runId, receipt)
    except DatabaseConflict:
        raise HTTPException(
            status_code=409,
            detail="Receipt ID already exists with different content.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Receipt processing failed")
        raise HTTPException(
            status_code=500,
            detail="Receipt processing failed.",
        )


