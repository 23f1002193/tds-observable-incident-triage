from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from database import DatabaseConflict, get_incident, initialize_database
from incident_engine import start_incident
from models import IncidentRequest, ReceiptRequest

app = FastAPI(title="Observable Incident Triage")


@app.on_event("startup")
def startup():
    initialize_database()


@app.post("/v2/incidents")
def create_incident(request: IncidentRequest):
    try:
        return start_incident(request)
    except DatabaseConflict:
        raise HTTPException(
            status_code=409,
            detail="runId already exists with different request content"
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Incident processing failed"
        )


@app.get("/v2/incidents/{runId}")
def read_incident(runId: str):
    incident = get_incident(runId)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident["response"]


@app.post("/v2/incidents/{runId}/receipts")
def submit_receipt(runId: str, receipt: ReceiptRequest):
    # Receipt processing will be implemented next.
    raise HTTPException(
        status_code=501,
        detail="Receipt processing is not implemented yet"
    )
