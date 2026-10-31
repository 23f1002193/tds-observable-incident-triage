from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class IncidentDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: List[str]


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    profile: str
    runId: str
    agentName: str
    publicMarker: str
    sensitive: Dict[str, Any]
    incident: IncidentDetails
    toolCatalog: List[Dict[str, Any]]
    policy: Dict[str, Any]


class ToolOutcome(BaseModel):
    model_config = ConfigDict(extra="allow")

    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: Optional[str] = None
    nonce: Optional[str] = None
    errorType: Optional[str] = None


class ApprovalOutcome(BaseModel):
    model_config = ConfigDict(extra="allow")

    approvalId: str
    decision: str
    nonce: str


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    receiptId: str
    outcomes: List[ToolOutcome] = Field(default_factory=list)
    approvals: List[ApprovalOutcome] = Field(default_factory=list)

