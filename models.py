from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IncidentDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    incidentId: str = Field(min_length=1)
    title: str = Field(min_length=1)
    service: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    transcript: str
    allowedRootCauses: List[str] = Field(min_length=1)


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    profile: str
    runId: str = Field(min_length=8)
    agentName: str = Field(min_length=1)
    publicMarker: str = Field(min_length=1)
    sensitive: Dict[str, Any]
    incident: IncidentDetails
    toolCatalog: List[Dict[str, Any]]
    policy: Dict[str, Any]


class ToolOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actionId: str = Field(min_length=8)
    callId: str = Field(min_length=8)
    attempt: int = Field(ge=1)
    status: int = Field(ge=0)
    resultClass: Optional[str] = None
    nonce: Optional[str] = None
    errorType: Optional[str] = None


class ApprovalOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approvalId: str = Field(min_length=8)
    decision: str
    nonce: str = Field(min_length=1)


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receiptId: str = Field(min_length=8)
    outcomes: List[ToolOutcome] = Field(default_factory=list)
    approvals: List[ApprovalOutcome] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_receipt_type(self):
        if self.outcomes and self.approvals:
            raise ValueError(
                "A receipt cannot contain both tool outcomes and approvals"
            )

        if not self.outcomes and not self.approvals:
            raise ValueError(
                "A receipt must contain at least one outcome or approval"
            )

        return self


