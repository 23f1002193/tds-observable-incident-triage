from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    profile: str
    runId: str
    agentName: str
    publicMarker: str
    sensitive: Dict[str, Any]
    transcript: List[Dict[str, Any]]
    allowedRootCauses: List[str]
    toolCatalog: List[Dict[str, Any]]
    policy: Dict[str, Any]


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    receiptId: str
    actionId: str
    callId: str
    status: Optional[int] = None
    errorType: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    approvalId: Optional[str] = None
    approvalNonce: Optional[str] = None
