from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from app.models.models import UserRole, IncidentStatus, IncidentSeverity


class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class DLPPolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    priority: int = 1
    data_type: str
    channel: str
    pattern: str
    action: str  # allow, block, quarantine, notify
    severity: str


class DLPPolicyCreate(DLPPolicyBase):
    pass


class DLPPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    data_type: Optional[str] = None
    channel: Optional[str] = None
    pattern: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None


class DLPPolicyResponse(DLPPolicyBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by: Optional[int] = None

    class Config:
        from_attributes = True


class DLEventBase(BaseModel):
    policy_id: Optional[int] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination: Optional[str] = None
    channel: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    data_type: Optional[str] = None
    file_name: Optional[str] = None
    details: Optional[str] = None
    status: str = "new"


class DLEventResponse(DLEventBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


class SIEMEventBase(BaseModel):
    source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    message: Optional[str] = None
    raw_log: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    details: Optional[str] = None


class SIEMEventResponse(SIEMEventBase):
    id: int
    timestamp: datetime
    correlated: bool

    class Config:
        from_attributes = True


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    source: str


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[int] = None
    notes: Optional[str] = None


class IncidentResponse(IncidentBase):
    id: int
    incident_id: str
    status: IncidentStatus
    source: str
    assigned_to: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_incidents: int
    open_incidents: int
    resolved_incidents: int
    critical_incidents: int
    dlp_events_today: int
    siem_events_today: int
    top_violators: List[dict]
    incidents_by_severity: dict
    incidents_by_status: dict
    dlp_events_by_channel: dict
