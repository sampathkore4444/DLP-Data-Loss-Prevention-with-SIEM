from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    incidents = relationship("Incident", back_populates="assigned_user")


class DLPPolicy(Base):
    __tablename__ = "dlp_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=1)
    data_type = Column(String(50))  # credit_card, ssn, account_number, etc.
    channel = Column(String(50))    # email, web, usb, print, network
    pattern = Column(Text)           # regex pattern
    action = Column(String(20))      # allow, block, quarantine, notify
    severity = Column(String(20))    # critical, high, medium, low
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"))

    dlp_events = relationship("DLEvent", back_populates="policy")


class DLEvent(Base):
    __tablename__ = "dlp_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    policy_id = Column(Integer, ForeignKey("dlp_policies.id"))
    user = Column(String(100))
    source_ip = Column(String(45))
    destination = Column(String(255))
    channel = Column(String(50))
    action = Column(String(20))
    severity = Column(String(20))
    data_type = Column(String(50))
    file_name = Column(String(255))
    details = Column(Text)
    status = Column(String(20), default="new")  # new, investigated, resolved, false_positive

    policy = relationship("DLPPolicy", back_populates="dlp_events")
    incident = relationship("Incident", back_populates="dlp_event", uselist=False)


class SIEMEvent(Base):
    __tablename__ = "siem_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source = Column(String(100))        # firewall, endpoint, dlp, etc.
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    event_type = Column(String(100))
    severity = Column(String(20))
    message = Column(Text)
    raw_log = Column(Text)
    user = Column(String(100))
    hostname = Column(String(100))
    details = Column(Text)
    correlated = Column(Boolean, default=False)

    incident = relationship("Incident", back_populates="siem_events")


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(50), unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.NEW)
    source = Column(String(50))         # dlp, siem, manual
    assigned_to = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True))
    notes = Column(Text)

    assigned_user = relationship("User", back_populates="incidents")
    dlp_event = relationship("DLEvent", back_populates="incident", uselist=False)
    siem_events = relationship("SIEMEvent", back_populates="incident")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100))
    resource = Column(String(100))
    resource_id = Column(String(50))
    details = Column(Text)
    ip_address = Column(String(45))
