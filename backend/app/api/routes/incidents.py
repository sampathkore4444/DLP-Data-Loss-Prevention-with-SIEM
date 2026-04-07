from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User, Incident, IncidentStatus, IncidentSeverity, DLEvent, SIEMEvent
from app.schemas.schemas import IncidentCreate, IncidentUpdate, IncidentResponse, DashboardStats

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentResponse])
async def get_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    source: Optional[str] = None,
    assigned_to: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Incident).options(
        selectinload(Incident.assigned_user),
        selectinload(Incident.dlp_event),
        selectinload(Incident.siem_events)
    ).order_by(Incident.created_at.desc())
    
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if source:
        query = query.where(Incident.source == source)
    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Incident).options(
            selectinload(Incident.assigned_user),
            selectinload(Incident.dlp_event),
            selectinload(Incident.siem_events)
        ).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("", response_model=IncidentResponse)
async def create_incident(
    incident: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    count_result = await db.execute(select(func.count(Incident.id)))
    incident_count = count_result.scalar() or 0
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{incident_count + 1:04d}"
    
    db_incident = Incident(
        incident_id=incident_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        source=incident.source,
        assigned_to=current_user.id
    )
    db.add(db_incident)
    await db.commit()
    await db.refresh(db_incident)
    return db_incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_update: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    update_data = incident_update.model_dump(exclude_unset=True)
    
    if "status" in update_data and update_data["status"] == IncidentStatus.RESOLVED:
        incident.resolved_at = datetime.now()
    
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    await db.commit()
    await db.refresh(incident)
    return incident


@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    await db.delete(incident)
    await db.commit()
    return {"message": "Incident deleted successfully"}


@router.get("/stats/dashboard")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_result = await db.execute(select(func.count(Incident.id)))
    total_incidents = total_result.scalar() or 0
    
    open_result = await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING])
        )
    )
    open_incidents = open_result.scalar() or 0
    
    resolved_result = await db.execute(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.RESOLVED)
    )
    resolved_incidents = resolved_result.scalar() or 0
    
    critical_result = await db.execute(
        select(func.count(Incident.id)).where(Incident.severity == IncidentSeverity.CRITICAL)
    )
    critical_incidents = critical_result.scalar() or 0
    
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    dlp_today_result = await db.execute(
        select(func.count(DLEvent.id)).where(DLEvent.timestamp >= today)
    )
    dlp_events_today = dlp_today_result.scalar() or 0
    
    siem_today_result = await db.execute(
        select(func.count(SIEMEvent.id)).where(SIEMEvent.timestamp >= today)
    )
    siem_events_today = siem_today_result.scalar() or 0
    
    severity_result = await db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    )
    incidents_by_severity = {row[0]: row[1] for row in severity_result}
    
    status_result = await db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    )
    incidents_by_status = {row[0]: row[1] for row in status_result}
    
    top_violators_result = await db.execute(
        select(DLEvent.user, func.count(DLEvent.id))
        .where(DLEvent.user.isnot(None))
        .group_by(DLEvent.user)
        .order_by(func.count(DLEvent.id).desc())
        .limit(5)
    )
    top_violators = [{"user": row[0], "count": row[1]} for row in top_violators_result]
    
    dlp_channel_result = await db.execute(
        select(DLEvent.channel, func.count(DLEvent.id)).group_by(DLEvent.channel)
    )
    dlp_events_by_channel = {row[0]: row[1] for row in dlp_channel_result}
    
    return DashboardStats(
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        resolved_incidents=resolved_incidents,
        critical_incidents=critical_incidents,
        dlp_events_today=dlp_events_today,
        siem_events_today=siem_events_today,
        top_violators=top_violators,
        incidents_by_severity=incidents_by_severity,
        incidents_by_status=incidents_by_status,
        dlp_events_by_channel=dlp_events_by_channel
    )


@router.get("/by-source")
async def get_incidents_by_source(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Incident.source, func.count(Incident.id))
        .group_by(Incident.source)
    )
    return {row[0]: row[1] for row in result}
