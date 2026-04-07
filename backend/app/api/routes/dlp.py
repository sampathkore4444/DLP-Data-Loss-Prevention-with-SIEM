from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.opensearch import get_opensearch
from app.models.models import User, DLPPolicy, DLEvent, Incident, IncidentSeverity, IncidentStatus
from app.schemas.schemas import (
    DLPPolicyCreate, DLPPolicyUpdate, DLPPolicyResponse, 
    DLEventResponse, IncidentCreate, IncidentUpdate, IncidentResponse
)

router = APIRouter(prefix="/dlp", tags=["DLP"])


@router.get("/policies", response_model=List[DLPPolicyResponse])
async def get_policies(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLPPolicy).order_by(DLPPolicy.priority))
    return result.scalars().all()


@router.post("/policies", response_model=DLPPolicyResponse)
async def create_policy(
    policy: DLPPolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLPPolicy).where(DLPPolicy.name == policy.name))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy name already exists"
        )
    
    db_policy = DLPPolicy(
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        priority=policy.priority,
        data_type=policy.data_type,
        channel=policy.channel,
        pattern=policy.pattern,
        action=policy.action,
        severity=policy.severity,
        created_by=current_user.id
    )
    db.add(db_policy)
    await db.commit()
    await db.refresh(db_policy)
    return db_policy


@router.get("/policies/{policy_id}", response_model=DLPPolicyResponse)
async def get_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLPPolicy).where(DLPPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/policies/{policy_id}", response_model=DLPPolicyResponse)
async def update_policy(
    policy_id: int,
    policy: DLPPolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLPPolicy).where(DLPPolicy.id == policy_id))
    db_policy = result.scalar_one_or_none()
    if not db_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    for field, value in policy.model_dump(exclude_unset=True).items():
        setattr(db_policy, field, value)
    
    await db.commit()
    await db.refresh(db_policy)
    return db_policy


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLPPolicy).where(DLPPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    await db.delete(policy)
    await db.commit()
    return {"message": "Policy deleted successfully"}


@router.get("/events", response_model=List[DLEventResponse])
async def get_events(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    channel: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(DLEvent).order_by(DLEvent.timestamp.desc())
    
    if severity:
        query = query.where(DLEvent.severity == severity)
    if channel:
        query = query.where(DLEvent.channel == channel)
    if status:
        query = query.where(DLEvent.status == status)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/events/{event_id}", response_model=DLEventResponse)
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLEvent).where(DLEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/events/{event_id}/create-incident", response_model=IncidentResponse)
async def create_incident_from_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(DLEvent).where(DLEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    count_result = await db.execute(select(func.count(Incident.id)))
    incident_count = count_result.scalar() or 0
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{incident_count + 1:04d}"
    
    incident = Incident(
        incident_id=incident_id,
        title=f"DLP Alert: {event.data_type} detected via {event.channel}",
        description=event.details,
        severity=IncidentSeverity[event.severity.upper()] if event.severity else IncidentSeverity.MEDIUM,
        source="dlp",
        assigned_to=current_user.id
    )
    event.status = "investigating"
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/stats/summary")
async def get_dlp_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_result = await db.execute(select(func.count(DLEvent.id)))
    total_events = total_result.scalar() or 0
    
    today_result = await db.execute(
        select(func.count(DLEvent.id)).where(DLEvent.timestamp >= today)
    )
    today_events = today_result.scalar() or 0
    
    by_severity = {}
    severity_result = await db.execute(
        select(DLEvent.severity, func.count(DLEvent.id)).group_by(DLEvent.severity)
    )
    for row in severity_result:
        by_severity[row[0]] = row[1]
    
    by_channel = {}
    channel_result = await db.execute(
        select(DLEvent.channel, func.count(DLEvent.id)).group_by(DLEvent.channel)
    )
    for row in channel_result:
        by_channel[row[0]] = row[1]
    
    by_action = {}
    action_result = await db.execute(
        select(DLEvent.action, func.count(DLEvent.id)).group_by(DLEvent.action)
    )
    for row in action_result:
        by_action[row[0]] = row[1]
    
    return {
        "total_events": total_events,
        "events_today": today_events,
        "by_severity": by_severity,
        "by_channel": by_channel,
        "by_action": by_action
    }


@router.post("/test-pattern")
async def test_pattern(
    pattern: str,
    content: str,
    current_user: User = Depends(get_current_user)
):
    import re
    try:
        regex = re.compile(pattern)
        matches = regex.findall(content)
        return {"valid": True, "matches": matches, "count": len(matches)}
    except Exception as e:
        return {"valid": False, "error": str(e)}
