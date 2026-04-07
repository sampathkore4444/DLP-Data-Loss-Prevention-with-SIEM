from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, timedelta
import json

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.opensearch import get_opensearch
from app.models.models import User, SIEMEvent, Incident, IncidentSeverity, IncidentStatus
from app.schemas.schemas import SIEMEventResponse, IncidentCreate, IncidentUpdate, IncidentResponse

router = APIRouter(prefix="/siem", tags=["SIEM"])


@router.get("/events", response_model=List[SIEMEventResponse])
async def get_events(
    skip: int = 0,
    limit: int = 100,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(SIEMEvent).order_by(SIEMEvent.timestamp.desc())
    
    if source:
        query = query.where(SIEMEvent.source == source)
    if event_type:
        query = query.where(SIEMEvent.event_type == event_type)
    if severity:
        query = query.where(SIEMEvent.severity == severity)
    if start_time:
        query = query.where(SIEMEvent.timestamp >= start_time)
    if end_time:
        query = query.where(SIEMEvent.timestamp <= end_time)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/events/{event_id}", response_model=SIEMEventResponse)
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(SIEMEvent).where(SIEMEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/events", response_model=SIEMEventResponse)
async def create_event(
    event: SIEMEventResponse,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_event = SIEMEvent(
        source=event.source,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        event_type=event.event_type,
        severity=event.severity,
        message=event.message,
        raw_log=event.raw_log,
        user=event.user,
        hostname=event.hostname,
        details=event.details
    )
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)
    return db_event


@router.get("/events/search")
async def search_events(
    query: str = Query(..., description="Search query"),
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    client = get_opensearch()
    try:
        response = client.search(
            index="securevault-logs",
            body={
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["message", "event_type", "source", "user"]
                    }
                },
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
        )
        return {
            "total": response["hits"]["total"]["value"],
            "events": [hit["_source"] for hit in response["hits"]["hits"]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sources")
async def get_sources(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(SIEMEvent.source, func.count(SIEMEvent.id))
        .group_by(SIEMEvent.source)
    )
    sources = {}
    for row in result:
        sources[row[0]] = row[1]
    return sources


@router.get("/event-types")
async def get_event_types(
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(SIEMEvent.event_type, func.count(SIEMEvent.id))
    if source:
        query = query.where(SIEMEvent.source == source)
    query = query.group_by(SIEMEvent.event_type)
    
    result = await db.execute(query)
    types = {}
    for row in result:
        types[row[0]] = row[1]
    return types


@router.get("/stats/summary")
async def get_siem_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_result = await db.execute(select(func.count(SIEMEvent.id)))
    total_events = total_result.scalar() or 0
    
    today_result = await db.execute(
        select(func.count(SIEMEvent.id)).where(SIEMEvent.timestamp >= today)
    )
    today_events = today_result.scalar() or 0
    
    by_severity = {}
    severity_result = await db.execute(
        select(SIEMEvent.severity, func.count(SIEMEvent.id)).group_by(SIEMEvent.severity)
    )
    for row in severity_result:
        by_severity[row[0]] = row[1]
    
    by_source = {}
    source_result = await db.execute(
        select(SIEMEvent.source, func.count(SIEMEvent.id)).group_by(SIEMEvent.source)
    )
    for row in source_result:
        by_source[row[0]] = row[1]
    
    return {
        "total_events": total_events,
        "events_today": today_events,
        "by_severity": by_severity,
        "by_source": by_source
    }


@router.post("/syslog")
async def receive_syslog(
    message: str,
    source_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    client = get_opensearch()
    doc = {
        "timestamp": datetime.now().isoformat(),
        "source": "syslog",
        "source_ip": source_ip,
        "hostname": hostname,
        "message": message,
        "event_type": "syslog",
        "raw": message
    }
    client.index(index="securevault-logs", body=doc)
    return {"status": "received"}


@router.get("/logs")
async def get_logs(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    source: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    client = get_opensearch()
    
    must = []
    if start_time or end_time:
        range_filter = {"range": {"timestamp": {}}}
        if start_time:
            range_filter["range"]["timestamp"]["gte"] = start_time.isoformat()
        if end_time:
            range_filter["range"]["timestamp"]["lte"] = end_time.isoformat()
        must.append(range_filter)
    if source:
        must.append({"term": {"source": source}})
    if level:
        must.append({"term": {"level": level}})
    
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    
    try:
        response = client.search(
            index="securevault-logs",
            body={
                "query": query,
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
        )
        return {
            "total": response["hits"]["total"]["value"],
            "logs": [hit["_source"] for hit in response["hits"]["hits"]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
