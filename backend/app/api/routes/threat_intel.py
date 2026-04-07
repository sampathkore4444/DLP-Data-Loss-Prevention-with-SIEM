from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.models.models import User
from app.services.detection.threat_intel import threat_intel_service, IOCType
import json

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("/check/{indicator}")
async def check_indicator(
    indicator: str,
    ioc_type: str = None,
    current_user: User = Depends(get_current_user)
):
    result = threat_intel_service.enrich_indicator(indicator, ioc_type)
    return {
        "indicator": result.ioc,
        "type": result.ioc_type,
        "verdict": result.verdict,
        "severity": result.severity,
        "confidence": result.confidence,
        "metadata": result.metadata,
        "description": result.description
    }


@router.get("/iocs")
async def get_iocs(
    ioc_type: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    itype = IOCType(ioc_type) if ioc_type else None
    return threat_intel_service.get_all_iocs(itype, limit)


@router.post("/iocs")
async def add_ioc(
    type: str,
    value: str,
    severity: str = "medium",
    source: str = "manual",
    tags: list = None,
    current_user: User = Depends(get_current_user)
):
    from app.services.detection.threat_intel import IOC, ThreatSeverity
    
    ioc = IOC(
        type=IOCType(type),
        value=value,
        severity=ThreatSeverity(severity),
        source=source,
        confidence=80,
        first_seen=datetime.now().isoformat(),
        last_seen=datetime.now().isoformat(),
        tags=tags or []
    )
    threat_intel_service.add_ioc(ioc)
    return {"status": "added"}


@router.get("/feeds")
async def get_feeds(current_user: User = Depends(get_current_user)):
    return threat_intel_service.get_feeds()


@router.post("/feeds/{feed_id}/enable")
async def enable_feed(
    feed_id: str,
    current_user: User = Depends(get_current_user)
):
    success = threat_intel_service.enable_feed(feed_id)
    return {"status": "enabled" if success else "not_found"}


@router.post("/feeds/{feed_id}/disable")
async def disable_feed(
    feed_id: str,
    current_user: User = Depends(get_current_user)
):
    success = threat_intel_service.disable_feed(feed_id)
    return {"status": "disabled" if success else "not_found"}


@router.get("/stix/export")
async def export_stix(current_user: User = Depends(get_current_user)):
    return threat_intel_service.export_stix()


@router.post("/stix/import")
async def import_stix(
    bundle: dict,
    current_user: User = Depends(get_current_user)
):
    count = threat_intel_service.import_stix(bundle)
    return {"status": "imported", "count": count}


from datetime import datetime
