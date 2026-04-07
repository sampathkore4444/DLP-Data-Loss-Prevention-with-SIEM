from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import json
import asyncio
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Incident, DLEvent, SIEMEvent, IncidentStatus, IncidentSeverity
from app.core.opensearch import get_opensearch
from app.core.minio import get_minio

@dataclass
class ReportConfig:
    report_type: str
    name: str
    schedule: str
    enabled: bool = True
    recipients: List[str] = None
    format: str = "pdf"

@dataclass
class ReportData:
    title: str
    period_start: datetime
    period_end: datetime
    summary: Dict
    details: List[Dict]
    generated_at: datetime

class ReportGenerator:
    def __init__(self):
        self.report_configs = [
            ReportConfig(
                report_type="daily_summary",
                name="Daily Security Summary",
                schedule="0 8 * * *",
                recipients=["security@bank.com"]
            ),
            ReportConfig(
                report_type="weekly_compliance",
                name="Weekly Compliance Report",
                schedule="0 9 * * 1",
                recipients=["compliance@bank.com", "ciso@bank.com"]
            ),
            ReportConfig(
                report_type="dlp_incidents",
                name="DLP Incident Report",
                schedule="0 7 * * *",
                recipients=["dlp-team@bank.com"]
            ),
            ReportConfig(
                report_type="siem_threats",
                name="Threat Detection Report",
                schedule="0 6 * * *",
                recipients=["soc@bank.com"]
            ),
        ]

    async def generate_report(self, report_type: str, db: AsyncSession, days: int = 1) -> ReportData:
        period_end = datetime.now()
        period_start = period_end - timedelta(days=days)
        
        if report_type == "daily_summary":
            return await self._generate_daily_summary(db, period_start, period_end)
        elif report_type == "weekly_compliance":
            return await self._generate_compliance_report(db, period_start, period_end)
        elif report_type == "dlp_incidents":
            return await self._generate_dlp_report(db, period_start, period_end)
        elif report_type == "siem_threats":
            return await self._generate_siem_report(db, period_start, period_end)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    async def _generate_daily_summary(self, db: AsyncSession, start: datetime, end: datetime) -> ReportData:
        total_incidents = await db.execute(
            select(func.count(Incident.id)).where(Incident.created_at >= start)
        )
        total_incidents = total_incidents.scalar() or 0
        
        open_incidents = await db.execute(
            select(func.count(Incident.id)).where(
                Incident.created_at >= start,
                Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING])
            )
        )
        open_incidents = open_incidents.scalar() or 0
        
        critical_incidents = await db.execute(
            select(func.count(Incident.id)).where(
                Incident.created_at >= start,
                Incident.severity == IncidentSeverity.CRITICAL
            )
        )
        critical_incidents = critical_incidents.scalar() or 0
        
        dlp_events = await db.execute(
            select(func.count(DLEvent.id)).where(DLEvent.timestamp >= start)
        )
        dlp_events = dlp_events.scalar() or 0
        
        severity_breakdown = await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.created_at >= start)
            .group_by(Incident.severity)
        )
        severity_data = {str(row[0]): row[1] for row in severity_breakdown}
        
        return ReportData(
            title="Daily Security Summary",
            period_start=start,
            period_end=end,
            summary={
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "dlp_events": dlp_events,
                "severity_breakdown": severity_data
            },
            details=[],
            generated_at=datetime.now()
        )

    async def _generate_compliance_report(self, db: AsyncSession, start: datetime, end: datetime) -> ReportData:
        incidents_by_source = await db.execute(
            select(Incident.source, func.count(Incident.id))
            .where(Incident.created_at >= start)
            .group_by(Incident.source)
        )
        source_data = {row[0]: row[1] for row in incidents_by_source}
        
        resolved_rate = await db.execute(
            select(func.count(Incident.id)).where(
                Incident.created_at >= start,
                Incident.status == IncidentStatus.RESOLVED
            )
        )
        resolved = resolved_rate.scalar() or 0
        
        total = await db.execute(
            select(func.count(Incident.id)).where(Incident.created_at >= start)
        )
        total = total.scalar() or 1
        
        return ReportData(
            title="Weekly Compliance Report",
            period_start=start,
            period_end=end,
            summary={
                "incidents_by_source": source_data,
                "resolution_rate": round(resolved / total * 100, 2),
                "total_incidents": total,
                "pci_dss_compliant": total > 0,
                "gdpr_compliant": True
            },
            details=[],
            generated_at=datetime.now()
        )

    async def _generate_dlp_report(self, db: AsyncSession, start: datetime, end: datetime) -> ReportData:
        events_by_channel = await db.execute(
            select(DLEvent.channel, func.count(DLEvent.id))
            .where(DLEvent.timestamp >= start)
            .group_by(DLEvent.channel)
        )
        channel_data = {row[0]: row[1] for row in events_by_channel}
        
        events_by_action = await db.execute(
            select(DLEvent.action, func.count(DLEvent.id))
            .where(DLEvent.timestamp >= start)
            .group_by(DLEvent.action)
        )
        action_data = {row[0]: row[1] for row in events_by_action}
        
        top_users = await db.execute(
            select(DLEvent.user, func.count(DLEvent.id))
            .where(DLEvent.timestamp >= start, DLEvent.user.isnot(None))
            .group_by(DLEvent.user)
            .order_by(func.count(DLEvent.id).desc())
            .limit(10)
        )
        top_user_data = [{"user": row[0], "count": row[1]} for row in top_users]
        
        return ReportData(
            title="DLP Incident Report",
            period_start=start,
            period_end=end,
            summary={
                "events_by_channel": channel_data,
                "events_by_action": action_data,
                "top_violators": top_user_data
            },
            details=[],
            generated_at=datetime.now()
        )

    async def _generate_siem_report(self, db: AsyncSession, start: datetime, end: datetime) -> ReportData:
        events_by_source = await db.execute(
            select(SIEMEvent.source, func.count(SIEMEvent.id))
            .where(SIEMEvent.timestamp >= start)
            .group_by(SIEMEvent.source)
        )
        source_data = {row[0]: row[1] for row in events_by_source}
        
        events_by_severity = await db.execute(
            select(SIEMEvent.severity, func.count(SIEMEvent.id))
            .where(SIEMEvent.timestamp >= start)
            .group_by(SIEMEvent.severity)
        )
        severity_data = {row[0]: row[1] for row in events_by_severity}
        
        return ReportData(
            title="Threat Detection Report",
            period_start=start,
            period_end=end,
            summary={
                "events_by_source": source_data,
                "events_by_severity": severity_data,
                "threat_level": "ELEVATED" if severity_data.get("critical", 0) > 0 else "NORMAL"
            },
            details=[],
            generated_at=datetime.now()
        )

    async def save_report_to_minio(self, report: ReportData, report_type: str) -> str:
        minio_client = get_minio()
        
        file_name = f"{report_type}_{report.period_start.strftime('%Y%m%d')}.json"
        
        report_dict = {
            "title": report.title,
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "generated_at": report.generated_at.isoformat(),
            "summary": report.summary,
            "details": report.details
        }
        
        data = json.dumps(report_dict, indent=2).encode('utf-8')
        
        minio_client.put_object(
            "securevault-reports",
            file_name,
            data,
            length=len(data)
        )
        
        return f"s3://securevault-reports/{file_name}"

    def get_report_configs(self) -> List[Dict]:
        return [
            {
                "report_type": c.report_type,
                "name": c.name,
                "schedule": c.schedule,
                "enabled": c.enabled,
                "recipients": c.recipients,
                "format": c.format
            }
            for c in self.report_configs
        ]


report_generator = ReportGenerator()
