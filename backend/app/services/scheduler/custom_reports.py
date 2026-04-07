from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"
    JSON = "json"
    HTML = "html"


class ReportSectionType(str, Enum):
    SUMMARY = "summary"
    TABLE = "table"
    CHART = "chart"
    LIST = "list"
    METRICS = "metrics"


@dataclass
class ReportSection:
    type: ReportSectionType
    title: str
    data_source: str
    filters: Dict = field(default_factory=dict)
    columns: List[str] = field(default_factory=list)
    chart_type: str = "bar"
    position: int = 0


@dataclass
class CustomReport:
    id: str
    name: str
    description: str
    sections: List[ReportSection]
    date_range: str
    format: ReportFormat
    schedule: str = None
    recipients: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = None
    last_generated: str = None


class ReportBuilder:
    PREDEFINED_REPORTS = [
        CustomReport(
            id="dlp_summary",
            name="DLP Summary Report",
            description="Overview of DLP events and violations",
            sections=[
                ReportSection(ReportSectionType.SUMMARY, "Total Events", "dlp_events", position=0),
                ReportSection(ReportSectionType.METRICS, "Key Metrics", "dlp_events", position=1),
                ReportSection(ReportSectionType.CHART, "Events by Channel", "dlp_events", {"chart_type": "pie"}, position=2),
                ReportSection(ReportSectionType.TABLE, "Recent Violations", "dlp_events", {}, ["timestamp", "user", "data_type", "action"], position=3),
            ],
            date_range="last_7_days",
            format=ReportFormat.PDF
        ),
        CustomReport(
            id="security_incidents",
            name="Security Incident Report",
            description="Summary of security incidents",
            sections=[
                ReportSection(ReportSectionType.SUMMARY, "Total Incidents", "incidents", position=0),
                ReportSection(ReportSectionType.METRICS, "By Severity", "incidents", position=1),
                ReportSection(ReportSectionType.TABLE, "Open Incidents", "incidents", {"status": "open"}, ["incident_id", "title", "severity", "created_at"], position=2),
            ],
            date_range="last_30_days",
            format=ReportFormat.PDF
        ),
        CustomReport(
            id="compliance_status",
            name="Compliance Status Report",
            description="PCI-DSS and GDPR compliance status",
            sections=[
                ReportSection(ReportSectionType.METRICS, "PCI-DSS", "compliance", position=0),
                ReportSection(ReportSectionType.METRICS, "GDPR", "compliance", position=1),
                ReportSection(ReportSectionType.LIST, "Violations", "compliance", position=2),
            ],
            date_range="last_30_days",
            format=ReportFormat.PDF
        ),
    ]

    def __init__(self):
        self.reports: Dict[str, CustomReport] = {r.id: r for r in self.PREDEFINED_REPORTS}
        self.generated_reports = []
        self.data_sources: Dict[str, Callable] = {}

    def register_data_source(self, name: str, callback: Callable):
        self.data_sources[name] = callback

    def create_report(self, report: CustomReport):
        report.id = report.id or f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        report.created_at = datetime.now().isoformat()
        self.reports[report.id] = report
        return report

    def get_report(self, report_id: str) -> Optional[CustomReport]:
        return self.reports.get(report_id)

    def get_all_reports(self) -> List[Dict]:
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "sections": [
                    {"type": s.type.value, "title": s.title, "data_source": s.data_source}
                    for s in r.sections
                ],
                "date_range": r.date_range,
                "format": r.format.value,
                "schedule": r.schedule,
                "enabled": r.enabled,
                "created_at": r.created_at,
                "last_generated": r.last_generated
            }
            for r in self.reports.values()
        ]

    def update_report(self, report_id: str, updates: Dict) -> Optional[CustomReport]:
        if report_id not in self.reports:
            return None
        
        report = self.reports[report_id]
        
        if "name" in updates:
            report.name = updates["name"]
        if "description" in updates:
            report.description = updates["description"]
        if "sections" in updates:
            report.sections = updates["sections"]
        if "date_range" in updates:
            report.date_range = updates["date_range"]
        if "schedule" in updates:
            report.schedule = updates["schedule"]
        if "enabled" in updates:
            report.enabled = updates["enabled"]
        
        return report

    def delete_report(self, report_id: str) -> bool:
        if report_id in self.reports:
            del self.reports[report_id]
            return True
        return False

    async def generate_report(self, report_id: str, start_date: datetime = None, end_date: datetime = None) -> Dict:
        report = self.reports.get(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")
        
        start_date = start_date or (datetime.now() - timedelta(days=7))
        end_date = end_date or datetime.now()
        
        report_data = {
            "report_id": report.id,
            "report_name": report.name,
            "generated_at": datetime.now().isoformat(),
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "sections": []
        }
        
        for section in sorted(report.sections, key=lambda s: s.position):
            section_data = await self._generate_section(section, start_date, end_date)
            report_data["sections"].append({
                "type": section.type.value,
                "title": section.title,
                "data": section_data
            })
        
        report.last_generated = datetime.now().isoformat()
        
        self.generated_reports.append({
            "report_id": report.id,
            "generated_at": report_data["generated_at"],
            "data": report_data
        })
        
        return report_data

    async def _generate_section(self, section: ReportSection, start_date: datetime, end_date: datetime) -> Dict:
        data_source = section.data_source
        
        if data_source == "dlp_events":
            return await self._generate_dlp_section(section, start_date, end_date)
        elif data_source == "incidents":
            return await self._generate_incidents_section(section, start_date, end_date)
        elif data_source == "compliance":
            return await self._generate_compliance_section(section, start_date, end_date)
        elif data_source == "siem_events":
            return await self._generate_siem_section(section, start_date, end_date)
        else:
            return {"data": [], "summary": {}}

    async def _generate_dlp_section(self, section: ReportSection, start_date: datetime, end_date: datetime) -> Dict:
        sample_data = [
            {"timestamp": "2026-04-07", "user": "john.doe", "data_type": "credit_card", "channel": "email", "action": "block"},
            {"timestamp": "2026-04-07", "user": "jane.smith", "data_type": "ssn", "channel": "usb", "action": "quarantine"},
            {"timestamp": "2026-04-06", "user": "bob.jones", "data_type": "account_number", "channel": "web", "action": "notify"},
        ]
        
        if section.type == ReportSectionType.SUMMARY:
            return {"total_events": len(sample_data), "block_actions": 1, "quarantine_actions": 1}
        elif section.type == ReportSectionType.METRICS:
            return {"total": len(sample_data), "by_action": {"block": 1, "quarantine": 1, "notify": 1}}
        elif section.type == ReportSectionType.CHART:
            return {"labels": ["Email", "USB", "Web", "Print"], "values": [10, 5, 15, 2]}
        elif section.type == ReportSectionType.TABLE:
            return {"columns": section.columns or ["timestamp", "user", "data_type", "action"], "rows": sample_data}
        
        return {"data": sample_data}

    async def _generate_incidents_section(self, section: ReportSection, start_date: datetime, end_date: datetime) -> Dict:
        sample_data = [
            {"incident_id": "INC-20260407-0001", "title": "Credit card data exfiltration", "severity": "critical", "status": "investigating"},
            {"incident_id": "INC-20260407-0002", "title": "Unauthorized USB access", "severity": "high", "status": "new"},
        ]
        
        if section.type == ReportSectionType.SUMMARY:
            return {"total_incidents": len(sample_data), "open": 2, "resolved": 0}
        elif section.type == ReportSectionType.METRICS:
            return {"critical": 1, "high": 1, "medium": 0, "low": 0}
        elif section.type == ReportSectionType.TABLE:
            return {"columns": ["incident_id", "title", "severity", "status"], "rows": sample_data}
        
        return {"data": sample_data}

    async def _generate_compliance_section(self, section: ReportSection, start_date: datetime, end_date: datetime) -> Dict:
        if section.type == ReportSectionType.METRICS:
            return {
                "pci_dss": {"compliant": True, "score": 95, "requirements_met": 11, "total": 12},
                "gdpr": {"compliant": True, "score": 88, "requirements_met": 22, "total": 25}
            }
        
        return {"data": []}

    async def _generate_siem_section(self, section: ReportSection, start_date: datetime, end_date: datetime) -> Dict:
        sample_data = [
            {"timestamp": "2026-04-07", "source": "firewall", "event_type": "connection", "severity": "info"},
            {"timestamp": "2026-04-07", "source": "sshd", "event_type": "authentication_failure", "severity": "warning"},
        ]
        
        if section.type == ReportSectionType.SUMMARY:
            return {"total_events": len(sample_data)}
        
        return {"data": sample_data}

    def export_to_format(self, report_data: Dict, format: ReportFormat) -> bytes:
        if format == ReportFormat.JSON:
            return json.dumps(report_data, indent=2).encode('utf-8')
        elif format == ReportFormat.HTML:
            return self._generate_html(report_data)
        else:
            return json.dumps(report_data, indent=2).encode('utf-8')

    def _generate_html(self, report_data: Dict) -> bytes:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{report_data.get('report_name', 'Report')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 1px solid #ccc; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #1890ff; color: white; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>{report_data.get('report_name', 'Report')}</h1>
    <p>Generated: {report_data.get('generated_at', '')}</p>
"""
        for section in report_data.get("sections", []):
            html += f"<h2>{section.get('title', '')}</h2>\n"
            if section.get("data"):
                html += f"<pre>{json.dumps(section['data'], indent=2)}</pre>\n"
        
        html += "</body></html>"
        return html.encode('utf-8')

    def get_generated_reports(self, report_id: str = None, limit: int = 50) -> List[Dict]:
        reports = self.generated_reports
        if report_id:
            reports = [r for r in reports if r["report_id"] == report_id]
        return reports[-limit:]


report_builder = ReportBuilder()
