from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from datetime import datetime

from app.core.security import get_current_user
from app.models.models import User
from app.services.scheduler.custom_reports import report_builder, ReportFormat, CustomReport, ReportSection, ReportSectionType

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/custom")
async def get_custom_reports(current_user: User = Depends(get_current_user)):
    return report_builder.get_all_reports()


@router.post("/custom")
async def create_custom_report(
    name: str,
    description: str,
    sections: list,
    date_range: str = "last_7_days",
    format: str = "pdf",
    current_user: User = Depends(get_current_user)
):
    report_sections = []
    for i, s in enumerate(sections):
        report_sections.append(ReportSection(
            type=ReportSectionType(s.get("type", "summary")),
            title=s.get("title", ""),
            data_source=s.get("data_source", "dlp_events"),
            position=s.get("position", i)
        ))
    
    report = CustomReport(
        id=f"custom_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        name=name,
        description=description,
        sections=report_sections,
        date_range=date_range,
        format=ReportFormat(format)
    )
    
    created = report_builder.create_report(report)
    return {"id": created.id, "name": created.name}


@router.get("/custom/{report_id}")
async def get_custom_report(report_id: str, current_user: User = Depends(get_current_user)):
    report = report_builder.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report.id, "name": report.name, "sections": len(report.sections)}


@router.put("/custom/{report_id}")
async def update_custom_report(
    report_id: str,
    updates: dict,
    current_user: User = Depends(get_current_user)
):
    report = report_builder.update_report(report_id, updates)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "updated"}


@router.delete("/custom/{report_id}")
async def delete_custom_report(report_id: str, current_user: User = Depends(get_current_user)):
    success = report_builder.delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted"}


@router.post("/custom/{report_id}/generate")
async def generate_custom_report(
    report_id: str,
    start_date: str = None,
    end_date: str = None,
    current_user: User = Depends(get_current_user)
):
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None
    
    try:
        report_data = await report_builder.generate_report(report_id, start, end)
        return report_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/custom/{report_id}/download")
async def download_custom_report(
    report_id: str,
    format: str = "json",
    current_user: User = Depends(get_current_user)
):
    generated = report_builder.get_generated_reports(report_id, 1)
    if not generated:
        raise HTTPException(status_code=404, detail="No generated report found")
    
    report_data = generated[0]["data"]
    format_enum = ReportFormat(format.lower())
    
    content = report_builder.export_to_format(report_data, format_enum)
    
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={report_id}.{format}"}
    )


@router.get("/history")
async def get_report_history(
    report_id: str = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    return report_builder.get_generated_reports(report_id, limit)
