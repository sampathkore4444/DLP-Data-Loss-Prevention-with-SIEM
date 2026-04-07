from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User
from app.services.siem.correlation_engine import siem_engine
from app.services.websocket import websocket_endpoint, manager, notify_siem_alert
from app.services.collectors.syslog_collector import get_syslog_collector
from app.services.scheduler.reports import report_generator
from app.services.detection.dlp_engine import dlp_engine

router = APIRouter(prefix="/services", tags=["Services"])


@router.get("/correlation/rules")
async def get_correlation_rules(current_user: User = Depends(get_current_user)):
    return siem_engine.get_rules()


@router.post("/correlation/rules/{rule_id}/enable")
async def enable_correlation_rule(rule_id: str, current_user: User = Depends(get_current_user)):
    siem_engine.enable_rule(rule_id)
    return {"status": "enabled"}


@router.post("/correlation/rules/{rule_id}/disable")
async def disable_correlation_rule(rule_id: str, current_user: User = Depends(get_current_user)):
    siem_engine.disable_rule(rule_id)
    return {"status": "disabled"}


@router.get("/correlation/status")
async def get_correlation_status(current_user: User = Depends(get_current_user)):
    return siem_engine.get_buffer_status()


@router.get("/dlp/patterns")
async def get_dlp_patterns(current_user: User = Depends(get_current_user)):
    return dlp_engine.get_available_data_types()


@router.post("/dlp/scan")
async def scan_content(
    content: str,
    data_types: list = None,
    current_user: User = Depends(get_current_user)
):
    policies = []
    if data_types:
        for dt in data_types:
            policies.append({
                "id": 0,
                "name": f"scan_{dt}",
                "data_type": dt,
                "enabled": True,
                "pattern": "",
                "action": "block",
                "severity": "high"
            })
    matches = dlp_engine.scan_content(content, policies)
    return {
        "matches": [
            {
                "policy_name": m.policy_name,
                "data_type": m.data_type,
                "matched_value": m.matched_value,
                "action": m.action,
                "severity": m.severity
            }
            for m in matches
        ]
    }


@router.websocket("/ws")
async def websocket_route(websocket: WebSocket, channel: str = "all"):
    await websocket_endpoint(websocket, channel)


@router.get("/ws/status")
async def get_websocket_status():
    return {
        "total_connections": manager.get_connection_count(),
        "channels": {
            "dlp": manager.get_channel_count("dlp"),
            "siem": manager.get_channel_count("siem"),
            "incidents": manager.get_channel_count("incidents"),
            "all": manager.get_channel_count("all")
        }
    }


@router.post("/syslog/start")
async def start_syslog_collector(
    host: str = "0.0.0.0",
    port: int = 514,
    protocol: str = "udp",
    current_user: User = Depends(get_current_user)
):
    collector = get_syslog_collector()
    collector.host = host
    collector.port = port
    collector.protocol = protocol
    
    def on_event(event):
        siem_engine.process_event(event)
    
    collector.register_callback(on_event)
    collector.start()
    
    return {"status": "started", "host": host, "port": port}


@router.post("/syslog/stop")
async def stop_syslog_collector(current_user: User = Depends(get_current_user)):
    collector = get_syslog_collector()
    collector.stop()
    return {"status": "stopped"}


@router.get("/syslog/events")
async def get_syslog_events(count: int = 100, current_user: User = Depends(get_current_user)):
    collector = get_syslog_collector()
    return collector.get_recent_events(count)


@router.get("/reports/configs")
async def get_report_configs(current_user: User = Depends(get_current_user)):
    return report_generator.get_report_configs()


@router.post("/reports/generate")
async def generate_report(
    report_type: str,
    days: int = 1,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        report = await report_generator.generate_report(report_type, db, days)
        saved_path = await report_generator.save_report_to_minio(report, report_type)
        return {
            "title": report.title,
            "summary": report.summary,
            "saved_to": saved_path,
            "generated_at": report.generated_at.isoformat()
        }
    except Exception as e:
        return {"error": str(e)}
