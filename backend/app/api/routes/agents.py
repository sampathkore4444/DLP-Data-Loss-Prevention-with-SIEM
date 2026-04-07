from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User
from app.services.collectors.endpoint_agent import get_endpoint_agent
from app.services.collectors.network_sensor import get_network_sensor
from app.services.detection.ml_anomaly import get_ml_anomaly_detector
from app.services.soar.playbooks import soar_engine
from app.services.scheduler.custom_reports import report_builder, ReportFormat

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get("/endpoint/status")
async def get_endpoint_status(current_user: User = Depends(get_current_user)):
    agent = get_endpoint_agent()
    return agent.get_status()


@router.post("/endpoint/start")
async def start_endpoint_agent(
    paths: list = None,
    current_user: User = Depends(get_current_user)
):
    agent = get_endpoint_agent()
    
    def on_event(event):
        print(f"Endpoint Event: {event}")
    
    agent.register_callback(on_event)
    agent.start()
    
    if paths:
        for path in paths:
            agent.add_watch_path(path)
    
    return {"status": "started"}


@router.post("/endpoint/stop")
async def stop_endpoint_agent(current_user: User = Depends(get_current_user)):
    agent = get_endpoint_agent()
    agent.stop()
    return {"status": "stopped"}


@router.post("/endpoint/scan")
async def scan_endpoint_directory(
    directory: str,
    current_user: User = Depends(get_current_user)
):
    agent = get_endpoint_agent()
    events = agent.scan_directory(directory)
    return {
        "files_found": len(events),
        "events": [
            {
                "file_name": e.file_name,
                "file_path": e.file_path,
                "file_size": e.file_size,
                "channel": e.channel
            }
            for e in events[:100]
        ]
    }


@router.get("/network/status")
async def get_network_status(current_user: User = Depends(get_current_user)):
    sensor = get_network_sensor()
    return sensor.get_status()


@router.post("/network/start")
async def start_network_sensor(current_user: User = Depends(get_current_user)):
    sensor = get_network_sensor()
    
    def on_alert(alert, flow):
        print(f"Network Alert: {alert}")
    
    sensor.register_callback(on_alert)
    sensor.start()
    
    return {"status": "started"}


@router.post("/network/stop")
async def stop_network_sensor(current_user: User = Depends(get_current_user)):
    sensor = get_network_sensor()
    sensor.stop()
    return {"status": "stopped"}


@router.get("/network/flows")
async def get_network_flows(
    count: int = 100,
    current_user: User = Depends(get_current_user)
):
    sensor = get_network_sensor()
    return sensor.get_recent_flows(count)


@router.get("/ml/anomaly/rules")
async def get_anomaly_rules(current_user: User = Depends(get_current_user)):
    detector = get_ml_anomaly_detector()
    return {"enabled": True, "z_threshold": detector.Z_THRESHOLD}


@router.post("/ml/anomaly/train")
async def train_anomaly_baseline(
    user_id: str,
    historical_data: list,
    current_user: User = Depends(get_current_user)
):
    detector = get_ml_anomaly_detector()
    detector.train_baseline(user_id, historical_data)
    return {"status": "trained", "user_id": user_id}


@router.post("/ml/anomaly/detect")
async def detect_anomaly(event: dict, current_user: User = Depends(get_current_user)):
    detector = get_ml_anomaly_detector()
    alert = detector.detect_anomaly(event)
    if alert:
        return {
            "anomaly_detected": True,
            "user_id": alert.user_id,
            "type": alert.anomaly_type,
            "severity": alert.severity,
            "score": alert.score
        }
    return {"anomaly_detected": False}


@router.get("/ml/anomaly/history")
async def get_anomaly_history(
    user_id: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    detector = get_ml_anomaly_detector()
    return detector.get_anomaly_history(user_id, limit)


@router.get("/ml/anomaly/user/{user_id}/baseline")
async def get_user_baseline(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    detector = get_ml_anomaly_detector()
    baseline = detector.get_user_baseline(user_id)
    if baseline:
        return baseline
    return {"error": "No baseline found for user"}


@router.get("/ml/anomaly/riskscores")
async def get_risk_scores(current_user: User = Depends(get_current_user)):
    detector = get_ml_anomaly_detector()
    return detector.get_all_user_scores()
