from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import asyncio
from datetime import datetime
from enum import Enum

class AlertType(str, Enum):
    DLP_ALERT = "dlp_alert"
    SIEM_ALERT = "siem_alert"
    INCIDENT = "incident"
    CORRELATION = "correlation"
    SYSTEM = "system"

class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.subscriptions: Dict[str, List[WebSocket]] = {
            "dlp": [],
            "siem": [],
            "incidents": [],
            "all": []
        }

    async def connect(self, websocket: WebSocket, channel: str = "all"):
        await websocket.accept()
        self.active_connections.append(websocket)
        
        if channel not in self.subscriptions:
            self.subscriptions[channel] = []
        self.subscriptions[channel].append(websocket)
        
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "channel": channel,
            "timestamp": datetime.now().isoformat()
        }, websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        
        for channel in self.subscriptions:
            if websocket in self.subscriptions[channel]:
                self.subscriptions[channel].remove(websocket)

    async def send_personal_message(self, message: Dict, websocket: WebSocket):
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            print(f"Error sending message: {e}")

    async def broadcast(self, message: Dict, channel: str = "all"):
        if channel == "all":
            connections = self.active_connections
        else:
            connections = self.subscriptions.get(channel, [])
        
        disconnected = []
        for connection in connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                disconnected.append(connection)
        
        for ws in disconnected:
            self.disconnect(ws)

    async def send_alert(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        message: str,
        details: Dict = None,
        channel: str = "all"
    ):
        alert = {
            "type": alert_type.value,
            "severity": severity.value,
            "title": title,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast(alert, channel)

    def get_connection_count(self) -> int:
        return len(self.active_connections)

    def get_channel_count(self, channel: str) -> int:
        return len(self.subscriptions.get(channel, []))


manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, channel: str = "all"):
    await manager.connect(websocket, channel)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    }, websocket)
                elif message.get("type") == "subscribe":
                    new_channel = message.get("channel", "all")
                    if new_channel in manager.subscriptions:
                        manager.subscriptions[new_channel].append(websocket)
                    await manager.send_personal_message({
                        "type": "subscribed",
                        "channel": new_channel
                    }, websocket)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def notify_dlp_alert(
    policy_name: str,
    user: str,
    channel: str,
    data_type: str,
    action: str,
    severity: str = "high"
):
    severity_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW
    }
    
    await manager.send_alert(
        alert_type=AlertType.DLP_ALERT,
        severity=severity_map.get(severity, AlertSeverity.MEDIUM),
        title=f"DLP Alert: {data_type} detected",
        message=f"Policy '{policy_name}' triggered by {user} via {channel}",
        details={
            "policy_name": policy_name,
            "user": user,
            "channel": channel,
            "data_type": data_type,
            "action": action
        },
        channel="dlp"
    )


async def notify_siem_alert(
    rule_name: str,
    description: str,
    severity: str,
    events: List[Dict] = None
):
    severity_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW,
        "info": AlertSeverity.INFO
    }
    
    await manager.send_alert(
        alert_type=AlertType.SIEM_ALERT,
        severity=severity_map.get(severity, AlertSeverity.MEDIUM),
        title=f"SIEM Alert: {rule_name}",
        message=description,
        details={
            "rule_name": rule_name,
            "event_count": len(events) if events else 0,
            "events": events
        },
        channel="siem"
    )


async def notify_incident_created(
    incident_id: str,
    title: str,
    severity: str,
    source: str
):
    severity_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW
    }
    
    await manager.send_alert(
        alert_type=AlertType.INCIDENT,
        severity=severity_map.get(severity, AlertSeverity.MEDIUM),
        title=f"New Incident: {incident_id}",
        message=title,
        details={
            "incident_id": incident_id,
            "source": source
        },
        channel="incidents"
    )
