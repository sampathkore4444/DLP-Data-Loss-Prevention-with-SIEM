from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import logging
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class ActionType(str, Enum):
    BLOCK_USER = "block_user"
    BLOCK_IP = "block_ip"
    BLOCK_DEVICE = "block_device"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    QUARANTINE_FILE = "quarantine_file"
    SEND_EMAIL = "send_email"
    CREATE_INCIDENT = "create_incident"
    ESCALATE = "escalate"
    ENABLE_MFA = "enable_mfa"
    RESET_PASSWORD = "reset_password"
    NOTIFY_MANAGER = "notify_manager"
    RUN_SCRIPT = "run_script"
    WEBHOOK = "webhook"
    LOG = "log"


@dataclass
class PlaybookAction:
    action_type: ActionType
    params: Dict = field(default_factory=dict)
    delay_seconds: int = 0
    condition: str = None


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    trigger_type: str
    conditions: Dict = field(default_factory=dict)
    actions: List[PlaybookAction] = field(default_factory=list)
    enabled: bool = True
    status: PlaybookStatus = PlaybookStatus.READY


@dataclass
class PlaybookExecution:
    playbook_id: str
    execution_id: str
    trigger_event: Dict
    status: str
    start_time: str
    end_time: str = None
    actions_executed: List[Dict] = field(default_factory=list)
    result: Dict = field(default_factory=dict)


class SOARPlaybookEngine:
    PREDEFINED_PLAYBOOKS = [
        Playbook(
            id="pb_dlp_critical",
            name="DLP Critical Response",
            description="Auto-block and notify on critical DLP alerts",
            trigger_type="dlp_alert",
            conditions={"severity": "critical"},
            actions=[
                PlaybookAction(ActionType.BLOCK_USER, {}),
                PlaybookAction(ActionType.QUARANTINE_FILE, {}),
                PlaybookAction(ActionType.CREATE_INCIDENT, {}),
                PlaybookAction(ActionType.NOTIFY_MANAGER, {}),
            ]
        ),
        Playbook(
            id="pb_brute_force",
            name="Brute Force Attack Response",
            description="Block IP and create incident on brute force",
            trigger_type="siem_alert",
            conditions={"rule_id": "brute_force_ssh"},
            actions=[
                PlaybookAction(ActionType.BLOCK_IP, {}),
                PlaybookAction(ActionType.CREATE_INCIDENT, {}),
                PlaybookAction(ActionType.SEND_EMAIL, {"recipients": ["soc@bank.com"]}),
            ]
        ),
        Playbook(
            id="pb_insider_threat",
            name="Insider Threat Response",
            description="Response to anomalous user behavior",
            trigger_type="anomaly_alert",
            conditions={"severity": "critical"},
            actions=[
                PlaybookAction(ActionType.ISOLATE_ENDPOINT, {}),
                PlaybookAction(ActionType.ENABLE_MFA, {}),
                PlaybookAction(ActionType.ESCALATE, {"level": "high"}),
                PlaybookAction(ActionType.CREATE_INCIDENT, {}),
            ]
        ),
        Playbook(
            id="pb_malware_detected",
            name="Malware Response",
            description="Isolate endpoint on malware detection",
            trigger_type="siem_alert",
            conditions={"event_type": "malware_detected"},
            actions=[
                PlaybookAction(ActionType.ISOLATE_ENDPOINT, {}),
                PlaybookAction(ActionType.CREATE_INCIDENT, {}),
                PlaybookAction(ActionType.RUN_SCRIPT, {"script": "scan_endpoint"}),
            ]
        ),
        Playbook(
            id="pb_data_exfiltration",
            name="Data Exfiltration Response",
            description="Block large data transfers",
            trigger_type="siem_alert",
            conditions={"rule_id": "data_exfiltration"},
            actions=[
                PlaybookAction(ActionType.BLOCK_USER, {}),
                PlaybookAction(ActionType.BLOCK_IP, {}),
                PlaybookAction(ActionType.ISOLATE_ENDPOINT, {}),
                PlaybookAction(ActionType.CREATE_INCIDENT, {}),
            ]
        ),
    ]

    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {p.id: p for p in self.PREDEFINED_PLAYBOOKS}
        self.executions: List[PlaybookExecution] = []
        self.callbacks: Dict[str, List[Callable]] = {
            "block_user": [],
            "block_ip": [],
            "create_incident": [],
            "send_email": [],
            "webhook": [],
        }

    def register_callback(self, action_type: str, callback: Callable):
        if action_type in self.callbacks:
            self.callbacks[action_type].append(callback)

    def add_playbook(self, playbook: Playbook):
        self.playbooks[playbook.id] = playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def get_all_playbooks(self) -> List[Dict]:
        return [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "trigger_type": p.trigger_type,
                "conditions": p.conditions,
                "enabled": p.enabled,
                "status": p.status.value,
                "actions": [
                    {"action_type": a.action_type.value, "params": a.params}
                    for a in p.actions
                ]
            }
            for p in self.playbooks.values()
        ]

    def enable_playbook(self, playbook_id: str):
        if playbook_id in self.playbooks:
            self.playbooks[playbook_id].enabled = True

    def disable_playbook(self, playbook_id: str):
        if playbook_id in self.playbooks:
            self.playbooks[playbook_id].enabled = False

    async def trigger(self, event_type: str, event_data: Dict) -> List[PlaybookExecution]:
        executed = []
        
        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue
            
            if playbook.trigger_type != event_type:
                continue
            
            if not self._matches_conditions(event_data, playbook.conditions):
                continue
            
            execution = await self._execute_playbook(playbook, event_data)
            executed.append(execution)
            self.executions.append(execution)
        
        if len(self.executions) > 1000:
            self.executions = self.executions[-500:]
        
        return executed

    def _matches_conditions(self, event_data: Dict, conditions: Dict) -> bool:
        for key, value in conditions.items():
            if key not in event_data:
                return False
            if event_data[key] != value:
                return False
        return True

    async def _execute_playbook(self, playbook: Playbook, event_data: Dict) -> PlaybookExecution:
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            execution_id=f"exec_{playbook.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            trigger_event=event_data,
            status=PlaybookStatus.RUNNING.value,
            start_time=datetime.now().isoformat()
        )
        
        playbook.status = PlaybookStatus.RUNNING
        
        for action in playbook.actions:
            result = await self._execute_action(action, event_data, execution)
            execution.actions_executed.append({
                "action_type": action.action_type.value,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            
            await asyncio.sleep(0.1)
        
        execution.status = PlaybookStatus.COMPLETED.value
        execution.end_time = datetime.now().isoformat()
        execution.result = {"success": True, "actions_count": len(playbook.actions)}
        
        playbook.status = PlaybookStatus.READY
        
        return execution

    async def _execute_action(self, action: PlaybookAction, event_data: Dict, execution: PlaybookExecution) -> Dict:
        action_type = action.action_type
        
        try:
            if action_type == ActionType.BLOCK_USER:
                user_id = event_data.get("user") or event_data.get("user_id")
                result = await self._block_user(user_id)
            
            elif action_type == ActionType.BLOCK_IP:
                ip = event_data.get("source_ip") or event_data.get("ip")
                result = await self._block_ip(ip)
            
            elif action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_incident(event_data, execution.execution_id)
            
            elif action_type == ActionType.SEND_EMAIL:
                result = await self._send_email(action.params, event_data)
            
            elif action_type == ActionType.NOTIFY_MANAGER:
                result = await self._notify_manager(event_data)
            
            elif action_type == ActionType.ESCALATE:
                result = await self._escalate(event_data, action.params)
            
            elif action_type == ActionType.QUARANTINE_FILE:
                result = await self._quarantine_file(event_data)
            
            elif action_type == ActionType.ISOLATE_ENDPOINT:
                result = await self._isolate_endpoint(event_data)
            
            elif action_type == ActionType.ENABLE_MFA:
                result = await self._enable_mfa(event_data)
            
            elif action_type == ActionType.WEBHOOK:
                result = await self._call_webhook(action.params, event_data)
            
            else:
                result = {"success": True, "message": f"Action {action_type} executed"}
            
            logger.info(f"Executed action {action_type}: {result}")
            return result
        
        except Exception as e:
            logger.error(f"Action {action_type} failed: {e}")
            return {"success": False, "error": str(e)}

    async def _block_user(self, user_id: str) -> Dict:
        if not user_id:
            return {"success": False, "error": "No user_id"}
        
        for callback in self.callbacks["block_user"]:
            await callback(user_id)
        
        return {"success": True, "action": "block_user", "user_id": user_id}

    async def _block_ip(self, ip: str) -> Dict:
        if not ip:
            return {"success": False, "error": "No IP"}
        
        for callback in self.callbacks["block_ip"]:
            await callback(ip)
        
        return {"success": True, "action": "block_ip", "ip": ip}

    async def _create_incident(self, event_data: Dict, execution_id: str) -> Dict:
        incident_data = {
            "title": f"Auto-created: {event_data.get('title', 'Security Alert')}",
            "description": f"Playbook execution: {execution_id}",
            "source": event_data.get("source", "automated"),
            "severity": event_data.get("severity", "medium"),
        }
        
        for callback in self.callbacks["create_incident"]:
            await callback(incident_data)
        
        return {"success": True, "action": "create_incident", "incident": incident_data}

    async def _send_email(self, params: Dict, event_data: Dict) -> Dict:
        recipients = params.get("recipients", [])
        subject = params.get("subject", "Security Alert")
        
        for callback in self.callbacks["send_email"]:
            await callback(recipients, subject, event_data)
        
        return {"success": True, "action": "send_email", "recipients": recipients}

    async def _notify_manager(self, event_data: Dict) -> Dict:
        user_id = event_data.get("user")
        
        for callback in self.callbacks["webhook"]:
            await callback({"type": "notify_manager", "user": user_id, "event": event_data})
        
        return {"success": True, "action": "notify_manager"}

    async def _escalate(self, event_data: Dict, params: Dict) -> Dict:
        level = params.get("level", "medium")
        return {"success": True, "action": "escalate", "level": level}

    async def _quarantine_file(self, event_data: Dict) -> Dict:
        file_path = event_data.get("file_path") or event_data.get("file_name")
        return {"success": True, "action": "quarantine_file", "file": file_path}

    async def _isolate_endpoint(self, event_data: Dict) -> Dict:
        hostname = event_data.get("hostname") or event_data.get("host")
        return {"success": True, "action": "isolate_endpoint", "hostname": hostname}

    async def _enable_mfa(self, event_data: Dict) -> Dict:
        user_id = event_data.get("user")
        return {"success": True, "action": "enable_mfa", "user_id": user_id}

    async def _call_webhook(self, params: Dict, event_data: Dict) -> Dict:
        url = params.get("url")
        
        for callback in self.callbacks["webhook"]:
            await callback({"url": url, "data": event_data})
        
        return {"success": True, "action": "webhook", "url": url}

    def get_executions(self, playbook_id: str = None, limit: int = 100) -> List[Dict]:
        executions = self.executions
        if playbook_id:
            executions = [e for e in executions if e.playbook_id == playbook_id]
        
        return [
            {
                "playbook_id": e.playbook_id,
                "execution_id": e.execution_id,
                "status": e.status,
                "start_time": e.start_time,
                "end_time": e.end_time,
                "actions_executed": len(e.actions_executed),
                "result": e.result
            }
            for e in executions[-limit:]
        ]


soar_engine = SOARPlaybookEngine()
