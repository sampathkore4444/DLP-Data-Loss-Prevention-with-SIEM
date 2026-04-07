from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TriagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


class TriageAction(str, Enum):
    IMMEDIATE = "immediate"
    ESCALATE = "escalate"
    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    AUTO_RESOLVE = "auto_resolve"


@dataclass
class TriageRule:
    rule_id: str
    name: str
    conditions: Dict
    priority: TriagePriority
    action: TriageAction
    auto_resolve: bool = False


@dataclass
class TriageResult:
    priority: TriagePriority
    action: TriageAction
    confidence: float
    reasoning: List[str]
    similar_incidents: List[Dict] = field(default_factory=list)
    recommended_playbook: str = None


class SmartIncidentTriage:
    def __init__(self):
        self.rules = self._init_default_rules()
        self.incident_history = []
        self.statistics = defaultdict(int)
        self.false_positive_patterns = self._init_fp_patterns()

    def _init_default_rules(self) -> Dict[str, TriageRule]:
        return {
            "critical_dlp": TriageRule(
                rule_id="critical_dlp",
                name="Critical DLP Alert",
                conditions={"source": "dlp", "severity": "critical"},
                priority=TriagePriority.CRITICAL,
                action=TriageAction.IMMEDIATE
            ),
            "brute_force": TriageRule(
                rule_id="brute_force",
                name="Brute Force Attack",
                conditions={"event_type": "authentication_failure", "count": ">5"},
                priority=TriagePriority.HIGH,
                action=TriageAction.ESCALATE
            ),
            "data_exfil": TriageRule(
                rule_id="data_exfil",
                name="Data Exfiltration",
                conditions={"rule_id": "data_exfiltration"},
                priority=TriagePriority.CRITICAL,
                action=TriageAction.IMMEDIATE
            ),
            "insider_threat": TriageRule(
                rule_id="insider_threat",
                name="Insider Threat",
                conditions={"anomaly_type": "unusual_access"},
                priority=TriagePriority.HIGH,
                action=TriageAction.INVESTIGATE
            ),
            "malware": TriageRule(
                rule_id="malware",
                name="Malware Detection",
                conditions={"event_type": "malware_detected"},
                priority=TriagePriority.CRITICAL,
                action=TriageAction.IMMEDIATE
            ),
            "mfa_bypass": TriageRule(
                rule_id="mfa_bypass",
                name="MFA Bypass Attempt",
                conditions={"event_type": "mfa_failure", "count": ">3"},
                priority=TriagePriority.HIGH,
                action=TriageAction.ESCALATE
            ),
            "after_hours": TriageRule(
                rule_id="after_hours",
                name="After Hours Access",
                conditions={"anomaly_type": "unusual_login_hour"},
                priority=TriagePriority.LOW,
                action=TriageAction.MONITOR
            ),
        }

    def _init_fp_patterns(self) -> List[Dict]:
        return [
            {"type": "ip", "pattern": "10.0.0.0/8", "reason": "Internal network"},
            {"type": "user", "pattern": "admin", "reason": "System admin"},
            {"type": "event", "pattern": "normal_login", "reason": "Normal login pattern"},
        ]

    def triage(self, incident: Dict) -> TriageResult:
        reasoning = []
        priority = TriagePriority.MEDIUM
        action = TriageAction.INVESTIGATE
        confidence = 0.5
        
        source = incident.get("source", "")
        severity = incident.get("severity", "")
        event_type = incident.get("event_type", "")
        
        if self._is_false_positive(incident):
            priority = TriagePriority.FALSE_POSITIVE
            action = TriageAction.AUTO_RESOLVE
            confidence = 0.95
            reasoning.append("Matches known false positive pattern")
            return TriageResult(priority, action, confidence, reasoning)
        
        matched_rules = self._match_rules(incident)
        
        if matched_rules:
            top_rule = matched_rules[0]
            priority = top_rule.priority
            action = top_rule.action
            confidence = min(0.7 + len(matched_rules) * 0.1, 0.95)
            reasoning.append(f"Matched rule: {top_rule.name}")
            
            if top_rule.auto_resolve:
                action = TriageAction.AUTO_RESOLVE
        
        if severity == "critical":
            priority = TriagePriority.CRITICAL
            if action == TriageAction.INVESTIGATE:
                action = TriageAction.IMMEDIATE
            reasoning.append("Critical severity override")
        
        if source == "dlp" and "credit_card" in str(incident):
            priority = TriagePriority.HIGH
            reasoning.append("DLP: Credit card data detected")
        
        if source == "siem" and event_type in ["brute_force", "port_scan"]:
            priority = TriagePriority.HIGH
            reasoning.append(f"SIEM: {event_type} detected")
        
        if confidence < 0.5:
            priority = TriagePriority.MEDIUM
            action = TriageAction.INVESTIGATE
            reasoning.append("Low confidence - manual review required")
        
        similar = self._find_similar_incidents(incident)
        
        playbook = self._recommend_playbook(priority, action)
        
        self.statistics[f"{priority.value}_count"] += 1
        
        return TriageResult(
            priority=priority,
            action=action,
            confidence=confidence,
            reasoning=reasoning,
            similar_incidents=similar[:3],
            recommended_playbook=playbook
        )

    def _is_false_positive(self, incident: Dict) -> bool:
        source_ip = incident.get("source_ip", "")
        user = incident.get("user", "")
        
        for fp in self.false_positive_patterns:
            if fp["type"] == "ip" and fp["pattern"] in source_ip:
                return True
            if fp["type"] == "user" and fp["pattern"] in user:
                return True
        
        return False

    def _match_rules(self, incident: Dict) -> List[TriageRule]:
        matched = []
        
        for rule in self.rules.values():
            conditions_match = True
            for key, expected in rule.conditions.items():
                actual = incident.get(key, "")
                if isinstance(expected, str) and ">" in expected:
                    threshold = int(expected.replace(">", ""))
                    try:
                        if int(actual) <= threshold:
                            conditions_match = False
                    except:
                        conditions_match = False
                elif str(actual).lower() != str(expected).lower():
                    conditions_match = False
                
                if not conditions_match:
                    break
            
            if conditions_match:
                matched.append(rule)
        
        return matched

    def _find_similar_incidents(self, incident: Dict) -> List[Dict]:
        similar = []
        
        for hist in self.incident_history[-50:]:
            score = 0
            if incident.get("source") == hist.get("source"):
                score += 2
            if incident.get("severity") == hist.get("severity"):
                score += 2
            if incident.get("user") == hist.get("user"):
                score += 3
            
            if score >= 3:
                similar.append({
                    "incident_id": hist.get("incident_id"),
                    "title": hist.get("title"),
                    "status": hist.get("status"),
                    "similarity_score": score
                })
        
        return similar

    def _recommend_playbook(self, priority: TriagePriority, action: TriageAction) -> str:
        if priority == TriagePriority.CRITICAL and action == TriageAction.IMMEDIATE:
            return "pb_dlp_critical"
        if priority == TriagePriority.HIGH and action == TriageAction.ESCALATE:
            return "pb_brute_force"
        if "insider" in str(action).lower():
            return "pb_insider_threat"
        return None

    def add_incident_to_history(self, incident: Dict):
        self.incident_history.append({
            **incident,
            "triaged_at": datetime.now().isoformat()
        })
        if len(self.incident_history) > 1000:
            self.incident_history = self.incident_history[-500:]

    def get_statistics(self) -> Dict:
        return {
            "total_triaged": sum(self.statistics.values()),
            "by_priority": dict(self.statistics),
            "auto_resolved": self.statistics.get("false_positive_count", 0),
            "critical_handled": self.statistics.get("critical_count", 0)
        }

    def add_false_positive_pattern(self, pattern: Dict):
        self.false_positive_patterns.append(pattern)

    def get_rules(self) -> List[Dict]:
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "conditions": r.conditions,
                "priority": r.priority.value,
                "action": r.action.value,
                "auto_resolve": r.auto_resolve
            }
            for r in self.rules.values()
        ]


from datetime import datetime
from enum import Enum

smart_triage = SmartIncidentTriage()
