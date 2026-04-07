from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json
import hashlib

@dataclass
class CorrelationRule:
    id: str
    name: str
    description: str
    condition: str
    time_window: int = 300
    threshold: int = 5
    severity: str = "high"
    source: str = "any"
    enabled: bool = True
    action: str = "alert"

@dataclass
class CorrelatedEvent:
    rule_id: str
    rule_name: str
    severity: str
    description: str
    events: List[Dict]
    timestamp: datetime
    action_taken: str = "logged"

class SIEMCorrelationEngine:
    PREDEFINED_RULES = [
        CorrelationRule(
            id="brute_force_ssh",
            name="SSH Brute Force Attack",
            description="Multiple failed SSH login attempts from same source",
            condition="failed_ssh_login",
            time_window=300,
            threshold=5,
            severity="critical",
            source="sshd"
        ),
        CorrelationRule(
            id="brute_force_web",
            name="Web Login Brute Force",
            description="Multiple failed web login attempts",
            condition="failed_web_login",
            time_window=300,
            threshold=10,
            severity="high",
            source="webserver"
        ),
        CorrelationRule(
            id="port_scan",
            name="Port Scanning Detection",
            description="Multiple connection attempts to different ports",
            condition="port_scan",
            time_window=60,
            threshold=20,
            severity="high",
            source="firewall"
        ),
        CorrelationRule(
            id="data_exfiltration",
            name="Potential Data Exfiltration",
            description="Large data transfer to unknown destination",
            condition="large_transfer",
            time_window=3600,
            threshold=1,
            severity="critical",
            source="network"
        ),
        CorrelationRule(
            id="privilege_escalation",
            name="Privilege Escalation Attempt",
            description="User gaining admin privileges",
            condition="privilege_change",
            time_window=60,
            threshold=1,
            severity="critical",
            source="windows"
        ),
        CorrelationRule(
            id="unusual_access_hours",
            name="Access Outside Business Hours",
            description="User accessing systems outside normal hours",
            condition="after_hours_access",
            time_window=86400,
            threshold=1,
            severity="medium",
            source="any"
        ),
        CorrelationRule(
            id="failed_mfa",
            name="Multiple MFA Failures",
            description="Multiple failed MFA attempts",
            condition="mfa_failure",
            time_window=300,
            threshold=3,
            severity="high",
            source="auth"
        ),
        CorrelationRule(
            id="dlp_correlation",
            name="DLP + Behavioral Correlation",
            description="DLP violation combined with anomalous behavior",
            condition="dlp_plus_anomaly",
            time_window=600,
            threshold=1,
            severity="critical",
            source="dlp"
        ),
    ]

    def __init__(self):
        self.rules = {rule.id: rule for rule in self.PREDEFINED_RULES}
        self.event_buffer = defaultdict(list)
        self.correlation_callbacks = []

    def register_callback(self, callback):
        self.correlation_callbacks.append(callback)

    def add_rule(self, rule: CorrelationRule):
        self.rules[rule.id] = rule

    def remove_rule(self, rule_id: str):
        if rule_id in self.rules:
            del self.rules[rule_id]

    def enable_rule(self, rule_id: str):
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str):
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False

    def process_event(self, event: Dict) -> List[CorrelatedEvent]:
        correlated_events = []
        event_time = datetime.now()
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if self._matches_rule_source(event, rule.source):
                matched = self._evaluate_condition(event, rule)
                if matched:
                    self.event_buffer[rule.id].append({
                        'event': event,
                        'timestamp': event_time
                    })
                    
                    self._cleanup_old_events(rule.id, rule.time_window)
                    
                    if len(self.event_buffer[rule.id]) >= rule.threshold:
                        correlated = self._create_correlated_event(rule, event_time)
                        correlated_events.append(correlated)
                        
                        for callback in self.correlation_callbacks:
                            callback(correlated)
                        
                        self.event_buffer[rule.id] = []
        
        return correlated_events

    def _matches_rule_source(self, event: Dict, source: str) -> bool:
        if source == "any":
            return True
        event_source = event.get('source', '').lower()
        return event_source == source.lower() or source.lower() in event_source.lower()

    def _evaluate_condition(self, event: Dict, rule: CorrelationRule) -> bool:
        condition = rule.condition
        
        if condition == "failed_ssh_login":
            return (event.get('event_type') == 'authentication_failure' and 
                    'ssh' in event.get('message', '').lower())
        
        elif condition == "failed_web_login":
            return (event.get('event_type') == 'authentication_failure' and 
                    'web' in event.get('message', '').lower())
        
        elif condition == "port_scan":
            return (event.get('event_type') == 'connection' and 
                    event.get('action') == 'denied')
        
        elif condition == "large_transfer":
            return (event.get('event_type') == 'network_flow' and 
                    event.get('bytes_sent', 0) > 100000000)
        
        elif condition == "privilege_change":
            return (event.get('event_type') in ['user_added_to_group', 'privilege_change'] and 
                    'admin' in event.get('details', '').lower())
        
        elif condition == "after_hours_access":
            hour = datetime.now().hour
            return hour < 7 or hour > 20
        
        elif condition == "mfa_failure":
            return event.get('event_type') == 'mfa_failure'
        
        elif condition == "dlp_plus_anomaly":
            return event.get('source') == 'dlp' and event.get('severity') in ['critical', 'high']
        
        return True

    def _cleanup_old_events(self, rule_id: str, time_window: int):
        cutoff = datetime.now() - timedelta(seconds=time_window)
        self.event_buffer[rule_id] = [
            e for e in self.event_buffer[rule_id]
            if e['timestamp'] > cutoff
        ]

    def _create_correlated_event(self, rule: CorrelationRule, timestamp: datetime) -> CorrelatedEvent:
        return CorrelatedEvent(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            description=f"{rule.name} - {len(self.event_buffer[rule.id])} events detected",
            events=list(self.event_buffer[rule.id]),
            timestamp=timestamp,
            action_taken=rule.action
        )

    def get_rules(self) -> List[Dict]:
        return [
            {
                'id': r.id,
                'name': r.name,
                'description': r.description,
                'condition': r.condition,
                'time_window': r.time_window,
                'threshold': r.threshold,
                'severity': r.severity,
                'source': r.source,
                'enabled': r.enabled,
                'action': r.action
            }
            for r in self.rules.values()
        ]

    def get_buffer_status(self) -> Dict:
        return {
            rule_id: len(events)
            for rule_id, events in self.event_buffer.items()
        }

    def clear_buffer(self):
        self.event_buffer.clear()


siem_engine = SIEMCorrelationEngine()
