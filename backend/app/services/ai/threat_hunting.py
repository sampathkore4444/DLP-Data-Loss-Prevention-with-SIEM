from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class HuntHypothesis:
    hypothesis_id: str
    name: str
    description: str
    mitre_tactics: List[str]
    severity: str
    hunt_queries: List[Dict]
    status: str = "pending"
    findings_count: int = 0
    last_run: str = None


@dataclass
class HuntFinding:
    finding_id: str
    hypothesis_id: str
    title: str
    description: str
    severity: str
    indicators: List[str]
    timestamp: str
    mitre_techniques: List[str] = field(default_factory=list)


class ThreatHuntingEngine:
    MITRE_ATTACK_MAPPING = {
        "TA0001": {"name": "Initial Access", "techniques": ["T1566", "T1190", "T1133"]},
        "TA0002": {"name": "Execution", "techniques": ["T1059", "T1204", "T1203"]},
        "TA0003": {"name": "Persistence", "techniques": ["T1547", "T1053", "T1136"]},
        "TA0004": {"name": "Privilege Escalation", "techniques": ["T1548", "T1134", "T1068"]},
        "TA0005": {"name": "Defense Evasion", "techniques": ["T1070", "T1036", "T1027"]},
        "TA0006": {"name": "Credential Access", "techniques": ["T1110", "T1555", "T1003"]},
        "TA0007": {"name": "Discovery", "techniques": ["T1087", "T1082", "T1083"]},
        "TA0008": {"name": "Lateral Movement", "techniques": ["T1021", "T1080", "T1210"]},
        "TA0009": {"name": "Collection", "techniques": ["T1560", "T1123", "T1119"]},
        "TA0011": {"name": "Exfiltration", "techniques": ["T1041", "T1048", "T1567"]},
        "TA0040": {"name": "Impact", "techniques": ["T1486", "T1489", "T1490"]},
    }

    def __init__(self):
        self.hypotheses = self._init_hypotheses()
        self.findings = []
        self.hunt_history = []

    def _init_hypotheses(self) -> Dict[str, HuntHypothesis]:
        return {
            "hunt_brute_force": HuntHypothesis(
                hypothesis_id="hunt_brute_force",
                name="Active Brute Force Attack",
                description="Hunting for evidence of ongoing brute force or credential stuffing attacks",
                mitre_tactics=["TA0006"],
                severity="high",
                hunt_queries=[
                    {"source": "siem", "filter": {"event_type": "authentication_failure", "count": ">5"}},
                    {"source": "siem", "filter": {"event_type": "authentication_success", "user": "unknown"}}
                ]
            ),
            "hunt_data_exfil": HuntHypothesis(
                hypothesis_id="hunt_data_exfil",
                name="Data Exfiltration in Progress",
                description="Searching for patterns indicating data exfiltration",
                mitre_tactics=["TA0011"],
                severity="critical",
                hunt_queries=[
                    {"source": "dlp", "filter": {"severity": "critical"}},
                    {"source": "network", "filter": {"bytes_out": ">100000000"}}
                ]
            ),
            "hunt_insider": HuntHypothesis(
                hypothesis_id="hunt_insider",
                name="Insider Threat Activity",
                description="Detecting potential insider threat behaviors",
                mitre_tactics=["TA0003", "TA0009"],
                severity="high",
                hunt_queries=[
                    {"source": "dlp", "filter": {"action": "block"}},
                    {"source": "siem", "filter": {"anomaly": "after_hours"}},
                    {"source": "endpoint", "filter": {"event": "bulk_download"}}
                ]
            ),
            "hunt_malware": HuntHypothesis(
                hypothesis_id="hunt_malware",
                name="Malware Command & Control",
                description="Looking for signs of malware C2 communication",
                mitre_tactics=["TA0001", "TA0011"],
                severity="critical",
                hunt_queries=[
                    {"source": "network", "filter": {"dest_port": [4444, 8080, 31337]}},
                    {"source": "siem", "filter": {"event_type": "suspicious_dns"}}
                ]
            ),
            "hunt_privilege": HuntHypothesis(
                hypothesis_id="hunt_privilege",
                name="Privilege Escalation Attempt",
                description="Searching for privilege escalation activities",
                mitre_tactics=["TA0004"],
                severity="high",
                hunt_queries=[
                    {"source": "siem", "filter": {"event_type": "privilege_change"}},
                    {"source": "windows", "filter": {"event_id": [4728, 4729]}}
                ]
            ),
            "hunt_lateral": HuntHypothesis(
                hypothesis_id="hunt_lateral",
                name="Lateral Movement",
                description="Detecting lateral movement patterns",
                mitre_tactics=["TA0008"],
                severity="high",
                hunt_queries=[
                    {"source": "network", "filter": {"new_connections": ">10"}},
                    {"source": "siem", "filter": {"event_type": "port_scan"}}
                ]
            ),
        }

    def run_hunt(self, hypothesis_id: str) -> List[HuntFinding]:
        if hypothesis_id not in self.hypotheses:
            return []
        
        hypothesis = self.hypotheses[hypothesis_id]
        hypothesis.status = "running"
        hypothesis.last_run = datetime.now().isoformat()
        
        findings = self._execute_hunt(hypothesis)
        
        hypothesis.findings_count = len(findings)
        hypothesis.status = "completed" if findings else "no_findings"
        
        self.findings.extend(findings)
        
        self.hunt_history.append({
            "hypothesis_id": hypothesis_id,
            "run_at": hypothesis.last_run,
            "findings": len(findings)
        })
        
        return findings

    def _execute_hunt(self, hypothesis: HuntHypothesis) -> List[HuntFinding]:
        findings = []
        
        sample_findings = {
            "hunt_brute_force": [
                {"title": "Multiple failed logins", "severity": "high", "indicators": ["192.168.1.100", "50+ failures"]},
            ],
            "hunt_data_exfil": [
                {"title": "Large data transfer to external IP", "severity": "critical", "indicators": ["185.199.108.153", "500MB"]},
            ],
            "hunt_insider": [
                {"title": "Bulk file download after hours", "severity": "high", "indicators": ["user: john.doe", "files: 500+"]},
            ],
        }
        
        if hypothesis.hypothesis_id in sample_findings:
            for i, f in enumerate(sample_findings[hypothesis.hypothesis_id]):
                findings.append(HuntFinding(
                    finding_id=f"finding_{hypothesis.hypothesis_id}_{i}",
                    hypothesis_id=hypothesis.hypothesis_id,
                    title=f["title"],
                    description=f"Found during hunt: {hypothesis.name}",
                    severity=f["severity"],
                    indicators=f["indicators"],
                    timestamp=datetime.now().isoformat(),
                    mitre_techniques=hypothesis.mitre_tactics
                ))
        
        return findings

    def get_hypotheses(self) -> List[Dict]:
        return [
            {
                "id": h.hypothesis_id,
                "name": h.name,
                "description": h.description,
                "mitre_tactics": h.mitre_tactics,
                "severity": h.severity,
                "status": h.status,
                "findings_count": h.findings_count,
                "last_run": h.last_run
            }
            for h in self.hypotheses.values()
        ]

    def run_all_hunts(self) -> Dict:
        results = {}
        for hypothesis_id in self.hypotheses.keys():
            findings = self.run_hunt(hypothesis_id)
            results[hypothesis_id] = {
                "findings": len(findings),
                "severity": self.hypotheses[hypothesis_id].severity
            }
        return results

    def get_findings(self, hypothesis_id: str = None, limit: int = 100) -> List[Dict]:
        findings = self.findings
        if hypothesis_id:
            findings = [f for f in findings if f.hypothesis_id == hypothesis_id]
        return [
            {
                "id": f.finding_id,
                "hypothesis": f.title,
                "description": f.description,
                "severity": f.severity,
                "indicators": f.indicators,
                "timestamp": f.timestamp,
                "mitre_techniques": f.mitre_techniques
            }
            for f in findings[-limit:]
        ]

    def get_mitre_coverage(self) -> Dict:
        covered = set()
        for f in self.findings:
            for t in f.mitre_techniques:
                covered.add(t)
        
        all_techniques = set()
        for tactics in self.MITRE_ATTACK_MAPPING.values():
            for t in tactics["techniques"]:
                all_techniques.add(t)
        
        return {
            "covered": len(covered),
            "total": len(all_techniques),
            "coverage_percent": round(len(covered) / len(all_techniques) * 100, 1),
            "techniques": list(covered)
        }


threat_hunting = ThreatHuntingEngine()
