from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceControl:
    control_id: str
    name: str
    description: str
    status: str
    last_checked: str
    evidence: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)


class ComplianceEngine:
    FRAMEWORKS = {
        "pci_dss": {
            "name": "PCI DSS",
            "version": "4.0",
            "description": "Payment Card Industry Data Security Standard"
        },
        "gdpr": {
            "name": "GDPR",
            "version": "2016/679",
            "description": "General Data Protection Regulation"
        },
        "sox": {
            "name": "SOX",
            "version": "2002",
            "description": "Sarbanes-Oxley Act"
        },
        "glba": {
            "name": "GLBA",
            "version": "1999",
            "description": "Gramm-Leach-Bliley Act"
        },
        "nist": {
            "name": "NIST CSF",
            "version": "2.0",
            "description": "NIST Cybersecurity Framework"
        }
    }

    def __init__(self):
        self.controls = self._init_controls()
        self.history = []

    def _init_controls(self) -> Dict[str, Dict[str, ComplianceControl]]:
        return {
            "pci_dss": {
                "req_1": ComplianceControl(
                    control_id="req_1",
                    name="Firewall Configuration",
                    description="Install and maintain firewall configuration",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_2": ComplianceControl(
                    control_id="req_2",
                    name="Vendor Defaults",
                    description="Change vendor defaults and remove unnecessary defaults",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_3": ComplianceControl(
                    control_id="req_3",
                    name="Stored Cardholder Data",
                    description="Protect stored cardholder data",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_4": ComplianceControl(
                    control_id="req_4",
                    name="Data Transmission",
                    description="Encrypt transmission of cardholder data",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_5": ComplianceControl(
                    control_id="req_5",
                    name="Malware Software",
                    description="Use and regularly update anti-virus software",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_6": ComplianceControl(
                    control_id="req_6",
                    name="Security Patches",
                    description="Ensure all system components have security patches",
                    status="non_compliant",
                    last_checked=datetime.now().isoformat(),
                    findings=[{"issue": "3 critical patches pending", "severity": "high"}]
                ),
                "req_7": ComplianceControl(
                    control_id="req_7",
                    name="Access Control",
                    description="Restrict access to cardholder data by business need to know",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_8": ComplianceControl(
                    control_id="req_8",
                    name="User Authentication",
                    description="Assign unique IDs to each user",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_9": ComplianceControl(
                    control_id="req_9",
                    name="Physical Access",
                    description="Restrict physical access to cardholder data",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "req_10": ComplianceControl(
                    control_id="req_10",
                    name="Logging",
                    description="Track and monitor all access to system components and cardholder data",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
            },
            "gdpr": {
                "art_5": ComplianceControl(
                    control_id="art_5",
                    name="Data Processing Principles",
                    description="Personal data shall be processed lawfully, fairly and transparently",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "art_6": ComplianceControl(
                    control_id="art_6",
                    name="Lawful Basis",
                    description="Processing must have a lawful basis",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "art_7": ComplianceControl(
                    control_id="art_7",
                    name="Consent",
                    description="Consent must be freely given, specific, informed and unambiguous",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "art_15": ComplianceControl(
                    control_id="art_15",
                    name="Right to Access",
                    description="Data subjects have the right to access their data",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "art_17": ComplianceControl(
                    control_id="art_17",
                    name="Right to Erasure",
                    description="Right to be forgotten - data deletion on request",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "art_32": ComplianceControl(
                    control_id="art_32",
                    name="Security of Processing",
                    description="Implement appropriate technical and organizational measures",
                    status="non_compliant",
                    last_checked=datetime.now().isoformat(),
                    findings=[{"issue": "Encryption gaps in test environment", "severity": "medium"}]
                ),
                "art_33": ComplianceControl(
                    control_id="art_33",
                    name="Breach Notification",
                    description="Notify supervisory authority within 72 hours of breach",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
            },
            "sox": {
                "sec_302": ComplianceControl(
                    control_id="sec_302",
                    name="Corporate Responsibility",
                    description="CEO/CFO certification of financial reports",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "sec_404": ComplianceControl(
                    control_id="sec_404",
                    name="Internal Controls",
                    description="Management assessment of internal controls",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
                "sec_802": ComplianceControl(
                    control_id="sec_802",
                    name="Records Retention",
                    description="Audit trails and record retention requirements",
                    status="compliant",
                    last_checked=datetime.now().isoformat()
                ),
            },
        }

    def check_compliance(self, framework: str) -> Dict:
        if framework not in self.controls:
            return {"error": "Framework not supported"}
        
        controls = self.controls[framework]
        
        compliant = sum(1 for c in controls.values() if c.status == "compliant")
        non_compliant = sum(1 for c in controls.values() if c.status == "non_compliant")
        total = len(controls)
        
        score = (compliant / total * 100) if total > 0 else 0
        
        return {
            "framework": self.FRAMEWORKS[framework]["name"],
            "version": self.FRAMEWORKS[framework]["version"],
            "score": round(score, 1),
            "compliant": compliant,
            "non_compliant": non_compliant,
            "total_controls": total,
            "status": "compliant" if non_compliant == 0 else "non_compliant",
            "controls": [
                {
                    "id": c.control_id,
                    "name": c.name,
                    "status": c.status,
                    "last_checked": c.last_checked,
                    "findings": c.findings
                }
                for c in controls.values()
            ]
        }

    def check_all_frameworks(self) -> Dict:
        results = {}
        
        for framework in self.controls.keys():
            results[framework] = self.check_compliance(framework)
        
        overall_score = sum(r.get("score", 0) for r in results.values()) / len(results)
        
        return {
            "overall_score": round(overall_score, 1),
            "frameworks": results,
            "checked_at": datetime.now().isoformat()
        }

    def get_control_details(self, framework: str, control_id: str) -> Optional[Dict]:
        if framework not in self.controls:
            return None
        
        if control_id not in self.controls[framework]:
            return None
        
        control = self.controls[framework][control_id]
        
        return {
            "control_id": control.control_id,
            "name": control.name,
            "description": control.description,
            "status": control.status,
            "last_checked": control.last_checked,
            "findings": control.findings,
            "evidence": control.evidence
        }

    def update_control_status(self, framework: str, control_id: str, status: str, findings: List[Dict] = None) -> bool:
        if framework in self.controls and control_id in self.controls[framework]:
            self.controls[framework][control_id].status = status
            self.controls[framework][control_id].last_checked = datetime.now().isoformat()
            if findings:
                self.controls[framework][control_id].findings = findings
            return True
        return False

    def get_compliance_report(self, framework: str = None) -> Dict:
        if framework:
            return self.check_compliance(framework)
        return self.check_all_frameworks()

    def get_remediation_plan(self, framework: str) -> List[Dict]:
        if framework not in self.controls:
            return []
        
        non_compliant = [
            {
                "control_id": c.control_id,
                "name": c.name,
                "findings": c.findings,
                "severity": max((f.get("severity", "low") for f in c.findings), default="low", key=lambda s: ["low", "medium", "high", "critical"].index(s) if s in ["low", "medium", "high", "critical"] else 0)
            }
            for c in self.controls[framework].values()
            if c.status == "non_compliant"
        ]
        
        return sorted(non_compliant, key=lambda x: ["low", "medium", "high", "critical"].index(x.get("severity", "low")), reverse=True)


compliance_engine = ComplianceEngine()
