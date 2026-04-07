from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScoreCategory:
    name: str
    weight: float
    score: float = 0
    findings: List[Dict] = field(default_factory=list)
    max_score: float = 100


class SecurityScorecard:
    CATEGORIES = {
        "network_security": {"weight": 0.15, "name": "Network Security"},
        "endpoint_security": {"weight": 0.15, "name": "Endpoint Security"},
        "identity_security": {"weight": 0.20, "name": "Identity & Access"},
        "data_protection": {"weight": 0.20, "name": "Data Protection"},
        "threat_detection": {"weight": 0.15, "name": "Threat Detection"},
        "compliance": {"weight": 0.15, "name": "Compliance"},
    }

    def __init__(self):
        self.category_scores = {}
        self.history = []

    def calculate_score(self) -> Dict:
        categories = []
        total_weight = 0
        weighted_sum = 0

        network_score = self._evaluate_network_security()
        categories.append(network_score)
        weighted_sum += network_score.score * network_score.weight
        total_weight += network_score.weight

        endpoint_score = self._evaluate_endpoint_security()
        categories.append(endpoint_score)
        weighted_sum += endpoint_score.score * endpoint_score.weight
        total_weight += endpoint_score.weight

        identity_score = self._evaluate_identity_security()
        categories.append(identity_score)
        weighted_sum += identity_score.score * identity_score.weight
        total_weight += identity_score.weight

        data_score = self._evaluate_data_protection()
        categories.append(data_score)
        weighted_sum += data_score.score * data_score.weight
        total_weight += data_score.weight

        threat_score = self._evaluate_threat_detection()
        categories.append(threat_score)
        weighted_sum += threat_score.score * threat_score.weight
        total_weight += threat_score.weight

        compliance_score = self._evaluate_compliance()
        categories.append(compliance_score)
        weighted_sum += compliance_score.score * compliance_score.weight
        total_weight += compliance_score.weight

        overall_score = weighted_sum / total_weight if total_weight > 0 else 0

        grade = "F"
        if overall_score >= 90:
            grade = "A"
        elif overall_score >= 80:
            grade = "B"
        elif overall_score >= 70:
            grade = "C"
        elif overall_score >= 60:
            grade = "D"

        risk_level = "low"
        if overall_score < 70:
            risk_level = "critical"
        elif overall_score < 80:
            risk_level = "high"
        elif overall_score < 90:
            risk_level = "medium"

        result = {
            "overall_score": round(overall_score, 1),
            "grade": grade,
            "risk_level": risk_level,
            "categories": [
                {
                    "name": c.name,
                    "score": round(c.score, 1),
                    "weight": c.weight,
                    "findings": c.findings
                }
                for c in categories
            ],
            "calculated_at": datetime.now().isoformat()
        }

        self.history.append({
            "score": overall_score,
            "grade": grade,
            "timestamp": result["calculated_at"]
        })

        return result

    def _evaluate_network_security(self) -> ScoreCategory:
        cat = ScoreCategory(name="Network Security", weight=0.15)
        
        findings = []
        
        findings.append({"issue": "Firewall rules configured", "status": "pass", "points": 25})
        
        findings.append({"issue": "IDS/IPS monitoring active", "status": "pass", "points": 25})
        
        findings.append({"issue": "Network segmentation", "status": "warning", "points": 15})
        
        findings.append({"issue": "VPN encryption", "status": "pass", "points": 20})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def _evaluate_endpoint_security(self) -> ScoreCategory:
        cat = ScoreCategory(name="Endpoint Security", weight=0.15)
        
        findings = []
        
        findings.append({"issue": "Antivirus installed", "status": "pass", "points": 20})
        
        findings.append({"issue": "EDR coverage", "status": "pass", "points": 25})
        
        findings.append({"issue": "Disk encryption", "status": "warning", "points": 15})
        
        findings.append({"issue": "Patch management", "status": "fail", "points": 0})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def _evaluate_identity_security(self) -> ScoreCategory:
        cat = ScoreCategory(name="Identity & Access", weight=0.20)
        
        findings = []
        
        findings.append({"issue": "MFA enabled", "status": "pass", "points": 30})
        
        findings.append({"issue": "Password policy enforced", "status": "pass", "points": 20})
        
        findings.append({"issue": " Privileged access management", "status": "warning", "points": 15})
        
        findings.append({"issue": "Session timeout", "status": "pass", "points": 15})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def _evaluate_data_protection(self) -> ScoreCategory:
        cat = ScoreCategory(name="Data Protection", weight=0.20)
        
        findings = []
        
        findings.append({"issue": "DLP policies active", "status": "pass", "points": 30})
        
        findings.append({"issue": "Data encryption at rest", "status": "pass", "points": 25})
        
        findings.append({"issue": "Data encryption in transit", "status": "pass", "points": 25})
        
        findings.append({"issue": "Backup strategy", "status": "warning", "points": 10})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def _evaluate_threat_detection(self) -> ScoreCategory:
        cat = ScoreCategory(name="Threat Detection", weight=0.15)
        
        findings = []
        
        findings.append({"issue": "SIEM correlation rules", "status": "pass", "points": 30})
        
        findings.append({"issue": "Threat intelligence integration", "status": "pass", "points": 25})
        
        findings.append({"issue": "Anomaly detection", "status": "pass", "points": 25})
        
        findings.append({"issue": "24/7 SOC monitoring", "status": "warning", "points": 10})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def _evaluate_compliance(self) -> ScoreCategory:
        cat = ScoreCategory(name="Compliance", weight=0.15)
        
        findings = []
        
        findings.append({"issue": "PCI-DSS compliance", "status": "pass", "points": 35})
        
        findings.append({"issue": "GDPR controls", "status": "pass", "points": 30})
        
        findings.append({"issue": "SOX controls", "status": "warning", "points": 20})
        
        cat.findings = findings
        cat.score = sum(f["points"] for f in findings if f["status"] == "pass")
        
        return cat

    def get_trend(self, days: int = 30) -> Dict:
        if not self.history:
            return {"trend": "insufficient_data"}
        
        recent = self.history[-days:] if len(self.history) > days else self.history
        
        if len(recent) < 2:
            return {"trend": "insufficient_data", "data_points": len(recent)}
        
        scores = [h["score"] for h in recent]
        
        if scores[-1] > scores[0]:
            trend = "improving"
        elif scores[-1] < scores[0]:
            trend = "declining"
        else:
            trend = "stable"
        
        avg = sum(scores) / len(scores)
        
        return {
            "trend": trend,
            "current": scores[-1],
            "previous": scores[0],
            "average": round(avg, 1),
            "data_points": len(scores)
        }

    def compare_with_industry(self, industry_avg: float = 75.0) -> Dict:
        if not self.history:
            return {"error": "No data available"}
        
        current = self.history[-1]["score"]
        
        if current >= industry_avg + 10:
            rating = "leader"
        elif current >= industry_avg:
            rating = "average"
        elif current >= industry_avg - 10:
            rating = "below_average"
        else:
            rating = "critical"
        
        return {
            "our_score": current,
            "industry_avg": industry_avg,
            "rating": rating,
            "gap": round(current - industry_avg, 1)
        }


security_scorecard = SecurityScorecard()
