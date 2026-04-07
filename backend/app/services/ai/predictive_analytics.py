from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    user_id: str
    score: float
    factors: List[Dict]
    trend: str
    last_updated: str


@dataclass
class Prediction:
    type: str
    probability: float
    timeframe: str
    description: str
    severity: str
    indicators: List[str]


class PredictiveAnalytics:
    def __init__(self):
        self.user_risk_scores: Dict[str, RiskScore] = {}
        self.historical_data = []
        self.threat_models = self._init_threat_models()

    def _init_threat_models(self) -> Dict:
        return {
            "data_exfiltration": {
                "indicators": ["large_transfer", "unusual_time", "new_destination"],
                "weight": 0.9
            },
            "account_compromise": {
                "indicators": ["failed_logins", "impossible_travel", "privilege_escalation"],
                "weight": 0.85
            },
            "insider_threat": {
                "indicators": ["bulk_download", "after_hours", "policy_violations"],
                "weight": 0.75
            },
            "privilege_abuse": {
                "indicators": ["sensitive_access", "unusual_queries", "data_dumping"],
                "weight": 0.8
            },
            "lateral_movement": {
                "indicators": ["new_systems", "unusual_ports", "scan_detected"],
                "weight": 0.7
            }
        }

    def calculate_user_risk(self, user_id: str, events: List[Dict]) -> RiskScore:
        factors = []
        total_score = 0

        failed_logins = sum(1 for e in events if e.get("event_type") == "authentication_failure")
        if failed_logins > 5:
            score = min(failed_logins * 5, 100)
            factors.append({"factor": "failed_logins", "score": score, "count": failed_logins})
            total_score += score

        dlp_violations = sum(1 for e in events if e.get("source") == "dlp")
        if dlp_violations > 0:
            score = min(dlp_violations * 15, 100)
            factors.append({"factor": "dlp_violations", "score": score, "count": dlp_violations})
            total_score += score

        unusual_hours = self._check_unusual_hours(events)
        if unusual_hours:
            score = 25
            factors.append({"factor": "after_hours_access", "score": score})
            total_score += score

        new_destinations = self._count_new_destinations(events)
        if new_destinations > 3:
            score = min(new_destinations * 10, 50)
            factors.append({"factor": "new_destinations", "score": score, "count": new_destinations})
            total_score += score

        large_transfers = self._check_large_transfers(events)
        if large_transfers:
            score = 40
            factors.append({"factor": "large_transfers", "score": score})
            total_score += score

        privilege_escalation = sum(1 for e in events if "privilege" in str(e.get("event_type", "")).lower())
        if privilege_escalation > 0:
            score = 35
            factors.append({"factor": "privilege_escalation", "score": score})
            total_score += score

        risk_score = min(total_score, 100)
        
        trend = self._calculate_trend(user_id)
        
        self.user_risk_scores[user_id] = RiskScore(
            user_id=user_id,
            score=risk_score,
            factors=factors,
            trend=trend,
            last_updated=datetime.now().isoformat()
        )
        
        return self.user_risk_scores[user_id]

    def _check_unusual_hours(self, events: List[Dict]) -> bool:
        for event in events:
            if "timestamp" in event:
                try:
                    ts = datetime.fromisoformat(event["timestamp"])
                    if ts.hour < 7 or ts.hour > 21:
                        return True
                except:
                    pass
        return False

    def _count_new_destinations(self, events: List[Dict]) -> int:
        destinations = set()
        for event in events:
            if "destination_ip" in event:
                destinations.add(event["destination_ip"])
        return len(destinations)

    def _check_large_transfers(self, events: List[Dict]) -> bool:
        for event in events:
            bytes_sent = event.get("bytes_out", 0)
            if bytes_sent > 100_000_000:
                return True
        return False

    def _calculate_trend(self, user_id: str) -> str:
        if user_id in self.user_risk_scores:
            if len(self.historical_data) > 1:
                return "stable"
        return "new"

    def predict_threats(self, user_id: str = None) -> List[Prediction]:
        predictions = []
        
        if user_id:
            user_risk = self.user_risk_scores.get(user_id)
            if user_risk and user_risk.score > 50:
                predictions.append(self._generate_prediction(user_risk))
        else:
            for uid, risk in self.user_risk_scores.items():
                if risk.score > 50:
                    pred = self._generate_prediction(risk)
                    predictions.append(pred)
        
        predictions.sort(key=lambda x: x.probability, reverse=True)
        return predictions[:10]

    def _generate_prediction(self, risk: RiskScore) -> Prediction:
        threat_type = "data_exfiltration"
        probability = min(risk.score / 100, 0.95)
        
        if any("dlp" in str(f["factor"]) for f in risk.factors):
            threat_type = "data_exfiltration"
            probability = min(risk.score / 100 + 0.1, 0.95)
        elif any("login" in str(f["factor"]) for f in risk.factors):
            threat_type = "account_compromise"
        elif any("privilege" in str(f["factor"]) for f in risk.factors):
            threat_type = "privilege_abuse"
        
        severity = "high" if probability > 0.7 else "medium" if probability > 0.4 else "low"
        
        indicators = [f["factor"] for f in risk.factors[:3]]
        
        return Prediction(
            type=threat_type,
            probability=probability,
            timeframe="24-48 hours",
            description=f"Potential {threat_type} risk detected for user {risk.user_id}",
            severity=severity,
            indicators=indicators
        )

    def calculate_org_risk_score(self) -> Dict:
        total_users = len(self.user_risk_scores)
        if total_users == 0:
            return {"score": 0, "level": "low", "users_at_risk": 0}
        
        scores = [r.score for r in self.user_risk_scores.values()]
        avg_score = sum(scores) / total_users
        high_risk = sum(1 for s in scores if s > 70)
        critical = sum(1 for s in scores if s > 90)
        
        level = "low"
        if avg_score > 60 or critical > 0:
            level = "critical"
        elif avg_score > 40 or high_risk > total_users * 0.1:
            level = "high"
        elif avg_score > 20:
            level = "medium"
        
        return {
            "score": round(avg_score, 2),
            "level": level,
            "total_users": total_users,
            "users_at_risk": high_risk,
            "critical": critical,
            "breakdown": {
                "critical": critical,
                "high": high_risk - critical,
                "medium": sum(1 for s in scores if 30 < s <= 70),
                "low": sum(1 for s in scores if s <= 30)
            }
        }

    def get_user_risk(self, user_id: str) -> Optional[RiskScore]:
        return self.user_risk_scores.get(user_id)

    def get_all_risk_scores(self) -> List[Dict]:
        return [
            {
                "user_id": r.user_id,
                "score": r.score,
                "trend": r.trend,
                "last_updated": r.last_updated,
                "factors_count": len(r.factors)
            }
            for r in self.user_risk_scores.values()
        ]

    def add_historical_data(self, data: Dict):
        self.historical_data.append({
            **data,
            "recorded_at": datetime.now().isoformat()
        })
        if len(self.historical_data) > 10000:
            self.historical_data = self.historical_data[-5000:]


predictive_analytics = PredictiveAnalytics()
