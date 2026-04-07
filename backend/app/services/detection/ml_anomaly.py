import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class UserBaseline:
    user_id: str
    login_hours: List[int]
    login_days: List[int]
    avg_session_duration: float
    avg_data_transfer: float
    avg_files_accessed: float
    trusted_devices: List[str]
    trusted_ips: List[str]
    last_updated: str
    anomaly_score: float = 0.0


@dataclass
class AnomalyAlert:
    user_id: str
    anomaly_type: str
    severity: str
    description: str
    features: Dict
    timestamp: str
    score: float


class MLAnomalyDetector:
    Z_THRESHOLD = 3.0
    
    def __init__(self):
        self.baselines: Dict[str, UserBaseline] = {}
        self.event_buffer: Dict[str, List[Dict]] = defaultdict(list)
        self.anomaly_history: List[AnomalyAlert] = []
        self.callbacks = []
        self.models_loaded = False

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def train_baseline(self, user_id: str, historical_data: List[Dict]):
        login_hours = []
        login_days = []
        session_durations = []
        data_transfers = []
        files_accessed = []
        devices = set()
        ips = set()
        
        for event in historical_data:
            if "timestamp" in event:
                ts = datetime.fromisoformat(event["timestamp"])
                login_hours.append(ts.hour)
                login_days.append(ts.weekday())
            
            if "session_duration" in event:
                session_durations.append(event["session_duration"])
            if "data_transfer" in event:
                data_transfers.append(event["data_transfer"])
            if "files_accessed" in event:
                files_accessed.append(event["files_accessed"])
            if "device_id" in event:
                devices.add(event["device_id"])
            if "ip_address" in event:
                ips.add(event["ip_address"])
        
        baseline = UserBaseline(
            user_id=user_id,
            login_hours=login_hours if login_hours else [9, 10, 11, 14, 15, 16, 17],
            login_days=login_days if login_days else [0, 1, 2, 3, 4],
            avg_session_duration=np.mean(session_durations) if session_durations else 3600,
            avg_data_transfer=np.mean(data_transfers) if data_transfers else 1000000,
            avg_files_accessed=np.mean(files_accessed) if files_accessed else 50,
            trusted_devices=list(devices) if devices else ["device1"],
            trusted_ips=list(ips) if ips else ["192.168.1.0/24"],
            last_updated=datetime.now().isoformat()
        )
        
        self.baselines[user_id] = baseline
        logger.info(f"Trained baseline for user {user_id}")

    def detect_anomaly(self, event: Dict) -> Optional[AnomalyAlert]:
        user_id = event.get("user_id") or event.get("user")
        if not user_id:
            return None
        
        if user_id not in self.baselines:
            self.train_baseline(user_id, [])
        
        baseline = self.baselines[user_id]
        scores = []
        features = {}
        
        if "timestamp" in event:
            ts = datetime.fromisoformat(event["timestamp"])
            
            hour_score = self._calculate_hour_anomaly(ts.hour, baseline.login_hours)
            if hour_score > 0:
                scores.append(("unusual_login_hour", hour_score))
                features["unusual_hour"] = True
            
            if ts.weekday() not in baseline.login_days:
                scores.append(("unusual_login_day", 2.0))
                features["unusual_day"] = True
        
        if "ip_address" in event:
            ip = event["ip_address"]
            if not self._is_trusted_ip(ip, baseline.trusted_ips):
                scores.append(("untrusted_ip", 2.5))
                features["untrusted_ip"] = ip
        
        if "device_id" in event:
            device = event["device_id"]
            if device not in baseline.trusted_devices:
                scores.append(("untrusted_device", 2.0))
                features["untrusted_device"] = device
        
        if "data_transfer" in event:
            transfer = event["data_transfer"]
            if transfer > baseline.avg_data_transfer * 3:
                scores.append(("large_transfer", 3.0))
                features["large_data_transfer"] = transfer
        
        if "files_accessed" in event:
            files = event["files_accessed"]
            if files > baseline.avg_files_accessed * 3:
                scores.append(("bulk_file_access", 2.5))
                features["bulk_file_access"] = files
        
        if "session_duration" in event:
            duration = event["session_duration"]
            if duration > baseline.avg_session_duration * 5:
                scores.append(("long_session", 2.0))
                features["long_session"] = duration
        
        if scores:
            total_score = sum(s[1] for s in scores)
            avg_score = total_score / len(scores)
            
            severity = "low"
            if avg_score >= 2.5:
                severity = "critical"
            elif avg_score >= 2.0:
                severity = "high"
            elif avg_score >= 1.5:
                severity = "medium"
            
            descriptions = [f"{s[0]}: {s[1]:.1f}" for s in scores]
            
            alert = AnomalyAlert(
                user_id=user_id,
                anomaly_type=" + ".join(s[0] for s in scores),
                severity=severity,
                description=f"Anomaly detected: {', '.join(s[0] for s in scores)}",
                features=features,
                timestamp=datetime.now().isoformat(),
                score=avg_score
            )
            
            self.anomaly_history.append(alert)
            if len(self.anomaly_history) > 1000:
                self.anomaly_history = self.anomaly_history[-500:]
            
            baseline.anomaly_score = avg_score
            
            for callback in self.callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
            
            return alert
        
        return None

    def _calculate_hour_anomaly(self, hour: int, baseline_hours: List[int]) -> float:
        if hour in baseline_hours:
            return 0.0
        
        if not baseline_hours:
            return 1.0
        
        avg_hour = np.mean(baseline_hours)
        std_hour = np.std(baseline_hours) if len(baseline_hours) > 1 else 2
        
        if std_hour == 0:
            std_hour = 2
        
        z_score = abs(hour - avg_hour) / std_hour
        
        if z_score > self.Z_THRESHOLD:
            return min(z_score, 5.0)
        return 0.0

    def _is_trusted_ip(self, ip: str, trusted_ips: List[str]) -> bool:
        for trusted in trusted_ips:
            if "/" in trusted:
                return True
            if trusted in ip:
                return True
        return False

    def get_user_baseline(self, user_id: str) -> Optional[Dict]:
        if user_id in self.baselines:
            baseline = self.baselines[user_id]
            return {
                "user_id": baseline.user_id,
                "login_hours": baseline.login_hours,
                "login_days": baseline.login_days,
                "avg_session_duration": baseline.avg_session_duration,
                "avg_data_transfer": baseline.avg_data_transfer,
                "trusted_devices": baseline.trusted_devices,
                "trusted_ips": baseline.trusted_ips,
                "last_updated": baseline.last_updated,
                "anomaly_score": baseline.anomaly_score
            }
        return None

    def get_anomaly_history(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        if user_id:
            filtered = [a for a in self.anomaly_history if a.user_id == user_id]
            return [self._anomaly_to_dict(a) for a in filtered[-limit:]]
        return [self._anomaly_to_dict(a) for a in self.anomaly_history[-limit:]]

    def _anomaly_to_dict(self, alert: AnomalyAlert) -> Dict:
        return {
            "user_id": alert.user_id,
            "anomaly_type": alert.anomaly_type,
            "severity": alert.severity,
            "description": alert.description,
            "features": alert.features,
            "timestamp": alert.timestamp,
            "score": alert.score
        }

    def get_risk_score(self, user_id: str) -> float:
        if user_id in self.baselines:
            return min(self.baselines[user_id].anomaly_score * 25, 100)
        return 0.0

    def get_all_user_scores(self) -> Dict[str, float]:
        return {
            user_id: min(baseline.anomaly_score * 25, 100)
            for user_id, baseline in self.baselines.items()
        }


ml_anomaly_detector = None

def get_ml_anomaly_detector() -> MLAnomalyDetector:
    global ml_anomaly_detector
    if ml_anomaly_detector is None:
        ml_anomaly_detector = MLAnomalyDetector()
    return ml_anomaly_detector
