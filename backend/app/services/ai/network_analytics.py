from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetworkProfile:
    ip_address: str
    hostname: str = None
    first_seen: str = None
    last_seen: str = None
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    connections_count: int = 0
    unique_destinations: int = 0
    risk_score: float = 0
    flags: List[str] = field(default_factory=list)


class NetworkAnalytics:
    def __init__(self):
        self.profiles: Dict[str, NetworkProfile] = {}
        self.traffic_history = []
        self.anomalies = []

    def analyze_traffic(self, flows: List[Dict]) -> Dict:
        stats = {
            "total_flows": len(flows),
            "total_bytes_in": 0,
            "total_bytes_out": 0,
            "unique_ips": set(),
            "protocols": defaultdict(int),
            "top_talkers": [],
            "suspicious_patterns": []
        }
        
        for flow in flows:
            src_ip = flow.get("source_ip", "")
            dst_ip = flow.get("destination_ip", "")
            bytes_in = flow.get("bytes_in", 0)
            bytes_out = flow.get("bytes_out", 0)
            protocol = flow.get("protocol", "unknown")
            
            stats["total_bytes_in"] += bytes_in
            stats["total_bytes_out"] += bytes_out
            stats["unique_ips"].add(src_ip)
            stats["unique_ips"].add(dst_ip)
            stats["protocols"][protocol] += 1
            
            if src_ip:
                self._update_profile(src_ip, flow, "source")
            if dst_ip:
                self._update_profile(dst_ip, flow, "destination")
        
        stats["unique_ips"] = len(stats["unique_ips"])
        
        self._detect_anomalies(flows)
        
        stats["top_talkers"] = self._get_top_talkers(10)
        stats["anomalies"] = self.anomalies[-20:]
        
        return stats

    def _update_profile(self, ip: str, flow: Dict, role: str):
        if ip not in self.profiles:
            self.profiles[ip] = NetworkProfile(
                ip_address=ip,
                first_seen=datetime.now().isoformat()
            )
        
        profile = self.profiles[ip]
        profile.last_seen = datetime.now().isoformat()
        
        if role == "source":
            profile.total_bytes_out += flow.get("bytes_out", 0)
        else:
            profile.total_bytes_in += flow.get("bytes_in", 0)
        
        profile.connections_count += 1
        
        dest_ip = flow.get("destination_ip" if role == "source" else "source_ip")
        if dest_ip:
            profile.unique_destinations += 1

    def _detect_anomalies(self, flows: List[Dict]) -> List[Dict]:
        new_anomalies = []
        
        high_volume_ips = defaultdict(int)
        for flow in flows:
            high_volume_ips[flow.get("source_ip", "")] += flow.get("bytes_out", 0)
        
        for ip, bytes_out in high_volume_ips.items():
            if bytes_out > 100_000_000:
                new_anomalies.append({
                    "type": "high_volume_transfer",
                    "ip": ip,
                    "severity": "critical",
                    "description": f"IP {ip} transferred {bytes_out / 1024 / 1024:.1f}MB",
                    "timestamp": datetime.now().isoformat()
                })
        
        beacon_ips = self._detect_beaconing(flows)
        if beacon_ips:
            new_anomalies.extend(beacon_ips)
        
        self.anomalies.extend(new_anomalies)
        if len(self.anomalies) > 1000:
            self.anomalies = self.anomalies[-500:]
        
        return new_anomalies

    def _detect_beaconing(self, flows: List[Dict]) -> List[Dict]:
        connections = defaultdict(list)
        
        for flow in flows:
            key = (flow.get("source_ip"), flow.get("destination_ip"), flow.get("dest_port"))
            connections[key].append(flow.get("timestamp"))
        
        beacons = []
        
        for (src, dst, port), timestamps in connections.items():
            if len(timestamps) > 10:
                beacons.append({
                    "type": "beaconing",
                    "source_ip": src,
                    "dest_ip": dst,
                    "port": port,
                    "severity": "high",
                    "description": f"Possible C2 communication detected to {dst}",
                    "timestamp": datetime.now().isoformat()
                })
        
        return beacons

    def _get_top_talkers(self, limit: int = 10) -> List[Dict]:
        sorted_profiles = sorted(
            self.profiles.values(),
            key=lambda p: p.total_bytes_in + p.total_bytes_out,
            reverse=True
        )
        
        return [
            {
                "ip": p.ip_address,
                "bytes_in": p.total_bytes_in,
                "bytes_out": p.total_bytes_out,
                "connections": p.connections_count,
                "risk_score": p.risk_score,
                "flags": p.flags
            }
            for p in sorted_profiles[:limit]
        ]

    def get_ip_profile(self, ip: str) -> Optional[Dict]:
        if ip not in self.profiles:
            return None
        
        p = self.profiles[ip]
        return {
            "ip": p.ip_address,
            "hostname": p.hostname,
            "first_seen": p.first_seen,
            "last_seen": p.last_seen,
            "total_bytes_in": p.total_bytes_in,
            "total_bytes_out": p.total_bytes_out,
            "connections": p.connections_count,
            "unique_destinations": p.unique_destinations,
            "risk_score": p.risk_score,
            "flags": p.flags
        }

    def get_all_profiles(self, min_connections: int = 0) -> List[Dict]:
        profiles = self.profiles.values()
        
        if min_connections > 0:
            profiles = [p for p in profiles if p.connections_count >= min_connections]
        
        return [
            {
                "ip": p.ip_address,
                "connections": p.connections_count,
                "bytes_total": p.total_bytes_in + p.total_bytes_out,
                "risk_score": p.risk_score
            }
            for p in sorted(profiles, key=lambda x: x.connections_count, reverse=True)
        ]

    def get_protocol_distribution(self) -> Dict:
        protocols = defaultdict(int)
        
        for profile in self.profiles.values():
            if profile.total_bytes_out > 0:
                protocols["HTTP"] += 1
        
        return dict(protocols)

    def get_geo_analysis(self) -> Dict:
        internal_ips = 0
        external_ips = 0
        unknown_ips = 0
        
        for ip in self.profiles.keys():
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                internal_ips += 1
            elif ip.replace(".", "").isdigit():
                external_ips += 1
            else:
                unknown_ips += 1
        
        return {
            "internal": internal_ips,
            "external": external_ips,
            "unknown": unknown_ips,
            "total": len(self.profiles)
        }

    def get_flow_summary(self, hours: int = 24) -> Dict:
        if not self.traffic_history:
            return {
                "flows_analyzed": len(self.profiles),
                "avg_daily_flows": 0,
                "peak_flows": 0
            }
        
        return {
            "flows_analyzed": len(self.profiles),
            "unique_ips": len(self.profiles),
            "anomalies_detected": len(self.anomalies),
            "high_risk_ips": sum(1 for p in self.profiles.values() if p.risk_score > 70)
        }


network_analytics = NetworkAnalytics()
