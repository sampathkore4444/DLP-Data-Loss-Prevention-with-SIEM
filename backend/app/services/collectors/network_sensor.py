import socket
import struct
import threading
import time
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetworkFlow:
    timestamp: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    bytes_in: int
    bytes_out: int
    packets: int
    duration: float
    app_protocol: str
    direction: str


class NetworkSensor:
    KNOWN_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 3306: "MYSQL", 5432: "POSTGRESQL",
        6379: "REDIS", 27017: "MONGODB", 9200: "ELASTICSEARCH",
        8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
    }

    SENSITIVE_PROTOCOLS = ["FTP", "SMB", "TELNET", "HTTP"]
    THRESHOLD_LARGE_UPLOAD = 100 * 1024 * 1024
    THRESHOLD_LARGE_DOWNLOAD = 500 * 1024 * 1024

    def __init__(self):
        self.running = False
        self.callbacks = []
        self.flows = []
        self.flows_lock = threading.Lock()
        self.stats = {
            "total_flows": 0,
            "blocked_flows": 0,
            "alerts": 0,
            "by_protocol": defaultdict(int),
            "by_severity": defaultdict(int)
        }
        self.active_connections = {}

    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def start(self, interface: str = None, port: int = None):
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        
        logger.info(f"Network Sensor started on interface: {interface or 'all'}")

    def stop(self):
        self.running = False
        logger.info(f"Network Sensor stopped. Total flows: {self.stats['total_flows']}")

    def _capture_loop(self):
        while self.running:
            time.sleep(1)
            self._simulate_network_activity()

    def _simulate_network_activity(self):
        sample_flows = [
            {"source": "192.168.1.100", "dest": "10.0.0.5", "port": 443, "bytes": 50000},
            {"source": "192.168.1.105", "dest": "172.16.0.10", "port": 22, "bytes": 2048},
            {"source": "192.168.1.110", "dest": "8.8.8.8", "port": 53, "bytes": 256},
        ]
        
        for flow_data in sample_flows:
            flow = NetworkFlow(
                timestamp=datetime.now().isoformat(),
                source_ip=flow_data["source"],
                source_port=50000 + hash(flow_data["source"]) % 1000,
                dest_ip=flow_data["dest"],
                dest_port=flow_data["port"],
                protocol=self._get_protocol(flow_data["port"]),
                bytes_in=flow_data["bytes"],
                bytes_out=flow_data["bytes"] // 2,
                packets=1,
                duration=0.5,
                app_protocol="https" if flow_data["port"] == 443 else "unknown",
                direction="outbound"
            )
            self._process_flow(flow)

    def _get_protocol(self, port: int) -> str:
        return self.KNOWN_PORTS.get(port, "UNKNOWN")

    def _process_flow(self, flow: NetworkFlow):
        self.stats["total_flows"] += 1
        self.stats["by_protocol"][flow.protocol] += 1
        
        alert = None
        
        if flow.protocol in self.SENSITIVE_PROTOCOLS:
            alert = {
                "type": "sensitive_protocol",
                "severity": "high",
                "message": f"Sensitive protocol {flow.protocol} detected",
                "flow": asdict(flow)
            }
        
        if flow.bytes_out > self.THRESHOLD_LARGE_UPLOAD:
            alert = {
                "type": "large_upload",
                "severity": "critical",
                "message": f"Large data upload detected: {flow.bytes_out / 1024 / 1024:.1f}MB",
                "flow": asdict(flow)
            }
            self.stats["by_severity"]["critical"] += 1
        
        if self._is_suspicious_port(flow.dest_port):
            alert = {
                "type": "suspicious_port",
                "severity": "medium",
                "message": f"Connection to suspicious port {flow.dest_port}",
                "flow": asdict(flow)
            }
            self.stats["by_severity"]["medium"] += 1
        
        if self._is_external_ip(flow.dest_ip) and flow.bytes_out > 10 * 1024 * 1024:
            alert = {
                "type": "external_transfer",
                "severity": "high",
                "message": f"Large transfer to external IP {flow.dest_ip}",
                "flow": asdict(flow)
            }
        
        if alert:
            self.stats["alerts"] += 1
            
            with self.flows_lock:
                self.flows.append(asdict(flow))
                if len(self.flows) > 1000:
                    self.flows = self.flows[-500:]
            
            for callback in self.callbacks:
                try:
                    callback(alert, flow)
                except Exception as e:
                    logger.error(f"Callback error: {e}")

    def _is_suspicious_port(self, port: int) -> bool:
        suspicious_ports = [4444, 5555, 6666, 31337, 12345, 54321]
        return port in suspicious_ports

    def _is_external_ip(self, ip: str) -> bool:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            return False
        if ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31:
            return False
        return True

    def get_recent_flows(self, count: int = 100) -> List[Dict]:
        with self.flows_lock:
            return self.flows[-count:]

    def get_status(self) -> Dict:
        return {
            "running": self.running,
            "total_flows": self.stats["total_flows"],
            "alerts": self.stats["alerts"],
            "by_protocol": dict(self.stats["by_protocol"]),
            "by_severity": dict(self.stats["by_severity"])
        }

    def add_flow(self, flow: NetworkFlow):
        self._process_flow(flow)


network_sensor = None

def get_network_sensor() -> NetworkSensor:
    global network_sensor
    if network_sensor is None:
        network_sensor = NetworkSensor()
    return network_sensor
