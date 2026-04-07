import socket
import threading
import logging
from typing import Callable, Optional, Dict
from datetime import datetime
import json
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SyslogCollector:
    CEF_PATTERNS = [
        re.compile(r'CEF:(\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)\|(.*)'),
        re.compile(r'<(\d+)>(\w+)\s+(\S+)\s+(.+)$'),
    ]

    def __init__(self, host: str = '0.0.0.0', port: int = 514, protocol: str = 'udp'):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.socket = None
        self.running = False
        self.callbacks = []
        self.parser_thread = None
        self.buffer = []
        self.buffer_lock = threading.Lock()

    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def start(self):
        if self.running:
            return
        
        self.running = True
        
        if self.protocol == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        
        if self.protocol == 'tcp':
            self.socket.listen(100)
        
        logger.info(f"Syslog collector started on {self.host}:{self.port} ({self.protocol.upper()})")
        
        self.parser_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.parser_thread.start()

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("Syslog collector stopped")

    def _receive_loop(self):
        while self.running:
            try:
                if self.protocol == 'udp':
                    data, addr = self.socket.recvfrom(8192)
                    if data:
                        self._process_data(data, addr)
                else:
                    self.socket.listen(5)
                    client, addr = self.socket.accept()
                    data = client.recv(8192)
                    if data:
                        self._process_data(data, addr)
                    client.close()
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving syslog: {e}")

    def _process_data(self, data: bytes, addr: tuple):
        try:
            message = data.decode('utf-8', errors='ignore').strip()
            parsed = self._parse_syslog(message, addr)
            
            with self.buffer_lock:
                self.buffer.append(parsed)
                if len(self.buffer) > 1000:
                    self.buffer = self.buffer[-500:]
            
            for callback in self.callbacks:
                try:
                    callback(parsed)
                except Exception as e:
                    logger.error(f"Error in syslog callback: {e}")
        except Exception as e:
            logger.error(f"Error processing syslog data: {e}")

    def _parse_syslog(self, message: str, addr: tuple) -> Dict:
        parsed = {
            'timestamp': datetime.now().isoformat(),
            'source': 'syslog',
            'source_ip': addr[0] if addr else None,
            'raw': message,
            'message': message,
            'event_type': 'syslog',
            'severity': 'info',
            'hostname': None,
            'user': None,
            'details': {}
        }
        
        for pattern in self.CEF_PATTERNS:
            match = pattern.match(message)
            if match:
                if 'CEF' in message:
                    parsed['cef_version'] = match.group(1)
                    parsed['device_vendor'] = match.group(2)
                    parsed['device_product'] = match.group(3)
                    parsed['event_type'] = match.group(4)
                    parsed['severity'] = match.group(5)
                    parsed['message'] = match.group(6)
                    parsed['details'] = self._parse_cef_extensions(match.group(7))
                else:
                    parsed['priority'] = match.group(1)
                    parsed['hostname'] = match.group(3)
                    parsed['message'] = match.group(4)
                    parsed['severity'] = self._priority_to_severity(int(match.group(1)))
                break
        
        if 'Failed password' in message or 'authentication failure' in message.lower():
            parsed['event_type'] = 'authentication_failure'
            parsed['severity'] = 'warning'
        elif 'Accepted password' in message or 'session opened' in message:
            parsed['event_type'] = 'authentication_success'
            parsed['severity'] = 'info'
        
        return parsed

    def _parse_cef_extensions(self, extensions: str) -> Dict:
        result = {}
        for pair in extensions.split(' '):
            if '=' in pair:
                key, value = pair.split('=', 1)
                result[key] = value
        return result

    def _priority_to_severity(self, priority: int) -> str:
        severity_map = {
            0: 'emergency',
            1: 'alert',
            2: 'critical',
            3: 'error',
            4: 'warning',
            5: 'notice',
            6: 'info',
            7: 'debug'
        }
        return severity_map.get(priority % 8, 'info')

    def get_recent_events(self, count: int = 100) -> list:
        with self.buffer_lock:
            return self.buffer[-count:]


syslog_collector = None

def get_syslog_collector() -> SyslogCollector:
    global syslog_collector
    if syslog_collector is None:
        syslog_collector = SyslogCollector()
    return syslog_collector
