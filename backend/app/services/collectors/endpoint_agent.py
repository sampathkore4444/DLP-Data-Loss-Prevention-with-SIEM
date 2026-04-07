import os
import hashlib
import threading
import time
import json
import logging
from typing import Dict, List, Callable, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class FileEvent:
    event_type: str
    file_path: str
    file_name: str
    file_size: int
    file_hash: str
    timestamp: str
    user: str
    process_name: str
    channel: str
    action: str = "monitor"
    blocked: bool = False


class EndpointAgent:
    WATCHED_CHANNELS = {
        "usb": ["/media", "/mnt", "/Volumes", "E:", "F:", "G:", "D:"],
        "print": ["/var/spool/cups", "C:\\Windows\\System32\\spool"],
        "network": ["/tmp", "/var/tmp", "C:\\Temp"],
    }

    SENSITIVE_EXTENSIONS = [
        ".xlsx", ".xls", ".csv", ".doc", ".docx", ".pdf",
        ".txt", ".json", ".xml", ".sql", ".bak", ".zip", ".rar"
    ]

    def __init__(self, hostname: str = None, user: str = None):
        self.hostname = hostname or os.environ.get("HOSTNAME", "unknown")
        self.user = user or os.environ.get("USER", "unknown")
        self.watched_paths = set()
        self.callbacks = []
        self.running = False
        self.thread = None
        self.event_count = 0
        self.blocked_events = 0

    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def add_watch_path(self, path: str, channel: str = "usb"):
        if os.path.exists(path):
            self.watched_paths.add(path)
            logger.info(f"Added watch path: {path} ({channel})")
        else:
            logger.warning(f"Path does not exist: {path}")

    def start(self):
        if self.running:
            return
        
        self.running = True
        self._discover_watch_paths()
        
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
        
        logger.info(f"Endpoint Agent started on {self.hostname} for user {self.user}")

    def stop(self):
        self.running = False
        logger.info(f"Endpoint Agent stopped. Events: {self.event_count}, Blocked: {self.blocked_events}")

    def _discover_watch_paths(self):
        for channel, paths in self.WATCHED_CHANNELS.items():
            for path in paths:
                if os.path.exists(path):
                    self.watched_paths.add(path)
                    logger.info(f"Discovered {channel} path: {path}")

    def _watch_loop(self):
        file_states = {}
        
        while self.running:
            for base_path in list(self.watched_paths):
                try:
                    if os.name == 'nt':
                        self._watch_windows(base_path, file_states)
                    else:
                        self._watch_unix(base_path, file_states)
                except Exception as e:
                    logger.debug(f"Watch error for {base_path}: {e}")
            
            time.sleep(2)

    def _watch_windows(self, base_path: str, file_states: Dict):
        try:
            for root, dirs, files in os.walk(base_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    if not self._is_sensitive_file(file):
                        continue
                    
                    try:
                        stat = os.stat(file_path)
                        key = (file_path, stat.st_size, stat.st_mtime)
                        
                        if file_path not in file_states:
                            event = self._create_event("created", file_path)
                            self._process_event(event)
                            file_states[file_path] = key
                        elif file_states[file_path] != key:
                            event = self._create_event("modified", file_path)
                            self._process_event(event)
                            file_states[file_path] = key
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            logger.debug(f"Windows watch error: {e}")

    def _watch_unix(self, base_path: str, file_states: Dict):
        try:
            for root, dirs, files in os.walk(base_path):
                if any(skip in root for skip in [".cache", ".local", "snap"]):
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    if not self._is_sensitive_file(file):
                        continue
                    
                    try:
                        stat = os.stat(file_path)
                        key = (file_path, stat.st_size, stat.st_mtime)
                        
                        if file_path not in file_states:
                            event = self._create_event("created", file_path)
                            self._process_event(event)
                            file_states[file_path] = key
                        elif file_states[file_path] != key:
                            event = self._create_event("modified", file_path)
                            self._process_event(event)
                            file_states[file_path] = key
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            logger.debug(f"Unix watch error: {e}")

    def _is_sensitive_file(self, filename: str) -> bool:
        ext = os.path.splitext(filename)[1].lower()
        return ext in self.SENSITIVE_EXTENSIONS

    def _create_event(self, event_type: str, file_path: str) -> FileEvent:
        file_name = os.path.basename(file_path)
        
        try:
            file_size = os.path.getsize(file_path)
        except:
            file_size = 0
        
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read(1024)).hexdigest()[:16]
        except:
            file_hash = "unknown"
        
        channel = self._detect_channel(file_path)
        
        return FileEvent(
            event_type=event_type,
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_hash=file_hash,
            timestamp=datetime.now().isoformat(),
            user=self.user,
            process_name="explorer",
            channel=channel,
            action="allow",
            blocked=False
        )

    def _detect_channel(self, file_path: str) -> str:
        path_lower = file_path.lower()
        
        for channel, paths in self.WATCHED_CHANNELS.items():
            for p in paths:
                if p.lower() in path_lower:
                    return channel
        
        return "local"

    def _process_event(self, event: FileEvent):
        self.event_count += 1
        
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def block_event(self, event: FileEvent):
        event.action = "block"
        event.blocked = True
        self.blocked_events += 1
        
        try:
            os.remove(event.file_path)
            logger.warning(f"Blocked and removed: {event.file_path}")
        except Exception as e:
            logger.error(f"Failed to block file: {e}")

    def get_status(self) -> Dict:
        return {
            "hostname": self.hostname,
            "user": self.user,
            "running": self.running,
            "watched_paths": list(self.watched_paths),
            "events_processed": self.event_count,
            "events_blocked": self.blocked_events
        }

    def scan_directory(self, directory: str) -> List[FileEvent]:
        events = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if self._is_sensitive_file(file):
                    file_path = os.path.join(root, file)
                    event = self._create_event("scan", file_path)
                    events.append(event)
        
        return events


endpoint_agent = None

def get_endpoint_agent() -> EndpointAgent:
    global endpoint_agent
    if endpoint_agent is None:
        endpoint_agent = EndpointAgent()
    return endpoint_agent
