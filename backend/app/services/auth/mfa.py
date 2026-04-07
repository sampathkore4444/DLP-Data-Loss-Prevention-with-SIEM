import random
import string
import time
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MFAConfig:
    enabled: bool = True
    method: str = "totp"
    issuer: str = "SecureVault"
    session_timeout: int = 300
    max_attempts: int = 3
    backup_codes_count: int = 10


@dataclass
class MFASession:
    session_id: str
    user_id: str
    method: str
    code: str
    created_at: str
    expires_at: str
    verified: bool = False
    attempts: int = 0


@dataclass
class UserMFA:
    user_id: str
    method: str
    secret: str
    enabled: bool
    backup_codes: List[str] = field(default_factory=list)
    trusted_devices: List[Dict] = field(default_factory=list)
    last_used: str = None


class MFAService:
    def __init__(self):
        self.sessions: Dict[str, MFASession] = {}
        self.user_mfa: Dict[str, UserMFA] = {}
        self.config = MFAConfig()

    def generate_secret(self) -> str:
        chars = string.ascii_uppercase + string.digits + '234567'
        return ''.join(random.choice(chars) for _ in range(16))

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        codes = []
        for _ in range(count):
            code = ''.join(random.choices(string.hexdigits.lower(), k=8))
            codes.append(code)
        return codes

    def init_mfa(self, user_id: str, method: str = "totp") -> Dict:
        if user_id in self.user_mfa and self.user_mfa[user_id].enabled:
            return {"error": "MFA already enabled"}

        secret = self.generate_secret()
        backup_codes = self.generate_backup_codes()

        user_mfa = UserMFA(
            user_id=user_id,
            method=method,
            secret=secret,
            enabled=True,
            backup_codes=backup_codes
        )
        self.user_mfa[user_id] = user_mfa

        return {
            "secret": secret,
            "backup_codes": backup_codes,
            "qr_code": f"otpauth://totp/{self.config.issuer}:{user_id}?secret={secret}&issuer={self.config.issuer}"
        }

    def verify_totp(self, code: str, user_id: str, session_id: str = None) -> bool:
        if user_id not in self.user_mfa:
            return False

        user_mfa = self.user_mfa[user_id]

        if not user_mfa.enabled:
            return True

        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            
            if session.verified:
                return True

            if code == session.code:
                session.verified = True
                logger.info(f"MFA verified for user {user_id}")
                return True

            session.attempts += 1
            if session.attempts >= self.config.max_attempts:
                del self.sessions[session_id]
                logger.warning(f"MFA session locked for user {user_id} after max attempts")
                return False

        return False

    def verify_backup_code(self, code: str, user_id: str) -> bool:
        if user_id not in self.user_mfa:
            return False

        user_mfa = self.user_mfa[user_id]
        
        if code in user_mfa.backup_codes:
            user_mfa.backup_codes.remove(code)
            logger.info(f"Backup code used for user {user_id}")
            return True

        return False

    def create_session(self, user_id: str, method: str = "totp") -> Dict:
        session_id = hashlib.sha256(f"{user_id}{time.time()}".encode()).hexdigest()[:32]
        
        if method == "totp":
            code = ''.join(random.choices(string.digits, k=6))
        else:
            code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        now = datetime.now()
        expires = now + timedelta(seconds=self.config.session_timeout)

        session = MFASession(
            session_id=session_id,
            user_id=user_id,
            method=method,
            code=code,
            created_at=now.isoformat(),
            expires_at=expires.isoformat()
        )

        self.sessions[session_id] = session

        return {
            "session_id": session_id,
            "code": code,
            "expires_at": session.expires_at,
            "method": method
        }

    def verify_session(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        
        if session.verified:
            return True

        expires = datetime.fromisoformat(session.expires_at)
        if datetime.now() > expires:
            del self.sessions[session_id]
            return False

        return False

    def get_user_mfa_status(self, user_id: str) -> Dict:
        if user_id in self.user_mfa:
            user_mfa = self.user_mfa[user_id]
            return {
                "enabled": user_mfa.enabled,
                "method": user_mfa.method,
                "backup_codes_remaining": len(user_mfa.backup_codes),
                "trusted_devices_count": len(user_mfa.trusted_devices)
            }
        return {"enabled": False}

    def disable_mfa(self, user_id: str) -> bool:
        if user_id in self.user_mfa:
            self.user_mfa[user_id].enabled = False
            return True
        return False

    def add_trusted_device(self, user_id: str, device_info: Dict) -> bool:
        if user_id in self.user_mfa:
            device_info["added_at"] = datetime.now().isoformat()
            self.user_mfa[user_id].trusted_devices.append(device_info)
            return True
        return False

    def get_config(self) -> Dict:
        return {
            "enabled": self.config.enabled,
            "method": self.config.method,
            "issuer": self.config.issuer,
            "session_timeout": self.config.session_timeout,
            "max_attempts": self.config.max_attempts
        }

    def update_config(self, updates: Dict):
        if "enabled" in updates:
            self.config.enabled = updates["enabled"]
        if "session_timeout" in updates:
            self.config.session_timeout = updates["session_timeout"]
        if "max_attempts" in updates:
            self.config.max_attempts = updates["max_attempts"]


mfa_service = MFAService()
