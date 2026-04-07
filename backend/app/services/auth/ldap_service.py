from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging
import hashlib

try:
    import ldap
    from ldap import ldap
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    ldap = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LDAPConfig:
    enabled: bool = False
    server_uri: str = "ldap://localhost:389"
    bind_dn: str = "cn=admin,dc=example,dc=com"
    bind_password: str = ""
    user_base_dn: str = "ou=users,dc=example,dc=com"
    group_base_dn: str = "ou=groups,dc=example,dc=com"
    user_search_attr: str = "sAMAccountName"
    group_search_attr: str = "cn"
    use_ssl: bool = False
    use_tls: bool = True
    sync_interval: int = 3600
    follow_referrals: bool = False


@dataclass
class LDAPUser:
    username: str
    email: str
    display_name: str
    dn: str
    groups: List[str] = field(default_factory=list)
    is_enabled: bool = True
    last_login: str = None
    attributes: Dict = field(default_factory=dict)


@dataclass
class LDAPGroup:
    name: str
    dn: str
    members: List[str] = field(default_factory=list)
    description: str = ""


class LDAPService:
    def __init__(self):
        self.config = LDAPConfig()
        self.connection = None
        self.user_cache: Dict[str, LDAPUser] = {}
        self.group_cache: Dict[str, LDAPGroup] = {}

    def configure(self, config: LDAPConfig):
        self.config = config

    def connect(self) -> bool:
        if not LDAP_AVAILABLE:
            logger.warning("LDAP library not available - using mock mode")
            return True

        try:
            self.connection = ldap.initialize(self.config.server_uri)
            
            if self.config.use_ssl:
                self.connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            
            if self.config.use_tls and not self.config.use_ssl:
                self.connection.start_tls_s()
            
            self.connection.set_option(ldap.OPT_REFERRALS, 1 if self.config.follow_referrals else 0)
            
            self.connection.simple_bind_s(self.config.bind_dn, self.config.bind_password)
            
            logger.info(f"Connected to LDAP server: {self.config.server_uri}")
            return True
        except ldap.LDAPError as e:
            logger.error(f"LDAP connection error: {e}")
            return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.unbind_s()
            except:
                pass
            self.connection = None

    def authenticate(self, username: str, password: str) -> Dict:
        if not password:
            return {"success": False, "error": "No password provided"}

        if not LDAP_AVAILABLE:
            return self._mock_authenticate(username, password)

        try:
            search_filter = f"({self.config.user_search_attr}={username})"
            
            result = self.connection.search_s(
                self.config.user_base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                None
            )
            
            if not result:
                return {"success": False, "error": "User not found"}
            
            dn, attrs = result[0]
            
            user_dn = dn
            if isinstance(user_dn, bytes):
                user_dn = user_dn.decode('utf-8')
            
            temp_conn = ldap.initialize(self.config.server_uri)
            
            if self.config.use_tls and not self.config.use_ssl:
                temp_conn.start_tls_s()
            
            temp_conn.simple_bind_s(user_dn, password)
            temp_conn.unbind_s()
            
            email = self._get_attr(attrs, 'mail', username)
            display_name = self._get_attr(attrs, 'displayName', username)
            groups = self._get_user_groups(username)
            
            user = LDAPUser(
                username=username,
                email=email,
                display_name=display_name,
                dn=user_dn,
                groups=groups,
                last_login=datetime.now().isoformat()
            )
            
            self.user_cache[username] = user
            
            return {
                "success": True,
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "display_name": user.display_name,
                    "groups": user.groups
                }
            }
        
        except ldap.INVALID_CREDENTIALS:
            return {"success": False, "error": "Invalid credentials"}
        except ldap.LDAPError as e:
            logger.error(f"LDAP auth error: {e}")
            return {"success": False, "error": str(e)}

    def _mock_authenticate(self, username: str, password: str) -> Dict:
        if username == "admin" and password == "admin":
            return {
                "success": True,
                "user": {
                    "username": "admin",
                    "email": "admin@bank.com",
                    "display_name": "System Administrator",
                    "groups": ["Domain Admins", "IT Security"]
                }
            }
        elif password == "password":
            return {
                "success": True,
                "user": {
                    "username": username,
                    "email": f"{username}@bank.com",
                    "display_name": username.title(),
                    "groups": ["Domain Users"]
                }
            }
        return {"success": False, "error": "Invalid credentials"}

    def _get_attr(self, attrs: Dict, key: str, default: str = "") -> str:
        if key in attrs:
            values = attrs[key]
            if values:
                val = values[0]
                if isinstance(val, bytes):
                    return val.decode('utf-8')
                return str(val)
        return default

    def get_user(self, username: str) -> Optional[LDAPUser]:
        if username in self.user_cache:
            return self.user_cache[username]

        if not LDAP_AVAILABLE:
            return None

        try:
            search_filter = f"({self.config.user_search_attr}={username})"
            
            result = self.connection.search_s(
                self.config.user_base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['mail', 'displayName', 'memberOf']
            )
            
            if not result:
                return None
            
            dn, attrs = result[0]
            
            groups = self._get_user_groups(username)
            
            user = LDAPUser(
                username=username,
                email=self._get_attr(attrs, 'mail'),
                display_name=self._get_attr(attrs, 'displayName'),
                dn=dn,
                groups=groups
            )
            
            self.user_cache[username] = user
            return user
        
        except ldap.LDAPError as e:
            logger.error(f"LDAP get user error: {e}")
            return None

    def _get_user_groups(self, username: str) -> List[str]:
        groups = []
        
        if not LDAP_AVAILABLE:
            return ["Domain Users"]
        
        try:
            search_filter = f"(&({self.config.user_search_attr}={username})(objectClass=user))"
            
            result = self.connection.search_s(
                self.config.user_base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['memberOf']
            )
            
            if result and len(result) > 0:
                _, attrs = result[0]
                if 'memberOf' in attrs:
                    for group_dn in attrs['memberOf']:
                        if isinstance(group_dn, bytes):
                            group_dn = group_dn.decode('utf-8')
                        group_name = group_dn.split(',')[0].replace('CN=', '')
                        groups.append(group_name)
        
        except ldap.LDAPError as e:
            logger.error(f"LDAP get groups error: {e}")
        
        return groups

    def get_all_users(self) -> List[Dict]:
        users = []
        
        if not LDAP_AVAILABLE:
            return [
                {"username": "admin", "email": "admin@bank.com", "display_name": "Admin", "groups": ["Admins"]},
                {"username": "analyst", "email": "analyst@bank.com", "display_name": "Analyst", "groups": ["Security"]},
            ]

        try:
            result = self.connection.search_s(
                self.config.user_base_dn,
                ldap.SCOPE_SUBTREE,
                "(objectClass=user)",
                ['sAMAccountName', 'mail', 'displayName', 'memberOf']
            )
            
            for dn, attrs in result:
                username = self._get_attr(attrs, 'sAMAccountName')
                if username:
                    groups = self._get_user_groups(username)
                    users.append({
                        "username": username,
                        "email": self._get_attr(attrs, 'mail'),
                        "display_name": self._get_attr(attrs, 'displayName'),
                        "groups": groups
                    })
        
        except ldap.LDAPError as e:
            logger.error(f"LDAP get users error: {e}")
        
        return users

    def get_all_groups(self) -> List[Dict]:
        groups = []
        
        if not LDAP_AVAILABLE:
            return [
                {"name": "Domain Admins", "description": "Domain Administrators"},
                {"name": "IT Security", "description": "IT Security Team"},
                {"name": "SOC Analysts", "description": "Security Operations Center"},
            ]

        try:
            result = self.connection.search_s(
                self.config.group_base_dn,
                ldap.SCOPE_SUBTREE,
                "(objectClass=group)",
                ['cn', 'description', 'member']
            )
            
            for dn, attrs in result:
                name = self._get_attr(attrs, 'cn')
                if name:
                    members = []
                    if 'member' in attrs:
                        for member in attrs['member']:
                            if isinstance(member, bytes):
                                member = member.decode('utf-8')
                            members.append(member)
                    
                    groups.append({
                        "name": name,
                        "description": self._get_attr(attrs, 'description'),
                        "members_count": len(members)
                    })
        
        except ldap.LDAPError as e:
            logger.error(f"LDAP get groups error: {e}")
        
        return groups

    def get_config(self) -> Dict:
        safe_config = {
            "enabled": self.config.enabled,
            "server_uri": self.config.server_uri,
            "user_base_dn": self.config.user_base_dn,
            "group_base_dn": self.config.group_base_dn,
            "use_ssl": self.config.use_ssl,
            "use_tls": self.config.use_tls
        }
        return safe_config

    def test_connection(self) -> Dict:
        if not LDAP_AVAILABLE:
            return {"success": True, "message": "Mock LDAP connection successful"}

        try:
            conn = ldap.initialize(self.config.server_uri)
            if self.config.use_tls:
                conn.start_tls_s()
            conn.simple_bind_s(self.config.bind_dn, self.config.bind_password)
            conn.unbind_s()
            return {"success": True, "message": "LDAP connection successful"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def map_group_to_role(self, group: str) -> str:
        group_mapping = {
            "Domain Admins": "admin",
            "IT Security": "admin",
            "SOC Analysts": "analyst",
            "Security Analysts": "analyst",
            "Security Operators": "operator",
            "Auditors": "auditor",
            "Compliance": "auditor",
            "Domain Users": "operator"
        }
        
        for key, role in group_mapping.items():
            if key.lower() in group.lower():
                return role
        
        return "operator"


ldap_service = LDAPService()
