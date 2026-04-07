from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.models.models import User
from app.services.auth.ldap_service import ldap_service, LDAPConfig

router = APIRouter(prefix="/ldap", tags=["LDAP/AD Integration"])


@router.get("/config")
async def get_ldap_config(current_user: User = Depends(get_current_user)):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return ldap_service.get_config()


@router.post("/config")
async def configure_ldap(
    config: dict,
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    ldap_config = LDAPConfig(
        enabled=config.get("enabled", False),
        server_uri=config.get("server_uri", "ldap://localhost:389"),
        bind_dn=config.get("bind_dn", "cn=admin,dc=example,dc=com"),
        bind_password=config.get("bind_password", ""),
        user_base_dn=config.get("user_base_dn", "ou=users,dc=example,dc=com"),
        group_base_dn=config.get("group_base_dn", "ou=groups,dc=example,dc=com"),
        user_search_attr=config.get("user_search_attr", "sAMAccountName"),
        use_ssl=config.get("use_ssl", False),
        use_tls=config.get("use_tls", True)
    )
    
    ldap_service.configure(ldap_config)
    return {"status": "configured"}


@router.post("/connect")
async def connect_ldap(current_user: User = Depends(get_current_user)):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    result = ldap_service.connect()
    if result:
        return {"status": "connected"}
    return {"status": "connection_failed"}


@router.post("/disconnect")
async def disconnect_ldap(current_user: User = Depends(get_current_user)):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    ldap_service.disconnect()
    return {"status": "disconnected"}


@router.post("/test")
async def test_ldap_connection(current_user: User = Depends(get_current_user)):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    return ldap_service.test_connection()


@router.post("/authenticate")
async def authenticate_with_ldap(
    username: str,
    password: str,
    current_user: User = Depends(get_current_user)
):
    result = ldap_service.authenticate(username, password)
    
    if not result.get("success"):
        raise HTTPException(status_code=401, detail=result.get("error", "Authentication failed"))
    
    user_data = result["user"]
    
    mapped_role = ldap_service.map_group_to_role(user_data["groups"][0] if user_data["groups"] else "Domain Users")
    
    return {
        "username": user_data["username"],
        "email": user_data["email"],
        "display_name": user_data["display_name"],
        "groups": user_data["groups"],
        "mapped_role": mapped_role
    }


@router.get("/users")
async def get_ldap_users(current_user: User = Depends(get_current_user)):
    if current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    return ldap_service.get_all_users()


@router.get("/user/{username}")
async def get_ldap_user(
    username: str,
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    user = ldap_service.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "dn": user.dn,
        "groups": user.groups,
        "is_enabled": user.is_enabled,
        "last_login": user.last_login
    }


@router.get("/groups")
async def get_ldap_groups(current_user: User = Depends(get_current_user)):
    if current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    return ldap_service.get_all_groups()


@router.post("/map-group/{group_name}")
async def map_group_to_role(
    group_name: str,
    role: str,
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    mapped_role = ldap_service.map_group_to_role(group_name)
    return {"group": group_name, "mapped_role": mapped_role}
