from fastapi import APIRouter, Depends, HTTPException, Header
from app.core.security import get_current_user
from app.models.models import User
from app.services.auth.mfa import mfa_service
from typing import Optional

router = APIRouter(prefix="/mfa", tags=["MFA"])


@router.get("/config")
async def get_mfa_config(current_user: User = Depends(get_current_user)):
    return mfa_service.get_config()


@router.post("/config")
async def update_mfa_config(
    updates: dict,
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    mfa_service.update_config(updates)
    return {"status": "updated"}


@router.post("/init")
async def init_mfa(
    method: str = "totp",
    current_user: User = Depends(get_current_user)
):
    result = mfa_service.init_mfa(current_user.username, method)
    return result


@router.post("/status")
async def get_mfa_status(current_user: User = Depends(get_current_user)):
    return mfa_service.get_user_mfa_status(current_user.username)


@router.post("/session")
async def create_mfa_session(
    current_user: User = Depends(get_current_user)
):
    status = mfa_service.get_user_mfa_status(current_user.username)
    if not status.get("enabled"):
        return {"mfa_required": False}
    
    session = mfa_service.create_session(current_user.username)
    return {"mfa_required": True, **session}


@router.post("/verify")
async def verify_mfa(
    code: str,
    session_id: Optional[str] = Header(None),
    backup_code: Optional[bool] = False,
    current_user: User = Depends(get_current_user)
):
    user_id = current_user.username
    
    if backup_code:
        verified = mfa_service.verify_backup_code(code, user_id)
    else:
        if not session_id:
            raise HTTPException(status_code=400, detail="Session ID required")
        verified = mfa_service.verify_totp(code, user_id, session_id)
    
    if verified:
        return {"verified": True, "message": "MFA verified successfully"}
    return {"verified": False, "message": "Invalid code"}


@router.post("/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user)
):
    success = mfa_service.disable_mfa(current_user.username)
    return {"status": "disabled" if success else "not_enabled"}


@router.post("/trusted-device")
async def add_trusted_device(
    device_name: str,
    device_id: str,
    current_user: User = Depends(get_current_user)
):
    device_info = {
        "name": device_name,
        "device_id": device_id,
        "ip": "unknown"
    }
    success = mfa_service.add_trusted_device(current_user.username, device_info)
    return {"status": "added" if success else "error"}
