from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.models.models import User
from app.services.soar.playbooks import soar_engine
from app.services.scheduler.custom_reports import report_builder, ReportFormat

router = APIRouter(prefix="/soar", tags=["SOAR"])


@router.get("/playbooks")
async def get_playbooks(current_user: User = Depends(get_current_user)):
    return soar_engine.get_all_playbooks()


@router.post("/playbooks/{playbook_id}/enable")
async def enable_playbook(playbook_id: str, current_user: User = Depends(get_current_user)):
    soar_engine.enable_playbook(playbook_id)
    return {"status": "enabled"}


@router.post("/playbooks/{playbook_id}/disable")
async def disable_playbook(playbook_id: str, current_user: User = Depends(get_current_user)):
    soar_engine.disable_playbook(playbook_id)
    return {"status": "disabled"}


@router.post("/playbooks/{playbook_id}/trigger")
async def trigger_playbook(
    playbook_id: str,
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    playbook = soar_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    executions = await soar_engine.trigger(playbook.trigger_type, event_data)
    return {"executed": len(executions), "executions": soar_engine.get_executions(playbook_id, 1)}


@router.post("/trigger")
async def trigger_playbooks_by_event(
    event_type: str,
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    executions = await soar_engine.trigger(event_type, event_data)
    return {
        "triggered_playbooks": len(executions),
        "event_type": event_type
    }


@router.get("/executions")
async def get_executions(
    playbook_id: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    return soar_engine.get_executions(playbook_id, limit)


@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, current_user: User = Depends(get_current_user)):
    playbook = soar_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {
        "id": playbook.id,
        "name": playbook.name,
        "description": playbook.description,
        "trigger_type": playbook.trigger_type,
        "conditions": playbook.conditions,
        "enabled": playbook.enabled,
        "actions": [
            {"action_type": a.action_type.value, "params": a.params}
            for a in playbook.actions
        ]
    }
