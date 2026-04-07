from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.models.models import User
from app.services.ai.threat_hunting import threat_hunting
from app.services.ai.security_scorecard import security_scorecard
from app.services.ai.compliance_engine import compliance_engine
from app.services.ai.network_analytics import network_analytics

router = APIRouter(prefix="/ai", tags=["Advanced AI"])


@router.get("/hunting/hypotheses")
async def get_hypotheses(current_user: User = Depends(get_current_user)):
    return threat_hunting.get_hypotheses()


@router.post("/hunting/run/{hypothesis_id}")
async def run_hunt(
    hypothesis_id: str,
    current_user: User = Depends(get_current_user)
):
    findings = threat_hunting.run_hunt(hypothesis_id)
    return {
        "hypothesis_id": hypothesis_id,
        "findings_count": len(findings),
        "findings": [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "indicators": f.indicators,
                "timestamp": f.timestamp
            }
            for f in findings
        ]
    }


@router.post("/hunting/run-all")
async def run_all_hunts(current_user: User = Depends(get_current_user)):
    return threat_hunting.run_all_hunts()


@router.get("/hunting/findings")
async def get_findings(
    hypothesis_id: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    return threat_hunting.get_findings(hypothesis_id, limit)


@router.get("/hunting/mitre-coverage")
async def get_mitre_coverage(current_user: User = Depends(get_current_user)):
    return threat_hunting.get_mitre_coverage()


@router.get("/scorecard")
async def get_security_scorecard(current_user: User = Depends(get_current_user)):
    return security_scorecard.calculate_score()


@router.get("/scorecard/trend")
async def get_scorecard_trend(
    days: int = 30,
    current_user: User = Depends(get_current_user)
):
    return security_scorecard.get_trend(days)


@router.get("/scorecard/industry-compare")
async def compare_with_industry(
    industry_avg: float = 75.0,
    current_user: User = Depends(get_current_user)
):
    return security_scorecard.compare_with_industry(industry_avg)


@router.get("/compliance")
async def get_compliance(current_user: User = Depends(get_current_user)):
    return compliance_engine.get_compliance_report()


@router.get("/compliance/{framework}")
async def get_framework_compliance(
    framework: str,
    current_user: User = Depends(get_current_user)
):
    return compliance_engine.check_compliance(framework)


@router.get("/compliance/{framework}/remediation")
async def get_remediation_plan(
    framework: str,
    current_user: User = Depends(get_current_user)
):
    return compliance_engine.get_remediation_plan(framework)


@router.get("/network/traffic")
async def analyze_traffic(
    flows: list = None,
    current_user: User = Depends(get_current_user)
):
    if flows is None:
        flows = []
    return network_analytics.analyze_traffic(flows)


@router.get("/network/top-talkers")
async def get_top_talkers(
    limit: int = 10,
    current_user: User = Depends(get_current_user)
):
    return network_analytics.get_top_talkers(limit)


@router.get("/network/ip/{ip}")
async def get_ip_profile(
    ip: str,
    current_user: User = Depends(get_current_user)
):
    profile = network_analytics.get_ip_profile(ip)
    if not profile:
        raise HTTPException(status_code=404, detail="IP not found")
    return profile


@router.get("/network/geo")
async def get_geo_analysis(current_user: User = Depends(get_current_user)):
    return network_analytics.get_geo_analysis()


@router.get("/network/anomalies")
async def get_network_anomalies(
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    return network_analytics.anomalies[-limit:]
