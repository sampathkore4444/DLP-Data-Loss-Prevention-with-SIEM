from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.models.models import User
from app.services.ai.data_classifier import ai_classifier
from app.services.ai.smart_triage import smart_triage
from app.services.ai.predictive_analytics import predictive_analytics
from app.services.ai.smart_search import smart_search, SearchQuery

router = APIRouter(prefix="/ai", tags=["AI Engines"])


@router.get("/classifier/categories")
async def get_data_categories(current_user: User = Depends(get_current_user)):
    from app.services.ai.data_classifier import DataCategory
    return [c.value for c in DataCategory]


@router.post("/classifier/classify")
async def classify_content(
    content: str,
    current_user: User = Depends(get_current_user)
):
    results = ai_classifier.classify(content)
    return {
        "classifications": [
            {
                "category": r.category.value,
                "subcategory": r.subcategory,
                "confidence": r.confidence.value,
                "score": r.score,
                "matched_patterns": r.matched_patterns[:5],
                "sensitivity_level": r.sensitivity_level,
                "recommended_action": r.recommended_action
            }
            for r in results
        ],
        "inventory": ai_classifier.get_data_inventory(results)
    }


@router.post("/classifier/classify-file")
async def classify_file(
    file_path: str,
    current_user: User = Depends(get_current_user)
):
    results = ai_classifier.classify_file(file_path)
    return {
        "classifications": [
            {
                "category": r.category.value,
                "subcategory": r.subcategory,
                "sensitivity_level": r.sensitivity_level
            }
            for r in results
        ]
    }


@router.get("/triage/rules")
async def get_triage_rules(current_user: User = Depends(get_current_user)):
    return smart_triage.get_rules()


@router.post("/triage/triage")
async def triage_incident(
    incident: dict,
    current_user: User = Depends(get_current_user)
):
    result = smart_triage.triage(incident)
    smart_triage.add_incident_to_history(incident)
    
    return {
        "priority": result.priority.value,
        "action": result.action.value,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "similar_incidents": result.similar_incidents,
        "recommended_playbook": result.recommended_playbook
    }


@router.get("/triage/statistics")
async def get_triage_statistics(current_user: User = Depends(get_current_user)):
    return smart_triage.get_statistics()


@router.post("/triage/false-positive")
async def add_false_positive(
    pattern: dict,
    current_user: User = Depends(get_current_user)
):
    smart_triage.add_false_positive_pattern(pattern)
    return {"status": "added"}


@router.get("/predictive/riskscores")
async def get_risk_scores(current_user: User = Depends(get_current_user)):
    return predictive_analytics.get_all_risk_scores()


@router.get("/predictive/user/{user_id}/risk")
async def get_user_risk(
    user_id: str,
    events: list = None,
    current_user: User = Depends(get_current_user)
):
    if events is None:
        risk = predictive_analytics.get_user_risk(user_id)
        if not risk:
            return {"error": "No risk data found"}
        return {
            "user_id": risk.user_id,
            "score": risk.score,
            "trend": risk.trend,
            "factors": risk.factors,
            "last_updated": risk.last_updated
        }
    else:
        risk = predictive_analytics.calculate_user_risk(user_id, events)
        return {
            "user_id": risk.user_id,
            "score": risk.score,
            "trend": risk.trend,
            "factors": risk.factors
        }


@router.get("/predictive/predictions")
async def get_predictions(
    user_id: str = None,
    current_user: User = Depends(get_current_user)
):
    predictions = predictive_analytics.predict_threats(user_id)
    return {
        "predictions": [
            {
                "type": p.type,
                "probability": p.probability,
                "timeframe": p.timeframe,
                "description": p.description,
                "severity": p.severity,
                "indicators": p.indicators
            }
            for p in predictions
        ]
    }


@router.get("/predictive/org-risk")
async def get_org_risk(current_user: User = Depends(get_current_user)):
    return predictive_analytics.calculate_org_risk_score()


@router.post("/search/natural")
async def natural_language_search(
    query: str,
    current_user: User = Depends(get_current_user)
):
    return smart_search.natural_language_search(query)


@router.post("/search")
async def search(
    query: str,
    indices: list = None,
    filters: dict = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    sq = SearchQuery(
        query=query,
        indices=indices or ["dlp_events", "siem_events", "incidents"],
        filters=filters or {},
        limit=limit
    )
    
    results = smart_search.search(sq)
    return {
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "source": r.source,
                "timestamp": r.timestamp,
                "relevance_score": r.relevance_score,
                "highlights": r.highlights
            }
            for r in results
        ],
        "total": len(results)
    }


@router.get("/search/analytics")
async def get_search_analytics(current_user: User = Depends(get_current_user)):
    return smart_search.get_search_analytics()


@router.get("/search/saved")
async def get_saved_searches(current_user: User = Depends(get_current_user)):
    return smart_search.get_saved_searches()
