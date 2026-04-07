from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import re
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    id: str
    index: str
    title: str
    description: str
    timestamp: str
    source: str
    relevance_score: float
    highlights: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class SearchQuery:
    query: str
    filters: Dict = field(default_factory=dict)
    date_range: Dict = None
    indices: List[str] = field(default_factory=list)
    limit: int = 50
    highlight: bool = True


class SmartSearchEngine:
    STOP_WORDS = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "from", "is", "are", "was", "were", "be", "been", "being"}

    def __init__(self):
        self.search_history = []
        self.saved_searches = {}
        self.correlation_cache = {}

    def search(self, query: SearchQuery) -> List[SearchResult]:
        results = []
        
        parsed_query = self._parse_query(query.query)
        
        for index in query.indices:
            index_results = self._search_index(index, parsed_query, query)
            results.extend(index_results)
        
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        
        results = results[:query.limit]
        
        self._record_search(query.query, len(results))
        
        return results

    def _parse_query(self, query: str) -> Dict:
        query_lower = query.lower()
        tokens = re.findall(r'\w+', query_lower)
        tokens = [t for t in tokens if t not in self.STOP_WORDS and len(t) > 2]
        
        operators = self._extract_operators(query)
        
        return {
            "tokens": tokens,
            "operators": operators,
            "original": query
        }

    def _extract_operators(self, query: str) -> Dict:
        operators = {}
        
        severity_match = re.search(r'severity[:\s]*(critical|high|medium|low)', query, re.IGNORECASE)
        if severity_match:
            operators["severity"] = severity_match.group(1).lower()
        
        source_match = re.search(r'source[:\s]*(\w+)', query, re.IGNORECASE)
        if source_match:
            operators["source"] = source_match.group(1).lower()
        
        user_match = re.search(r'user[:\s]*(\w+@\w+)', query, re.IGNORECASE)
        if user_match:
            operators["user"] = user_match.group(1).lower()
        
        ip_match = re.search(r'ip[:\s]*(\d+\.\d+\.\d+\.\d+)', query, re.IGNORECASE)
        if ip_match:
            operators["ip"] = ip_match.group(1)
        
        return operators

    def _search_index(self, index: str, parsed: Dict, query: SearchQuery) -> List[SearchResult]:
        results = []
        
        sample_data = self._get_sample_data(index)
        
        for item in sample_data:
            score = self._calculate_relevance(item, parsed, query)
            
            if score > 0:
                highlights = []
                if query.highlight:
                    highlights = self._generate_highlights(item, parsed["tokens"])
                
                results.append(SearchResult(
                    id=str(item.get("id", "")),
                    index=index,
                    title=item.get("title", ""),
                    description=item.get("message", "")[:200],
                    timestamp=item.get("timestamp", ""),
                    source=item.get("source", index),
                    relevance_score=score,
                    highlights=highlights,
                    metadata=item
                ))
        
        return results

    def _calculate_relevance(self, item: Dict, parsed: Dict, query: SearchQuery) -> float:
        score = 0
        
        text_fields = [str(v) for v in item.values() if v]
        combined_text = " ".join(text_fields).lower()
        
        for token in parsed["tokens"]:
            if token in combined_text:
                score += 10
                
                if token in item.get("title", "").lower():
                    score += 15
                if token in item.get("message", "").lower():
                    score += 5
        
        operators = parsed.get("operators", {})
        for key, value in operators.items():
            item_value = str(item.get(key, "")).lower()
            if value in item_value:
                score += 20
        
        if query.filters:
            for key, value in query.filters.items():
                if str(item.get(key, "")) == str(value):
                    score += 25
                elif str(value).lower() in str(item.get(key, "")).lower():
                    score += 10
        
        return score

    def _generate_highlights(self, item: Dict, tokens: List[str]) -> List[str]:
        highlights = []
        
        message = str(item.get("message", ""))
        
        for token in tokens[:5]:
            if token.lower() in message.lower():
                pattern = re.compile(re.escape(token), re.IGNORECASE)
                match = pattern.search(message)
                if match:
                    start = max(0, match.start() - 30)
                    end = min(len(message), match.end() + 30)
                    snippet = message[start:end]
                    highlights.append(f"...{snippet}...")
        
        return highlights[:3]

    def _get_sample_data(self, index: str) -> List[Dict]:
        samples = {
            "dlp_events": [
                {"id": 1, "title": "Credit Card Detected", "message": "Credit card number detected in email", "timestamp": "2026-04-07T10:00:00", "source": "dlp", "severity": "critical", "user": "john@example.com"},
                {"id": 2, "title": "SSN in USB", "message": "SSN data copied to USB device", "timestamp": "2026-04-07T09:30:00", "source": "dlp", "severity": "high", "user": "jane@example.com"},
                {"id": 3, "title": "Account Number Web Upload", "message": "Account number detected in web upload", "timestamp": "2026-04-07T08:00:00", "source": "dlp", "severity": "medium", "user": "bob@example.com"},
            ],
            "siem_events": [
                {"id": 1, "title": "SSH Brute Force", "message": "Multiple failed SSH login attempts from 192.168.1.100", "timestamp": "2026-04-07T11:00:00", "source": "siem", "severity": "high", "source_ip": "192.168.1.100"},
                {"id": 2, "title": "Port Scan Detected", "message": "Port scanning activity from internal host", "timestamp": "2026-04-07T10:30:00", "source": "siem", "severity": "medium"},
                {"id": 3, "title": "Firewall Rule Change", "message": "Firewall rule modified by admin", "timestamp": "2026-04-07T09:00:00", "source": "siem", "severity": "low"},
            ],
            "incidents": [
                {"id": 1, "title": "Data Exfiltration Attempt", "message": "Critical DLP alert - credit card data leaving network", "timestamp": "2026-04-07T10:00:00", "source": "incident", "severity": "critical", "status": "investigating"},
                {"id": 2, "title": "Unauthorized Access", "message": "User accessed sensitive data without authorization", "timestamp": "2026-04-07T08:00:00", "source": "incident", "severity": "high", "status": "open"},
            ]
        }
        
        return samples.get(index, [])

    def _record_search(self, query: str, result_count: int):
        self.search_history.append({
            "query": query,
            "results": result_count,
            "timestamp": datetime.now().isoformat()
        })
        if len(self.search_history) > 100:
            self.search_history = self.search_history[-50:]

    def natural_language_search(self, query: str) -> Dict:
        parsed = self._parse_query(query)
        
        intent = self._detect_intent(query)
        
        search_query = SearchQuery(
            query=query,
            indices=self._suggest_indices(intent),
            limit=50
        )
        
        results = self.search(search_query)
        
        return {
            "intent": intent,
            "query": query,
            "results_count": len(results),
            "results": [
                {
                    "id": r.id,
                    "title": r.title,
                    "description": r.description,
                    "source": r.source,
                    "timestamp": r.timestamp,
                    "relevance": r.relevance_score,
                    "highlights": r.highlights
                }
                for r in results
            ],
            "suggestions": self._generate_suggestions(query)
        }

    def _detect_intent(self, query: str) -> str:
        query_lower = query.lower()
        
        if any(w in query_lower for w in ["show", "get", "list", "find"]):
            if "critical" in query_lower or "high severity" in query_lower:
                return "critical_alerts"
            elif "dlp" in query_lower:
                return "dlp_events"
            elif "user" in query_lower or "who" in query_lower:
                return "user_activity"
            elif "ip" in query_lower or "source" in query_lower:
                return "ip_lookup"
        
        if "attack" in query_lower or "threat" in query_lower:
            return "threats"
        
        if "incident" in query_lower:
            return "incidents"
        
        return "general"

    def _suggest_indices(self, intent: str) -> List[str]:
        mapping = {
            "critical_alerts": ["dlp_events", "siem_events", "incidents"],
            "dlp_events": ["dlp_events"],
            "user_activity": ["dlp_events", "siem_events"],
            "ip_lookup": ["siem_events"],
            "threats": ["siem_events"],
            "incidents": ["incidents"],
            "general": ["dlp_events", "siem_events", "incidents"]
        }
        return mapping.get(intent, ["dlp_events", "siem_events", "incidents"])

    def _generate_suggestions(self, query: str) -> List[str]:
        suggestions = []
        
        if "critical" not in query.lower():
            suggestions.append("show critical severity events")
        if "dlp" not in query.lower():
            suggestions.append("find DLP violations")
        if "last" not in query.lower():
            suggestions.append("show events from last 24 hours")
        
        return suggestions[:3]

    def save_search(self, name: str, query: SearchQuery):
        self.saved_searches[name] = query

    def get_saved_searches(self) -> Dict:
        return self.saved_searches

    def get_search_analytics(self) -> Dict:
        if not self.search_history:
            return {"total_searches": 0, "popular_queries": []}
        
        query_counts = {}
        for search in self.search_history:
            q = search["query"]
            query_counts[q] = query_counts.get(q, 0) + 1
        
        popular = sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_searches": len(self.search_history),
            "popular_queries": [{"query": q, "count": c} for q, c in popular],
            "avg_results": sum(s["results"] for s in self.search_history) / len(self.search_history)
        }


smart_search = SmartSearchEngine()
