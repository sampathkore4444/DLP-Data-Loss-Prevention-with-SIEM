import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataCategory(str, Enum):
    PII = "pii"
    FINANCIAL = "financial"
    HEALTH = "health"
    AUTH = "authentication"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ClassificationResult:
    category: DataCategory
    subcategory: str
    confidence: ConfidenceLevel
    score: float
    matched_patterns: List[str]
    sensitivity_level: int
    recommended_action: str


@dataclass
class DataPattern:
    name: str
    category: DataCategory
    pattern: str
    weight: float
    description: str


class AIDataClassifier:
    PATTERNS = [
        DataPattern("Credit Card", DataCategory.FINANCIAL, r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 0.95, "Credit card number"),
        DataPattern("SSN", DataCategory.PII, r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', 0.95, "Social Security Number"),
        DataPattern("Bank Account", DataCategory.FINANCIAL, r'\b\d{8,17}\b', 0.7, "Bank account number"),
        DataPattern("Routing Number", DataCategory.FINANCIAL, r'\b\d{9}\b', 0.8, "Wire routing number"),
        DataPattern("IBAN", DataCategory.FINANCIAL, r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b', 0.9, "International Bank Account"),
        DataPattern("Email", DataCategory.PII, r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0.85, "Email address"),
        DataPattern("Phone", DataCategory.PII, r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', 0.8, "Phone number"),
        DataPattern("Passport", DataCategory.PII, r'\b[A-Z]{1,2}\d{6,9}\b', 0.9, "Passport number"),
        DataPattern("Driver License", DataCategory.PII, r'\b[A-Z]{1,2}\d{5,8}\b', 0.7, "Driver license"),
        DataPattern("Medical Record", DataCategory.HEALTH, r'\bMRN[:\s]?\d{6,10}\b', 0.85, "Medical Record Number"),
        DataPattern("ICD Code", DataCategory.HEALTH, r'\b[A-Z]\d{2}(\.\d{1,4})?\b', 0.75, "ICD diagnosis code"),
        DataPattern("HIPAA", DataCategory.HEALTH, r'\b(hipaa|patient|diagnosis|treatment)\b', 0.7, "HIPAA-related"),
        DataPattern("API Key", DataCategory.AUTH, r'\b(?:api[_-]?key|apikey)[=:]["\']?[A-Za-z0-9_\-]{20,}\b', 0.9, "API key"),
        DataPattern("Password", DataCategory.AUTH, r'\b(?:password|passwd|pwd)[=:]["\']?[^\s"\']{4,}\b', 0.9, "Password field"),
        DataPattern("JWT Token", DataCategory.AUTH, r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', 0.95, "JWT token"),
        DataPattern("Private Key", DataCategory.AUTH, r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 0.95, "Private key"),
        DataPattern("Secret Token", DataCategory.AUTH, r'\b(?:secret|token|auth)[_-]?(?:key)?[=:]["\']?[A-Za-z0-9_\-]{16,}\b', 0.85, "Secret token"),
        DataPattern("Source Code", DataCategory.INTELLECTUAL_PROPERTY, r'\b(?:class|function|def|import|from|const|let|var|public|private)\b', 0.6, "Source code"),
        DataPattern("Patent", DataCategory.INTELLECTUAL_PROPERTY, r'\b(?:patent|copyright|trademark|发明专利)\b', 0.8, "Patent info"),
        DataPattern("Salary", DataCategory.CONFIDENTIAL, r'\b(?:salary|wage|pay|compensation|bonus)[:\s]?\$?\d{3,6}\b', 0.85, "Salary info"),
        DataPattern("Credit Score", DataCategory.FINANCIAL, r'\bcredit[_-]?score[:\s]?\d{3,4}\b', 0.9, "Credit score"),
    ]

    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()
        self.category_weights = {
            DataCategory.AUTH: 10,
            DataCategory.FINANCIAL: 9,
            DataCategory.HEALTH: 9,
            DataCategory.PII: 8,
            DataCategory.INTELLECTUAL_PROPERTY: 7,
            DataCategory.CONFIDENTIAL: 8,
            DataCategory.PUBLIC: 1
        }

    def _compile_patterns(self):
        for pattern in self.PATTERNS:
            try:
                self.compiled_patterns[pattern.name] = re.compile(pattern.pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Invalid pattern {pattern.name}: {e}")

    def classify(self, content: str) -> List[ClassificationResult]:
        results = []
        
        for pattern in self.PATTERNS:
            if pattern.name not in self.compiled_patterns:
                continue
            
            regex = self.compiled_patterns[pattern.name]
            matches = regex.findall(content)
            
            if matches:
                confidence = self._calculate_confidence(matches, pattern.weight)
                confidence_level = self._get_confidence_level(confidence)
                sensitivity = self._calculate_sensitivity(pattern.category, len(matches))
                action = self._recommend_action(pattern.category, sensitivity)
                
                results.append(ClassificationResult(
                    category=pattern.category,
                    subcategory=pattern.name,
                    confidence=confidence_level,
                    score=confidence,
                    matched_patterns=matches[:10],
                    sensitivity_level=sensitivity,
                    recommended_action=action
                ))
        
        results.sort(key=lambda x: x.score, reverse=True)
        return results

    def classify_file(self, file_path: str) -> List[ClassificationResult]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return self.classify(content)
        except Exception as e:
            logger.error(f"Error classifying file {file_path}: {e}")
            return []

    def _calculate_confidence(self, matches: List[str], base_weight: float) -> float:
        count_factor = min(len(matches) / 10, 1.0)
        return min(base_weight * (0.5 + count_factor * 0.5), 1.0)

    def _get_confidence_level(self, score: float) -> ConfidenceLevel:
        if score >= 0.8:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _calculate_sensitivity(self, category: DataCategory, match_count: int) -> int:
        base = self.category_weights.get(category, 5)
        count_bonus = min(match_count * 0.1, 2)
        return min(int(base + count_bonus), 10)

    def _recommend_action(self, category: DataCategory, sensitivity: int) -> str:
        if category in [DataCategory.AUTH, DataCategory.FINANCIAL]:
            return "block"
        elif category == DataCategory.HEALTH:
            return "quarantine"
        elif sensitivity >= 8:
            return "quarantine"
        elif sensitivity >= 5:
            return "notify"
        return "allow"

    def get_data_inventory(self, results: List[ClassificationResult]) -> Dict:
        inventory = {}
        for r in results:
            cat = r.category.value
            if cat not in inventory:
                inventory[cat] = {"count": 0, "sensitivity": 0, "matches": 0}
            inventory[cat]["count"] += 1
            inventory[cat]["sensitivity"] = max(inventory[cat]["sensitivity"], r.sensitivity_level)
            inventory[cat]["matches"] += len(r.matched_patterns)
        
        total_sensitivity = sum(i["sensitivity"] for i in inventory.values())
        
        return {
            "categories_found": len(inventory),
            "inventory": inventory,
            "overall_risk_score": min(total_sensitivity / 10 * 100, 100),
            "timestamp": datetime.now().isoformat()
        }


ai_classifier = AIDataClassifier()
