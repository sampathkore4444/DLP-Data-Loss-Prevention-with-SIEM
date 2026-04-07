import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IOC:
    type: IOCType
    value: str
    severity: ThreatSeverity
    source: str
    confidence: int
    first_seen: str
    last_seen: str
    tags: List[str] = field(default_factory=list)
    description: str = ""
    malware_families: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)


@dataclass
class ThreatFeed:
    feed_id: str
    name: str
    source: str
    url: str
    type: str
    enabled: bool = True
    last_updated: str = None
    entry_count: int = 0


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    verdict: str
    severity: str
    confidence: int
    metadata: Dict = field(default_factory=dict)
    threat_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    description: str = ""


class ThreatIntelligenceService:
    REPUTATION_LISTS = {
        "malicious_ips": [
            "185.199.108.153", "192.0.2.1", "198.51.100.1", "203.0.113.1"
        ],
        "malicious_domains": [
            "evil-bank-fake.com", "malware-download.net", "phishing-bank.org"
        ],
        "suspicious_urls": [
            "http://malware-download.net/payload.exe",
            "https://phishing-bank.org/login"
        ],
        "malware_hashes": [
            "44d88612fea8a8f36de82e1278abb02f",
            "e3b0c44298fc1c149afbf4c8996fb924"
        ]
    }

    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.feeds: Dict[str, ThreatFeed] = {}
        self.enrichment_cache: Dict[str, EnrichmentResult] = {}
        self._init_sample_feeds()

    def _init_sample_feeds(self):
        self.feeds["internal_blocklist"] = ThreatFeed(
            feed_id="internal_blocklist",
            name="Internal Blocklist",
            source="internal",
            url="internal",
            type="blocklist",
            enabled=True,
            entry_count=len(self.REPUTATION_LISTS["malicious_ips"])
        )

    def add_ioc(self, ioc: IOC) -> bool:
        key = f"{ioc.type.value}:{ioc.value}"
        self.iocs[key] = ioc
        logger.info(f"Added IOC: {key}")
        return True

    def get_ioc(self, ioc_type: IOCType, value: str) -> Optional[IOC]:
        key = f"{ioc_type.value}:{value}"
        return self.iocs.get(key)

    def check_ip_reputation(self, ip: str) -> EnrichmentResult:
        cache_key = f"ip:{ip}"
        
        if cache_key in self.enrichment_cache:
            return self.enrichment_cache[cache_key]

        is_malicious = ip in self.REPUTION_LISTS.get("malicious_ips", [])
        
        result = EnrichmentResult(
            ioc=ip,
            ioc_type="ip",
            verdict="malicious" if is_malicious else "clean",
            severity=ThreatSeverity.CRITICAL.value if is_malicious else ThreatSeverity.INFO.value,
            confidence=90 if is_malicious else 100,
            metadata={"source": "local_reputation"}
        )

        self.enrichment_cache[cache_key] = result
        return result

    def check_domain_reputation(self, domain: str) -> EnrichmentResult:
        cache_key = f"domain:{domain}"
        
        if cache_key in self.enrichment_cache:
            return self.enrichment_cache[cache_key]

        is_malicious = domain in self.REPUTION_LISTS.get("malicious_domains", [])
        
        for malicious in self.REPUTION_LISTS.get("malicious_domains", []):
            if malicious in domain:
                is_malicious = True
                break

        result = EnrichmentResult(
            ioc=domain,
            ioc_type="domain",
            verdict="malicious" if is_malicious else "clean",
            severity=ThreatSeverity.CRITICAL.value if is_malicious else ThreatSeverity.INFO.value,
            confidence=85 if is_malicious else 100,
            metadata={"source": "local_reputation"}
        )

        self.enrichment_cache[cache_key] = result
        return result

    def check_url_reputation(self, url: str) -> EnrichmentResult:
        cache_key = f"url:{url}"
        
        if cache_key in self.enrichment_cache:
            return self.enrichment_cache[cache_key]

        is_malicious = url in self.REPUTION_LISTS.get("suspicious_urls", [])

        result = EnrichmentResult(
            ioc=url,
            ioc_type="url",
            verdict="malicious" if is_malicious else "clean",
            severity=ThreatSeverity.CRITICAL.value if is_malicious else ThreatSeverity.INFO.value,
            confidence=80 if is_malicious else 100,
            metadata={"source": "local_reputation"}
        )

        self.enrichment_cache[cache_key] = result
        return result

    def check_file_hash(self, file_hash: str) -> EnrichmentResult:
        cache_key = f"hash:{file_hash}"
        
        if cache_key in self.enrichment_cache:
            return self.enrichment_cache[cache_key]

        is_malicious = file_hash in self.REPUTION_LISTS.get("malware_hashes", [])

        result = EnrichmentResult(
            ioc=file_hash,
            ioc_type="file_hash",
            verdict="malicious" if is_malicious else "clean",
            severity=ThreatSeverity.CRITICAL.value if is_malicious else ThreatSeverity.INFO.value,
            confidence=95 if is_malicious else 100,
            metadata={"source": "local_reputation"}
        )

        self.enrichment_cache[cache_key] = result
        return result

    def enrich_indicator(self, indicator: str, ioc_type: str = None) -> EnrichmentResult:
        if ioc_type is None:
            if "@" in indicator:
                ioc_type = "email"
            elif indicator.startswith("http"):
                ioc_type = "url"
            elif "/" in indicator or "." not in indicator:
                ioc_type = "file_hash"
            elif self._is_ip(indicator):
                ioc_type = "ip"
            else:
                ioc_type = "domain"

        if ioc_type == "ip":
            return self.check_ip_reputation(indicator)
        elif ioc_type == "domain":
            return self.check_domain_reputation(indicator)
        elif ioc_type == "url":
            return self.check_url_reputation(indicator)
        elif ioc_type == "file_hash":
            return self.check_file_hash(indicator)
        
        return EnrichmentResult(
            ioc=indicator,
            ioc_type=ioc_type,
            verdict="unknown",
            severity=ThreatSeverity.INFO.value,
            confidence=0
        )

    def _is_ip(self, value: str) -> bool:
        parts = value.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    def add_feed(self, feed: ThreatFeed) -> bool:
        self.feeds[feed.feed_id] = feed
        return True

    def get_feeds(self) -> List[Dict]:
        return [
            {
                "feed_id": f.feed_id,
                "name": f.name,
                "source": f.source,
                "type": f.type,
                "enabled": f.enabled,
                "last_updated": f.last_updated,
                "entry_count": f.entry_count
            }
            for f in self.feeds.values()
        ]

    def enable_feed(self, feed_id: str) -> bool:
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = True
            return True
        return False

    def disable_feed(self, feed_id: str) -> bool:
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = False
            return True
        return False

    def get_all_iocs(self, ioc_type: IOCType = None, limit: int = 100) -> List[Dict]:
        iocs = self.iocs.values()
        
        if ioc_type:
            iocs = [i for i in iocs if i.type == ioc_type]
        
        return [
            {
                "type": i.type.value,
                "value": i.value,
                "severity": i.severity.value,
                "source": i.source,
                "confidence": i.confidence,
                "tags": i.tags
            }
            for i in list(iocs)[:limit]
        ]

    def export_stix(self) -> Dict:
        return {
            "type": "bundle",
            "id": f"bundle-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{i.value[:8]}",
                    "created": i.first_seen,
                    "modified": i.last_seen,
                    "pattern": f"[ipv4-addr:value = '{i.value}']",
                    "valid_from": i.first_seen,
                    "labels": i.tags
                }
                for i in list(self.iocs.values())[:100]
            ]
        }

    def import_stix(self, bundle: Dict) -> int:
        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                if "ipv4-addr:value" in pattern:
                    value = pattern.split("=")[1].strip("' ")
                    ioc = IOC(
                        type=IOCType.IP,
                        value=value,
                        severity=ThreatSeverity.MEDIUM,
                        source="stix_import",
                        confidence=70,
                        first_seen=obj.get("created", ""),
                        last_seen=obj.get("modified", "")
                    )
                    self.add_ioc(ioc)
                    count += 1
        return count


threat_intel_service = ThreatIntelligenceService()
