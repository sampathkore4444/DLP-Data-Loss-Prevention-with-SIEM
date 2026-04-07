from opensearchpy import OpenSearch
from app.core.config import settings

opensearch_client: OpenSearch = None


def get_opensearch() -> OpenSearch:
    global opensearch_client
    if opensearch_client is None:
        opensearch_client = OpenSearch(
            hosts=[settings.OPENSEARCH_URL],
            http_auth=(settings.OPENSEARCH_USERNAME, settings.OPENSEARCH_PASSWORD),
            use_ssl=settings.OPENSEARCH_URL.startswith("https"),
            verify_certs=False,
        )
    return opensearch_client


async def create_log_index():
    client = get_opensearch()
    index_name = "securevault-logs"
    if not client.indices.exists(index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "level": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "ip_address": {"type": "ip"},
                    "message": {"type": "text"},
                    "details": {"type": "object"},
                    "raw": {"type": "text"}
                }
            }
        }
        client.indices.create(index=index_name, body=mapping)


async def create_dlp_index():
    client = get_opensearch()
    index_name = "securevault-dlp-events"
    if not client.indices.exists(index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity": {"type": "keyword"},
                    "policy_name": {"type": "keyword"},
                    "channel": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "data_type": {"type": "keyword"},
                    "file_name": {"type": "keyword"},
                    "details": {"type": "object"}
                }
            }
        }
        client.indices.create(index=index_name, body=mapping)


async def create_incident_index():
    client = get_opensearch()
    index_name = "securevault-incidents"
    if not client.indices.exists(index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "incident_id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "assigned_to": {"type": "keyword"},
                    "description": {"type": "text"},
                    "events": {"type": "object"}
                }
            }
        }
        client.indices.create(index=index_name, body=mapping)
