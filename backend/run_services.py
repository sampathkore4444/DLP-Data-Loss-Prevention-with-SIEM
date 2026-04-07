import asyncio
import logging
from datetime import datetime

from app.core.database import init_db, async_session_maker
from app.core.opensearch import get_opensearch, create_log_index
from app.core.redis import get_redis
from app.services.siem.correlation_engine import siem_engine
from app.services.websocket import notify_siem_alert, notify_dlp_alert
from app.services.collectors.syslog_collector import get_syslog_collector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def process_syslog_event(event):
    """Process syslog events through the correlation engine"""
    correlated = siem_engine.process_event(event)
    for corr in correlated:
        await notify_siem_alert(
            rule_name=corr.rule_name,
            description=corr.description,
            severity=corr.severity,
            events=[e['event'] for e in corr.events]
        )
        logger.warning(f"Correlation alert: {corr.rule_name} - {corr.description}")


async def start_background_services():
    """Start all background services"""
    logger.info("Starting background services...")
    
    await init_db()
    
    try:
        await create_log_index()
    except Exception as e:
        logger.warning(f"OpenSearch index creation: {e}")
    
    collector = get_syslog_collector()
    collector.register_callback(process_syslog_event)
    
    siem_engine.register_callback(async def on_correlation(correlated):
        logger.warning(f"Correlation triggered: {correlated.rule_name}")
    )
    
    try:
        collector.start()
        logger.info("Syslog collector started on port 514")
    except Exception as e:
        logger.warning(f"Could not start syslog collector: {e}")
    
    redis = await get_redis()
    await redis.set("service:status", "running")
    await redis.set("service:started_at", datetime.now().isoformat())
    
    logger.info("All background services started")
    
    while True:
        await asyncio.sleep(60)
        
        await redis.set("service:last_heartbeat", datetime.now().isoformat())
        
        buffer_status = siem_engine.get_buffer_status()
        for rule_id, count in buffer_status.items():
            if count > 0:
                await redis.set(f"correlation:buffer:{rule_id}", count)


async def main():
    try:
        await start_background_services()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
