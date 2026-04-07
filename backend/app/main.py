from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import init_db
from app.core.redis import close_redis
from app.core.opensearch import create_log_index, create_dlp_index, create_incident_index
from app.core.minio import init_minio
from app.api.routes import auth, dlp, siem, incidents, services, agents, soar, reports, mfa, threat_intel, ai, advanced_ai, ldap


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    try:
        await create_log_index()
        await create_dlp_index()
        await create_incident_index()
    except Exception as e:
        print(f"OpenSearch initialization: {e}")
    try:
        await init_minio()
    except Exception as e:
        print(f"MinIO initialization: {e}")
    yield
    await close_redis()


app = FastAPI(
    title="SecureVault - DLP & SIEM Platform",
    description="Enterprise Data Loss Prevention and Security Information and Event Management for Banks",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(dlp.router, prefix="/api")
app.include_router(siem.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(services.router, prefix="/api")
app.include_router(agents.router, prefix="/api")
app.include_router(soar.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(mfa.router, prefix="/api")
app.include_router(threat_intel.router, prefix="/api")
app.include_router(ai.router, prefix="/api")
app.include_router(advanced_ai.router, prefix="/api")
app.include_router(ldap.router, prefix="/api")


@app.get("/")
async def root():
    return {"message": "SecureVault API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
