# SecureVault DLP & SIEM Platform

Enterprise Data Loss Prevention and Security Information and Event Management for Commercial Banks.

## Tech Stack

### Backend
- **Language:** Python 3.11 (FastAPI), Go 1.21 (Agents)
- **Database:** PostgreSQL 15 (async)
- **Cache:** Redis 7
- **Hot Storage:** OpenSearch 2.12
- **Cold Storage:** MinIO (S3-compatible)
- **Message Queue:** RabbitMQ (ready for scaling)

### Frontend
- **Framework:** React 18
- **UI Library:** Ant Design 5
- **Charts:** Recharts

## Project Structure

```
backend/
├── app/
│   ├── api/routes/       # REST API endpoints
│   ├── core/            # Config, DB, Redis, OpenSearch, MinIO
│   ├── models/          # SQLAlchemy models
│   ├── schemas/         # Pydantic schemas
│   └── services/
│       ├── collectors/  # Endpoint agent, Network sensor, Syslog
│       ├── detection/   # DLP engine, ML anomaly detection
│       ├── scheduler/   # Reports (scheduled + custom)
│       ├── siem/        # Correlation engine
│       └── soar/        # Playbook automation
├── cmd/
│   ├── agent/           # Go endpoint agent
│   └── sensor/          # Go network sensor
└── requirements.txt

frontend/
├── src/
│   ├── components/      # Reusable UI components
│   ├── pages/           # Dashboard, Policies, Events, etc.
│   └── services/        # API client
└── package.json
```

## Quick Start

```bash
# Start all services
docker-compose up --build

# Access
# API: http://localhost:8000
# Frontend: http://localhost:3000
# OpenSearch: http://localhost:9200 (admin/Admin123!)
# MinIO Console: http://localhost:9001
```

## Build Agents (Go)

```bash
# Endpoint Agent
cd backend/cmd/agent
go build -o endpoint-agent main.go

# Network Sensor  
cd ../sensor
go build -o network-sensor main.go
```

## API Endpoints

| Category | Endpoints |
|----------|-----------|
| Auth | `/api/auth/login`, `/api/auth/register` |
| DLP | `/api/dlp/policies`, `/api/dlp/events` |
| SIEM | `/api/siem/events`, `/api/siem/logs` |
| Incidents | `/api/incidents`, `/api/incidents/stats` |
| Agents | `/api/agents/endpoint/*`, `/api/agents/network/*` |
| ML | `/api/agents/ml/anomaly/*` |
| SOAR | `/api/soar/playbooks`, `/api/soar/trigger` |
| Reports | `/api/reports/custom/*` |
| WebSocket | `/api/services/ws` |

## Configuration

Environment variables in docker-compose.yml:
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection
- `OPENSEARCH_URL` - OpenSearch URL
- `MINIO_ENDPOINT` - MinIO server
- `SECRET_KEY` - JWT signing key

## Features

- **DLP:** Pattern-based detection, policy engine, channel monitoring
- **SIEM:** Log collection, correlation rules, threat detection
- **ML:** Anomaly detection, user behavioral baselines
- **SOAR:** Automated playbooks, incident response
- **Reports:** Custom report builder, scheduled reports
- **Real-time:** WebSocket alerts, live dashboards
