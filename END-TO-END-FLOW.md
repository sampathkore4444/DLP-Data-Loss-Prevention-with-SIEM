# SecureVault DLP & SIEM Platform - End to End Flow

## Table of Contents
1. [Platform Overview](#platform-overview)
2. [Architecture Overview](#architecture-overview)
3. [Phase 1: Data Collection & Ingestion](#phase-1-data-collection--ingestion)
4. [Phase 2: Detection & Analysis](#phase-2-detection--analysis)
5. [Phase 3: AI Processing & Intelligence](#phase-3-ai-processing--intelligence)
6. [Phase 4: Response & Automation](#phase-4-response--automation)
7. [Phase 5: Reporting & Visualization](#phase-5-reporting--visualization)
8. [Frontend to Backend Communication](#frontend-to-backend-communication)
9. [Deployment Guide](#deployment-guide)

---

## Platform Overview

SecureVault is an enterprise-grade **Data Loss Prevention (DLP)** and **Security Information and Event Management (SIEM)** platform designed specifically for commercial banks. It provides comprehensive monitoring, threat detection, incident response, and compliance management.

### Key Capabilities
- Real-time data loss prevention across multiple channels
- Security event correlation and threat detection
- AI-powered anomaly detection and predictive analytics
- Automated incident response with SOAR playbooks
- Compliance management for PCI-DSS, GDPR, SOX, GLBA
- Comprehensive reporting and dashboard visualization

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECUREVAULT PLATFORM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        FRONTEND (React + Ant Design)                 │   │
│  │    Dashboard | DLP Policies | SIEM Events | Incidents | Reports       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                          │
│                                    ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    BACKEND API (FastAPI Python)                       │   │
│  │   Auth | DLP | SIEM | Incidents | Agents | SOAR | Reports | AI         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                          │
│         ┌──────────────────────────┼──────────────────────────┐            │
│         ▼                          ▼                          ▼            │
│  ┌─────────────┐          ┌─────────────┐           ┌─────────────┐      │
│  │  Database   │          │  OpenSearch │           │   MinIO     │      │
│  │ PostgreSQL  │          │  (Hot)      │           │  (Cold)     │      │
│  └─────────────┘          └─────────────┘           └─────────────┘      │
│                                    │                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    COLLECTION LAYER                                   │   │
│  │   Go Agents | Syslog | Endpoint | Network Sensor                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    AI/ML LAYER                                         │   │
│  │   Classification | Triage | Prediction | Hunting | Analytics           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Data Collection & Ingestion

### 1.1 Endpoint Agent (Go)
**Location:** `backend/cmd/agent/main.go`

The lightweight Go-based endpoint agent monitors file system activities on workstations:

```
Flow:
1. Agent starts → Watches configured paths (USB, Print, Network directories)
2. File created/modified detected
3. Checks if file extension is sensitive (.xlsx, .pdf, .csv, .doc, etc.)
4. Creates FileEvent with metadata (path, size, hash, channel)
5. Sends HTTP POST to backend API: /api/agents/endpoint/event
```

**Key Features:**
- Watches USB drives, print spool directories, network shares
- Calculates SHA-256 hash of file content (first 1KB)
- Detects channel based on file path
- Supports Windows and Linux

### 1.2 Network Sensor (Go)
**Location:** `backend/cmd/sensor/main.go`

Go-based network traffic analyzer:

```
Flow:
1. Sensor starts → Simulates/collects network flows
2. Analyzes each flow for:
   - Sensitive protocols (FTP, Telnet, SMB)
   - Large data transfers (>100MB)
   - Suspicious ports (4444, 5555, 31337)
   - External IP transfers
3. Creates Alert if conditions met
4. Sends to backend: /api/agents/network/flow
```

### 1.3 Syslog Collector
**Location:** `backend/app/services/collectors/syslog_collector.py`

Python-based syslog receiver for network devices:

```
Flow:
1. Collector starts on UDP/TCP port 514
2. Receives syslog messages from firewalls, IDS, routers
3. Parses CEF (Common Event Format) and standard syslog
4. Extracts key fields: source IP, hostname, message
5. Detects event types: authentication_failure, authentication_success
6. Sends to Correlation Engine for processing
```

### 1.4 Log Collection (SIEM)
**Location:** `backend/app/api/routes/siem.py`

REST API endpoints for external log ingestion:

```
Endpoints:
- POST /api/siem/events → Store security events
- POST /api/syslog → Receive syslog messages
- GET /api/siem/logs → Query logs from OpenSearch
- GET /api/siem/events/search → Full-text search
```

---

## Phase 2: Detection & Analysis

### 2.1 DLP Detection Engine
**Location:** `backend/app/services/detection/dlp_engine.py`

Pattern-based content scanning:

```
Flow:
1. Content received (from API or agent)
2. Iterates through enabled DLP policies
3. For each policy:
   a. Get data type pattern (credit_card, ssn, etc.)
   b. Compile regex pattern
   c. Search content for matches
   d. Validate with Luhn check (for credit cards)
   e. Mask sensitive values
4. Create DLPMatch objects for all matches
5. Determine action (allow/block/quarantine/notify)
6. Store event in database
7. Trigger WebSocket alert
```

**Pre-built Patterns:**
- Credit Card: `\b(?:\d{4}[-\s]?){3}\d{4}\b` + Luhn validation
- SSN: `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`
- Account Number: `\b\d{8,17}\b`
- API Key, Password, Email, Phone, IBAN, etc.

### 2.2 SIEM Correlation Engine
**Location:** `backend/app/services/siem/correlation_engine.py`

Rule-based threat detection with time-windowed correlation:

```
Flow:
1. Event received from collector
2. For each enabled correlation rule:
   a. Check if event matches rule source
   b. Evaluate condition (e.g., "failed_ssh_login")
   c. Add event to rule's buffer
   d. Check if buffer exceeds threshold
   e. If threshold exceeded → Create CorrelatedEvent
3. Trigger callbacks for each correlation
4. Send alert via WebSocket
```

**Pre-built Rules:**
- SSH Brute Force: 5 failed logins in 5 minutes
- Web Login Brute Force: 10 failures in 5 minutes
- Port Scanning: 20 connections in 1 minute
- Data Exfiltration: >100MB transfer to external IP
- Privilege Escalation: Admin group changes
- After Hours Access: Outside 7AM-9PM
- DLP + Anomaly: Critical DLP + behavioral anomaly

### 2.3 ML Anomaly Detection
**Location:** `backend/app/services/detection/ml_anomaly.py`

Statistical Z-score based user behavior analysis:

```
Flow:
1. User baseline trained with historical data:
   - Login hours (mean, std)
   - Login days
   - Average session duration
   - Average data transfer
   - Trusted devices and IPs
2. New event received
3. Calculate anomaly scores:
   - Unusual login hour: Z-score > 3
   - Untrusted IP address
   - Untrusted device
   - Large data transfer (>3x baseline)
   - Bulk file access (>3x baseline)
4. If score exceeds threshold:
   - Create AnomalyAlert
   - Calculate severity (critical/high/medium/low)
   - Store in history
5. Trigger callback
```

---

## Phase 3: AI Processing & Intelligence

### 3.1 AI Data Classifier
**Location:** `backend/app/services/ai/data_classifier.py`

Automatic sensitive data categorization:

```
Flow:
1. Content submitted for classification
2. Run 20+ regex patterns across content
3. For each match:
   - Calculate confidence (base weight × count factor)
   - Determine confidence level (high/medium/low)
   - Calculate sensitivity (1-10 scale)
   - Recommend action (block/quarantine/notify/allow)
4. Return classified results with inventory
5. Calculate overall risk score
```

**Categories:**
- PII (Personally Identifiable Information)
- Financial (Credit Cards, Account Numbers)
- Health (Medical Records, HIPAA)
- Authentication (Passwords, API Keys, JWT)
- Intellectual Property (Source Code, Patents)
- Confidential (Salary, Credit Score)

### 3.2 Smart Incident Triage
**Location:** `backend/app/services/ai/smart_triage.py`

Automated incident prioritization and false positive detection:

```
Flow:
1. Incident/alert received
2. Check false positive patterns:
   - Internal IP ranges
   - Known admin users
   - Normal login patterns
3. Match against triage rules (priority order):
   - Critical DLP → Immediate
   - Brute Force → Escalate
   - Data Exfiltration → Immediate
   - Insider Threat → Investigate
   - After Hours → Monitor
4. Calculate confidence score
5. Find similar past incidents
6. Recommend SOAR playbook
7. Output: Priority, Action, Confidence, Reasoning
```

### 3.3 Predictive Analytics
**Location:** `backend/app/services/ai/predictive_analytics.py`

User risk scoring and threat prediction:

```
Flow:
1. Aggregate events for user over time window
2. Calculate risk factors:
   - Failed logins count × 5 (max 100)
   - DLP violations × 15 (max 100)
   - After hours access (+25)
   - New destinations × 10 (max 50)
   - Large transfers (+40)
   - Privilege escalation (+35)
3. Sum all factors (max 100) = Risk Score
4. Determine trend (stable/increasing/decreasing)
5. Predict threat types based on factors:
   - DLP violations → Data Exfiltration
   - Failed logins → Account Compromise
   - Privilege changes → Privilege Abuse
6. Generate prediction with probability and severity
```

### 3.4 Threat Hunting
**Location:** `backend/app/services/ai/threat_hunting.py`

Proactive threat search using MITRE ATT&CK framework:

```
Flow:
1. Execute hunt hypothesis:
   a. Run predefined queries (SIEM, DLP, Network)
   b. Analyze results
   c. Generate findings
2. For each finding:
   - Map to MITRE tactics/techniques
   - Calculate severity
   - Extract indicators
3. Store findings with timestamps
4. Calculate MITRE coverage
```

**Hypotheses:**
- Active Brute Force Attack
- Data Exfiltration in Progress
- Insider Threat Activity
- Malware Command & Control
- Privilege Escalation Attempt
- Lateral Movement

### 3.5 Security Scorecard
**Location:** `backend/app/services/ai/security_scorecard.py`

Organization-wide security posture scoring:

```
Flow:
1. Evaluate 6 categories (each 100 points max):
   a. Network Security (15% weight)
      - Firewall: 25pts, IDS: 25pts, Segmentation: 15pts, VPN: 20pts
   b. Endpoint Security (15% weight)
      - AV: 20pts, EDR: 25pts, Encryption: 15pts, Patching: 0pts
   c. Identity & Access (20% weight)
      - MFA: 30pts, Password: 20pts, PAM: 15pts, Timeout: 15pts
   d. Data Protection (20% weight)
      - DLP: 30pts, Encryption at rest: 25pts, In transit: 25pts, Backup: 10pts
   e. Threat Detection (15% weight)
      - SIEM: 30pts, Threat Intel: 25pts, Anomaly: 25pts, SOC: 10pts
   f. Compliance (15% weight)
      - PCI-DSS: 35pts, GDPR: 30pts, SOX: 20pts
2. Calculate weighted average = Overall Score
3. Assign Grade (A/B/C/D/F)
4. Determine Risk Level (low/medium/high/critical)
```

### 3.6 Compliance Engine
**Location:** `backend/app/services/ai/compliance_engine.py`

Automated compliance checking for multiple frameworks:

```
Flow:
1. Check framework controls:
   a. PCI DSS: 10 requirements (Req 1-10)
   b. GDPR: 7 articles (Art 5, 6, 7, 15, 17, 32, 33)
   c. SOX: 3 sections (Sec 302, 404, 802)
   d. GLBA, NIST CSF
2. For each control:
   - Query relevant data sources
   - Evaluate status (compliant/non-compliant)
   - Collect evidence
   - Document findings
3. Calculate compliance score
4. Generate remediation plan for non-compliant items
```

### 3.7 Network Analytics
**Location:** `backend/app/services/ai/network_analytics.py`

Traffic pattern analysis and anomaly detection:

```
Flow:
1. Process flow data:
   - Build IP profiles (bytes in/out, connections, destinations)
   - Aggregate protocol statistics
   - Track top talkers
2. Detect anomalies:
   - High volume transfers (>100MB)
   - Beaconing (regular interval connections)
   - New connections spike
   - Port scanning behavior
3. Calculate geo distribution
4. Generate risk scores per IP
```

### 3.8 Smart Search Engine
**Location:** `backend/app/services/ai/smart_search.py`

Natural language search across all data:

```
Flow:
1. Parse natural language query:
   - Tokenize (remove stop words)
   - Extract operators (severity:, source:, user:, ip:)
2. Determine intent:
   - "show critical" → critical_alerts
   - "find DLP" → dlp_events
   - "who did X" → user_activity
3. Suggest appropriate indices
4. Calculate relevance scores:
   - Token match: +10pts
   - Title match: +15pts
   - Message match: +5pts
   - Operator match: +20pts
   - Filter match: +25pts
5. Generate highlights
6. Return ranked results with suggestions
```

---

## Phase 4: Response & Automation

### 4.1 SOAR Playbook Engine
**Location:** `backend/app/services/soar/playbooks.py`

Automated incident response:

```
Flow:
1. Event triggers playbook:
   a. Match event type (dlp_alert, siem_alert, anomaly_alert)
   b. Check conditions match
2. Execute actions in sequence:
   a. BLOCK_USER → Disable account
   b. BLOCK_IP → Add to firewall blocklist
   c. QUARANTINE_FILE → Move to secure storage
   d. CREATE_INCIDENT → Open ticket
   e. NOTIFY_MANAGER → Send email
   f. ESCALATE → Raise priority
   g. ENABLE_MFA → Force MFA enrollment
   h. ISOLATE_ENDPOINT → Network quarantine
   i. WEBHOOK → Call external system
3. Log all actions with results
4. Send notifications via WebSocket
```

**Pre-built Playbooks:**
- pb_dlp_critical: Block user + quarantine + notify
- pb_brute_force: Block IP + incident + email
- pb_insider_threat: Isolate + enable MFA + escalate
- pb_malware_detected: Isolate + incident + scan
- pb_data_exfiltration: Block user + IP + isolate + incident

### 4.2 WebSocket Real-time Alerts
**Location:** `backend/app/services/websocket.py`

Push notifications to frontend:

```
Flow:
1. Client connects to WebSocket endpoint
   - WS /api/services/ws?channel=dlp|siem|incidents|all
2. Server registers connection in ConnectionManager
3. Events trigger broadcasts:
   - DLP Alert → notify_dlp_alert()
   - SIEM Correlation → notify_siem_alert()
   - Incident Created → notify_incident_created()
4. All subscribers receive JSON message
5. Frontend displays real-time notification
```

---

## Phase 5: Reporting & Visualization

### 5.1 Dashboard (Frontend)
**Location:** `frontend/src/pages/Dashboard.js`

Real-time security overview:

```
Components:
- Incident Statistics (Total, Open, Resolved, Critical)
- DLP Events Today / SIEM Events Today
- Incidents by Severity (Pie Chart)
- DLP Events by Channel (Bar Chart)
- Top Violators Table
```

### 5.2 Report Generation
**Location:** `backend/app/services/scheduler/reports.py`

Scheduled and on-demand reports:

```
Report Types:
1. Daily Security Summary
   - Total incidents, open, critical
   - DLP events count
   - Severity breakdown
2. Weekly Compliance Report
   - Incidents by source
   - Resolution rate
   - PCI-DSS/GDPR compliance status
3. DLP Incident Report
   - Events by channel
   - Events by action
   - Top violators
4. Threat Detection Report
   - Events by source
   - Events by severity
   - Threat level assessment
```

### 5.3 Custom Report Builder
**Location:** `backend/app/services/scheduler/custom_reports.py`

User-defined reports with sections:

```
Features:
- Create custom report with name/description
- Add sections: Summary, Metrics, Chart, Table, List
- Configure data source per section
- Set date range
- Export to JSON/HTML
- Schedule recurring generation
```

---

## Frontend to Backend Communication

### API Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                          │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   axios     │  │   WebSocket │  │  Ant Design │          │
│  │   Client    │  │   Manager   │  │    Charts   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   HTTP/WS Requests   │
                    │   (port 3000)       │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │    NGINX (optional) │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │    FastAPI Backend  │
                    │    (port 8000)      │
                    └─────────────────────┘
```

### Authentication Flow

```
1. User enters credentials on Login page
2. POST /api/auth/login with username/password
3. Backend validates against User table:
   - Verify password hash with bcrypt
   - Check is_active flag
4. If valid:
   - Generate JWT access_token (30 min expiry)
   - Generate refresh_token (7 days expiry)
   - Return tokens to frontend
5. Frontend stores tokens in localStorage
6. All subsequent requests include:
   - Header: Authorization: Bearer <token>
7. Token validation middleware:
   - Decode JWT with SECRET_KEY
   - Check expiration
   - Load user from database
   - Add user to request context
```

### API Endpoints Overview

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Auth | /api/auth/login | POST | User login |
| Auth | /api/auth/register | POST | User registration |
| Auth | /api/auth/me | GET | Current user |
| DLP | /api/dlp/policies | GET/POST | CRUD policies |
| DLP | /api/dlp/events | GET | List DLP events |
| DLP | /api/dlp/stats/summary | GET | DLP statistics |
| SIEM | /api/siem/events | GET | List SIEM events |
| SIEM | /api/siem/logs | GET | Query OpenSearch logs |
| SIEM | /api/siem/search | GET | Full-text search |
| Incidents | /api/incidents | GET/POST | CRUD incidents |
| Incidents | /api/incidents/stats/dashboard | GET | Dashboard stats |
| Agents | /api/agents/endpoint/start | POST | Start endpoint agent |
| Agents | /api/agents/network/start | POST | Start network sensor |
| Agents | /api/agents/ml/anomaly/detect | POST | Detect anomalies |
| SOAR | /api/soar/playbooks | GET | List playbooks |
| SOAR | /api/soar/trigger | POST | Trigger playbook |
| AI | /api/ai/classifier/classify | POST | Classify content |
| AI | /api/ai/triage/triage | POST | Triage incident |
| AI | /api/ai/predictive/predictions | GET | Get predictions |
| AI | /api/ai/hunting/run/{id} | POST | Run hunt |
| AI | /api/ai/scorecard | GET | Security score |
| AI | /api/ai/compliance | GET | Compliance status |
| Reports | /api/reports/custom | GET/POST | Custom reports |
| Reports | /api/reports/custom/{id}/generate | POST | Generate report |
| MFA | /api/mfa/init | POST | Initialize MFA |
| MFA | /api/mfa/verify | POST | Verify MFA code |
| Threat Intel | /api/threat-intel/check/{indicator} | GET | Check IOC |
| Threat Intel | /api/threat-intel/iocs | GET/POST | Manage IOCs |
| WebSocket | /api/services/ws | WS | Real-time alerts |

### WebSocket Communication

```javascript
// Frontend connection
const ws = new WebSocket('http://localhost:8000/api/services/ws?channel=all');

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  
  switch(alert.type) {
    case 'dlp_alert':
      notification.error(alert.title);
      break;
    case 'siem_alert':
      notification.warning(alert.title);
      break;
    case 'incident':
      notification.info(alert.title);
      break;
  }
};
```

---

## Deployment Guide

### Option 1: Docker Compose (Recommended)

#### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum for all services

#### Start Services

```bash
# Navigate to project directory
cd "DLP - Data Loss Prevention Banks"

# Build and start all services
docker-compose up --build

# Or start in detached mode
docker-compose up -d --build

# Check service status
docker-compose ps
```

#### Stop Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes ( WARNING: deletes all data)
docker-compose down -v

# Stop and remove images
docker-compose down --rmi all
```

#### Service URLs After Startup

| Service | URL | Credentials |
|---------|-----|--------------|
| Frontend | http://localhost:3000 | - |
| API | http://localhost:8000 | - |
| OpenSearch | https://localhost:9200 | admin/Admin123! |
| MinIO Console | http://localhost:9001 | securevault/securevault123 |
| PostgreSQL | localhost:5432 | securevault/securevault |
| Redis | localhost:6379 | - |

---

### Option 2: Manual Setup (Without Docker)

#### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- OpenSearch 2.12+
- Go 1.21+ (for building agents)

#### Backend Setup

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://securevault:securevault@localhost:5432/securevault"
export REDIS_URL="redis://localhost:6379/0"
export OPENSEARCH_URL="http://localhost:9200"
export OPENSEARCH_PASSWORD="Admin123!"
export MINIO_ENDPOINT="localhost:9000"
export MINIO_ACCESS_KEY="securevault"
export MINIO_SECRET_KEY="securevault123"
export SECRET_KEY="your-secret-key-change-in-production"

# Initialize database
# First create PostgreSQL database
createdb securevault

# Run migrations (if using Alembic)
alembic upgrade head

# Start backend API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Set environment variable
export REACT_APP_API_URL=http://localhost:8000

# Start frontend
npm start
```

#### Go Agents (Optional)

```bash
# Build Endpoint Agent
cd backend/cmd/agent
go build -o endpoint-agent main.go
./endpoint-agent

# Build Network Sensor (in another terminal)
cd ../sensor
go build -o network-sensor main.go
./network-sensor
```

#### Starting Individual Services

```bash
# PostgreSQL
pg_ctl -D /usr/local/var/postgres start

# Redis
redis-server

# OpenSearch (after extracting)
./opensearch-2.12.0/bin/opensearch

# MinIO
minio server /data --console-address ":9001"
```

---

### Building and Running Go Agents

#### Build Go Agents

```bash
# Endpoint Agent
cd backend/cmd/agent
go mod init securevault-agent
go build -o endpoint-agent main.go
./endpoint-agent

# Network Sensor
cd ../sensor
go mod init securevault-sensor
go build -o network-sensor main.go
./network-sensor
```

#### Build Agent Docker Images

```bash
# Endpoint Agent
cd backend/cmd/agent
docker build -t securevault-agent:latest .

# Network Sensor
cd ../sensor
docker build -t securevault-sensor:latest .
```

---

### Troubleshooting

#### Common Issues

**Port Already in Use**
```bash
# Find process using port
netstat -ano | findstr :8000
# Kill process
taskkill /PID <PID> /F
```

**Database Connection Error**
```bash
# Check PostgreSQL status
pg_ctl status

# Verify connection
psql -h localhost -U securevault -d securevault
```

**OpenSearch Connection Failed**
```bash
# Check if OpenSearch is running
curl -k -u admin:Admin123! https://localhost:9200

# Check cluster health
curl -k -u admin:Admin123! https://localhost:9200/_cluster/health
```

**Frontend API Connection Failed**
```bash
# Verify backend is running
curl http://localhost:8000/health

# Check CORS settings in main.py
```

---

### Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| DATABASE_URL | PostgreSQL connection string | postgresql://user:pass@localhost:5432/db |
| REDIS_URL | Redis connection string | redis://localhost:6379/0 |
| OPENSEARCH_URL | OpenSearch URL | http://localhost:9200 |
| OPENSEARCH_USERNAME | OpenSearch admin username | admin |
| OPENSEARCH_PASSWORD | OpenSearch admin password | Admin123! |
| MINIO_ENDPOINT | MinIO server endpoint | localhost:9000 |
| MINIO_ACCESS_KEY | MinIO root user | securevault |
| MINIO_SECRET_KEY | MinIO root password | securevault123 |
| MINIO_BUCKET | MinIO bucket name | securevault-logs |
| SECRET_KEY | JWT signing key | your-secret-key |
| ALGORITHM | JWT algorithm | HS256 |
| ACCESS_TOKEN_EXPIRE_MINUTES | Token expiry | 30 |

---

## Summary

SecureVault provides a complete end-to-end security platform:

1. **Collection** → Go agents collect endpoint and network data
2. **Detection** → DLP patterns + SIEM correlation detect threats
3. **AI Intelligence** → 8 AI engines provide advanced analysis
4. **Response** → SOAR playbooks automate incident response
5. **Visualization** → React frontend displays real-time dashboards

The platform is production-ready and can be deployed using Docker Compose for quick setup or manually for custom configurations.

---

*Document Version: 1.0*
*Last Updated: April 2026*
