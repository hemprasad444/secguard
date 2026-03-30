# SecGuard - Unified Security Scanning Platform

SecGuard is an open-source, self-hosted security scanning platform that provides unified vulnerability management across your entire infrastructure - container images, Kubernetes clusters, source code, and web applications.

## Features

- **Dependency Scanning** - Scan container images for CVEs using Trivy
- **Secret Detection** - Find leaked secrets and credentials in images
- **SBOM Generation** - Software Bill of Materials with license compliance tracking
- **K8s Security** - Kubernetes misconfiguration and compliance scanning (Kubescape + Trivy)
- **SAST** - Static Application Security Testing via Semgrep
- **DAST** - Dynamic Application Security Testing via OWASP ZAP
- **Unified Dashboard** - Single pane of glass across all scan types with per-tool filtering
- **Finding Lifecycle** - Open/Close workflow with verification, justification, and audit trail
- **Image Comparison** - Compare old vs new image tags to verify vulnerability fixes
- **K8s Re-verification** - Live cluster re-scan to confirm remediation before closing findings
- **Excel Reports** - Export findings to XLSX for compliance reporting
- **Multi-project** - Organize scans by project with team-based access control
- **Remote K8s Scanning** - Upload kubeconfig via browser for remote cluster scanning

## Screenshots

<!-- Add your screenshots here -->
<!-- ![Dashboard](docs/screenshots/dashboard.png) -->
<!-- ![K8s Scan Results](docs/screenshots/k8s-results.png) -->
<!-- ![Image Comparison](docs/screenshots/image-compare.png) -->

## Architecture

```
                    +------------------+
                    |    Frontend      |
                    |  React + Vite    |
                    |  (Nginx :8080)   |
                    +--------+---------+
                             |
                    +--------+---------+
                    |    Backend       |
                    |  FastAPI :8000   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+----+  +-----+------+  +----+-------+
     |  PostgreSQL  |  |   Redis    |  |   Celery   |
     |   :5432      |  |   :6379   |  |   Worker   |
     +-------------+  +-----------+  +-----+------+
                                           |
                              +------------+------------+
                              |            |            |
                        +-----+----+ +----+-----+ +----+-----+
                        |  Trivy   | |Kubescape | | Semgrep  |
                        +----------+ +----------+ +----------+
```

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- 4GB+ RAM recommended

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/hemprasad444/secguard.git
cd secguard
```

2. **Create environment file**

```bash
cp .env.example .env
```

Edit `.env` and change:
- `SECRET_KEY` - Set a strong random key for JWT tokens
- `POSTGRES_PASSWORD` - Set a secure database password
- Update `DATABASE_URL` to match the password

3. **Start all services**

```bash
docker-compose up -d
```

This will build and start all 7 containers. First run takes 5-10 minutes to build.

4. **Access the application**

- **Frontend**: http://localhost:8080
- **Backend API**: http://localhost:8000/docs (Swagger UI)

5. **Create your account**

Open http://localhost:8080 and click "Sign Up" to create your first admin account.

### Verify Installation

Check all services are running:

```bash
docker-compose ps
```

You should see 7 containers running:
- `secguard-frontend-1` (port 8080)
- `secguard-backend-1` (port 8000)
- `secguard-postgres-1` (port 5432)
- `secguard-redis-1` (port 6379)
- `secguard-celery-worker-1`
- `secguard-celery-beat-1`
- `secguard-trivy-1` (port 4954)

## Usage Guide

### 1. Create a Project

Navigate to **Projects** and create a new project to organize your scans.

### 2. Run Your First Scan

Go to **Scans** page and choose a scan type:

#### Dependency Scan (Container Image)
- Select your project
- Choose "Dependency Scan"
- Enter the container image (e.g., `nginx:1.24`)
- Add registry credentials if private
- Click "Start Scan"

#### K8s Security Scan
- Select your project
- Choose "K8s Security"
- Upload your kubeconfig file (via the Scans page)
- Select tools: Both (recommended), Kubescape, or Trivy
- Click "Start Scan"

#### Secret Detection
- Select your project
- Choose "Secret Detection"
- Enter the container image to scan
- Click "Start Scan"

### 3. Review Results

- **Dashboard** - Overview of all findings with severity breakdown
- **Project Detail** - Click any scan to see full findings
- **K8s Results** - Dedicated page with resource-grouped findings, affected config, remediation

### 4. Close Findings

Each finding can be closed with:
- **Verify & Close** (K8s) - Re-scans the cluster to confirm the fix
- **Verify Fixed Image** (Dependency) - Scan updated image tag and auto-compare
- **Accept Risk** - Document justification for accepted risks
- **False Positive** - Mark incorrectly flagged findings

### 5. Image Comparison

For dependency scans:
1. Open a scan result page
2. Click "Verify Fixed Image"
3. Enter the new image tag
4. System scans and compares CVEs
5. Fixed CVEs auto-close, still-open ones remain

## Configuration

### Environment Variables

See [.env.example](.env.example) for all available configuration options.

### K8s Remote Scanning

SecGuard scans Kubernetes clusters remotely via kubeconfig:
1. Download your kubeconfig from the cluster
2. Upload it through the browser on the Scans page
3. Scans run from the SecGuard backend - no agent needed on the cluster

### Custom Port

To change the default port (8080), edit `docker-compose.yml`:

```yaml
frontend:
  ports:
    - "YOUR_PORT:80"
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Frontend | React 18, TypeScript, Tailwind CSS, Recharts, Vite |
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), Pydantic |
| Database | PostgreSQL 16 |
| Queue | Redis + Celery |
| Scanners | Trivy, Kubescape, Semgrep, OWASP ZAP, Gitleaks |
| Container | Docker, Docker Compose |

## Updating

```bash
git pull
docker-compose build
docker-compose up -d
```

Database migrations run automatically on startup.

## Stopping

```bash
# Stop all services (keeps data)
docker-compose stop

# Stop and remove containers (keeps data volumes)
docker-compose down

# Stop and remove everything including data
docker-compose down -v
```

## Troubleshooting

### Scan stuck in "pending"
```bash
docker-compose restart celery-worker
```

### Frontend not loading after update
```bash
docker-compose build frontend
docker-compose up -d frontend
```

### Redis read-only error
```bash
docker-compose exec redis redis-cli REPLICAOF NO ONE
```

### Check logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs backend --tail 50
docker-compose logs celery-worker --tail 50
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

MIT License - See [LICENSE](LICENSE) for details.
