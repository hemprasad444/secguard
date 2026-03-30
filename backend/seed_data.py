"""Seed script to populate the database with sample data for development."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import uuid
from datetime import datetime, timezone, timedelta
import random

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base
from app.models.organization import Organization
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.middleware.auth import hash_password

engine = create_engine(settings.sync_database_url)
Base.metadata.create_all(engine)


def seed():
    with Session(engine) as session:
        # Create organization
        org = Organization(
            name="SecGuard Demo",
            slug="secguard-demo",
            description="Demo organization for SecGuard",
        )
        session.add(org)
        session.flush()

        # Create users (all in the demo org)
        admin = User(
            email="admin@secguard.io",
            name="Admin User",
            password_hash=hash_password("admin123"),
            role="admin",
            org_id=org.id,
        )
        engineer = User(
            email="engineer@secguard.io",
            name="Security Engineer",
            password_hash=hash_password("engineer123"),
            role="security_engineer",
            org_id=org.id,
        )
        developer = User(
            email="dev@secguard.io",
            name="Developer User",
            password_hash=hash_password("dev123"),
            role="developer",
            org_id=org.id,
        )
        viewer = User(
            email="viewer@secguard.io",
            name="Viewer User",
            password_hash=hash_password("viewer123"),
            role="viewer",
            org_id=org.id,
        )
        session.add_all([admin, engineer, developer, viewer])
        session.flush()

        # Create a second org to test tenant isolation
        org2 = Organization(
            name="Other Corp",
            slug="other-corp",
            description="Another organization for isolation testing",
        )
        session.add(org2)
        session.flush()
        other_admin = User(
            email="admin@othercorp.io",
            name="Other Admin",
            password_hash=hash_password("admin123"),
            role="admin",
            org_id=org2.id,
        )
        session.add(other_admin)
        session.flush()

        # Create projects (all in demo org)
        projects = [
            Project(name="Web Application", repo_url="https://github.com/org/webapp", description="Main web application", created_by=admin.id, org_id=org.id),
            Project(name="API Service", repo_url="https://github.com/org/api-service", description="Backend API microservice", created_by=engineer.id, org_id=org.id),
            Project(name="Mobile Backend", repo_url="https://github.com/org/mobile-backend", description="Mobile app backend", created_by=engineer.id, org_id=org.id),
        ]
        session.add_all(projects)
        session.flush()

        # Create a project in the other org to test isolation
        other_project = Project(
            name="Other Corp App", repo_url="https://github.com/othercorp/app",
            description="Should NOT be visible to demo org", created_by=other_admin.id, org_id=org2.id,
        )
        session.add(other_project)
        session.flush()

        tools = ["trivy", "gitleaks", "semgrep", "zap", "kubescape"]
        scan_types = {"trivy": "dependency", "gitleaks": "secrets", "semgrep": "sast", "zap": "dast", "kubescape": "k8s"}
        severities = ["critical", "high", "medium", "low", "info"]
        statuses = ["open", "in_progress", "resolved", "false_positive"]

        sample_findings = {
            "trivy": [
                ("CVE-2024-1234: lodash", "Prototype pollution in lodash < 4.17.21"),
                ("CVE-2024-5678: express", "Path traversal vulnerability in express < 4.19.2"),
                ("CVE-2024-9012: axios", "SSRF vulnerability in axios < 1.7.0"),
            ],
            "gitleaks": [
                ("AWS Access Key detected", "Hardcoded AWS access key found in config file"),
                ("GitHub Token exposed", "GitHub personal access token found in .env"),
                ("Database password in source", "PostgreSQL password hardcoded in connection string"),
            ],
            "semgrep": [
                ("SQL Injection risk", "User input directly concatenated in SQL query"),
                ("XSS vulnerability", "Unescaped user input rendered in HTML template"),
                ("Insecure deserialization", "pickle.loads() called on untrusted data"),
            ],
            "zap": [
                ("Cross-Site Scripting (Reflected)", "Reflected XSS found in search parameter"),
                ("Missing CSP Header", "Content-Security-Policy header not set"),
                ("Cookie without Secure flag", "Session cookie missing Secure attribute"),
            ],
            "kubescape": [
                ("Privileged container", "Container running with privileged security context"),
                ("Missing network policy", "No NetworkPolicy defined for namespace"),
                ("Default service account", "Pod using default service account with excessive permissions"),
            ],
        }

        now = datetime.now(timezone.utc)

        for project in projects:
            for tool in tools:
                for month_offset in range(6):
                    scan_date = now - timedelta(days=30 * month_offset + random.randint(0, 10))
                    scan = Scan(
                        project_id=project.id,
                        tool_name=tool,
                        scan_type=scan_types[tool],
                        status="completed",
                        triggered_by=engineer.id,
                        findings_count=random.randint(1, 5),
                        started_at=scan_date,
                        completed_at=scan_date + timedelta(minutes=random.randint(1, 10)),
                    )
                    session.add(scan)
                    session.flush()

                    findings_for_tool = sample_findings[tool]
                    for title, desc in random.sample(findings_for_tool, k=min(random.randint(1, 3), len(findings_for_tool))):
                        severity = random.choice(severities[:4])  # exclude info for variety
                        status = random.choices(statuses, weights=[4, 2, 3, 1])[0]
                        finding = Finding(
                            scan_id=scan.id,
                            project_id=project.id,
                            tool_name=tool,
                            severity=severity,
                            title=title,
                            description=desc,
                            file_path=f"src/{random.choice(['app', 'lib', 'utils', 'config'])}/{random.choice(['main', 'auth', 'db', 'api'])}.{random.choice(['py', 'js', 'ts'])}",
                            line_number=random.randint(1, 500),
                            status=status,
                            assigned_to=random.choice([developer.id, engineer.id, None]),
                            fingerprint=uuid.uuid4().hex[:64],
                            resolved_at=(scan_date + timedelta(days=random.randint(1, 14))) if status == "resolved" else None,
                        )
                        session.add(finding)

        session.commit()
        print("Seed data created successfully!")
        print(f"  Organizations: 2 (SecGuard Demo + Other Corp)")
        print(f"  Users: 5 (4 in demo org + 1 in other org)")
        print(f"  Projects: {len(projects)} in demo + 1 in other org")
        print(f"  Use admin@secguard.io / admin123 to login")
        print(f"  Or sign up a new organization at /signup")


if __name__ == "__main__":
    seed()
