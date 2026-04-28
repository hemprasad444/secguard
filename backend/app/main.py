from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base, async_session
from app.api.auth import router as auth_router
from app.api.projects import router as projects_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router
from app.api.dashboard import router as dashboard_router
from app.api.users import router as users_router
from app.api.settings import router as settings_router
from app.api.onboarding import router as onboarding_router
from app.api.organizations import router as organizations_router

# Import all models so they're registered with Base
import app.models  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from app.seed_control_fixes import seed_control_fixes
    async with async_session() as session:
        await seed_control_fixes(session)
    yield
    await engine.dispose()


app = FastAPI(
    title="OpenSentinel",
    description="Security Dashboard - Unified security monitoring and scanning platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(users_router)
app.include_router(settings_router)
app.include_router(onboarding_router)
app.include_router(organizations_router)


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "opensentinel"}
