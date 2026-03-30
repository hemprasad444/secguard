from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.middleware.auth import hash_password, create_access_token, create_refresh_token
from app.schemas.organization import SignUpRequest, OrgResponse
from app.schemas.user import TokenResponse

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])

@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(body: SignUpRequest, db: AsyncSession = Depends(get_db)):
    """Sign up a new organization with admin user."""
    # Check slug uniqueness
    existing = await db.execute(select(Organization).where(Organization.slug == body.org_slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization slug already taken")
    
    # Check email uniqueness
    existing_user = await db.execute(select(User).where(User.email == body.admin_email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create org
    org = Organization(name=body.org_name, slug=body.org_slug)
    db.add(org)
    await db.flush()
    
    # Create admin user
    user = User(
        email=body.admin_email,
        name=body.admin_name,
        password_hash=hash_password(body.admin_password),
        role="admin",
        org_id=org.id,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id))
    
    return {
        "organization": {"id": str(org.id), "name": org.name, "slug": org.slug},
        "user": {"id": str(user.id), "name": user.name, "email": user.email, "role": user.role},
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
