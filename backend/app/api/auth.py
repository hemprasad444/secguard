from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.user import UserCreate, UserLogin, TokenResponse, UserResponse
from app.services.auth_service import register_user, login_user, refresh_access_token
from app.middleware.auth import get_current_user, require_role
from app.database import get_db
from app.models.user import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return access + refresh tokens."""
    token = await login_user(db, body)
    return token


@router.post("/register", response_model=UserResponse)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Register a new user. Requires admin role."""
    user = await register_user(db, body)
    return user


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: dict, db: AsyncSession = Depends(get_db)):
    """Refresh an access token using a valid refresh token."""
    refresh_token: str = body.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="refresh_token is required",
        )
    token = await refresh_access_token(db, refresh_token)
    return token


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user with org info."""
    user_data = {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.name,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at.isoformat(),
        "org_id": str(current_user.org_id) if current_user.org_id else None,
        "org_name": current_user.organization.name if current_user.organization else None,
    }
    return user_data
