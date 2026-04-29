import secrets
import string
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_role, hash_password
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdate, AdminCreateUser, AdminCreateUserResult

router = APIRouter(prefix="/api/users", tags=["users"])


def _generate_temp_password(length: int = 14) -> str:
    """Letters + digits, guaranteed mix. Avoids ambiguous chars (O/0/I/l)."""
    alphabet = string.ascii_letters + string.digits
    alphabet = alphabet.translate(str.maketrans("", "", "Il10oO"))
    return "".join(secrets.choice(alphabet) for _ in range(length))


@router.get("/", response_model=list[UserResponse])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """List all users with pagination. Requires admin role."""
    offset = (page - 1) * page_size
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).offset(offset).limit(page_size)
    )
    users = result.scalars().all()
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Get a single user by ID. Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a user (role, is_active, name). Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Deactivate a user (set is_active=False). Requires admin role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    await db.commit()


@router.post("/", response_model=AdminCreateUserResult, status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    body: AdminCreateUser,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a user with a temporary password. The user must change it on first login.

    The temporary password is returned ONCE in the response; we don't store it in plaintext.
    Show it to the admin so they can hand it off (chat / email / etc.) — secguard does not
    send the email itself.
    """
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    temp = (body.password or "").strip() or _generate_temp_password()
    user = User(
        email=body.email,
        name=body.name,
        password_hash=hash_password(temp),
        role=body.role or "viewer",
        org_id=current_user.org_id,
        must_change_password=True,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return AdminCreateUserResult(
        user=UserResponse.model_validate(user),
        temporary_password=temp,
    )


@router.post("/{user_id}/reset-password", response_model=AdminCreateUserResult)
async def admin_reset_password(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Generate a fresh temporary password and force the user to change it on next login."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    temp = _generate_temp_password()
    user.password_hash = hash_password(temp)
    user.must_change_password = True
    await db.commit()
    await db.refresh(user)
    return AdminCreateUserResult(
        user=UserResponse.model_validate(user),
        temporary_password=temp,
    )
