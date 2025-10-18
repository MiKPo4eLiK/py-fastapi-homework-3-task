from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.config.dependencies import get_jwt_auth_manager, get_db
from src.database.models import UserModel, UserGroupEnum, RefreshTokenModel
from src.security import verify_password
from src.security.interfaces import JWTAuthManagerInterface
from src.schemas.accounts import (
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    AccessTokenResponseSchema,
)

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


@router.post("/login/", response_model=AccessTokenResponseSchema)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    """Authenticate user and return access & refresh tokens"""
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not active."
        )

    user_id = cast(int, user.id)
    user_group = cast(UserGroupEnum, user.group.name)

    access_token = jwt_manager.create_access_token(user_id=user_id, group=user_group)
    refresh_token_str = jwt_manager.create_refresh_token(user_id=user_id, group=user_group)

    refresh_token = RefreshTokenModel(user_id=user_id, token=refresh_token_str)

    try:
        async with db.begin():
            db.add(refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to login."
        )


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using a valid refresh token"""
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = cast(int, payload.get("user_id"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired refresh token."
        )

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    refresh_token_record = result.scalar_one_or_none()

    if not refresh_token_record or user_id != refresh_token_record.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = await db.get(UserModel, refresh_token_record.user_id)
    if not user:
        async with db.begin():
            await db.delete(refresh_token_record)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not active."
        )

    try:
        new_access_token = jwt_manager.create_access_token(
            user_id=cast(int, user.id),
            group=cast(UserGroupEnum, user.group.name)
        )
        return {"access_token": new_access_token}

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh access token."
        )
