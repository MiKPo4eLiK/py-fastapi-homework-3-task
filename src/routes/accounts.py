from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config.dependencies import get_jwt_auth_manager, get_settings, get_db
from config.settings import BaseAppSettings
from database.models import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions.security import BaseSecurityError
from security import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenResponseSchema,
    MessageResponseSchema,
)

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


@router.post(
    "/login/",
    response_model=TokenResponseSchema
)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    user_id = cast(int, user.id)
    user_group = cast(UserGroupEnum, user.group.name)

    access_token = jwt_manager.create_access_token(user_id=user_id, group=user_group)
    refresh_token_str = jwt_manager.create_refresh_token(user_id=user_id, group=user_group)

    refresh_token = RefreshTokenModel.create(user_id=user_id, token=refresh_token_str)
    db.add(refresh_token)

    try:
        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
        }
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = cast(int, payload.get("user_id"))
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    refresh_token_record = result.scalar_one_or_none()

    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if user_id != refresh_token_record.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        # 404 Not Found
        await db.delete(refresh_token_record)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not active.")

    try:
        new_access_token = jwt_manager.create_access_token(
            user_id=cast(int, user.id),
            group=cast(UserGroupEnum, user.group.name)
        )

        return {
            "access_token": new_access_token,
            "refresh_token": data.refresh_token,
            "token_type": "bearer",
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
