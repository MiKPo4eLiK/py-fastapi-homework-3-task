import re
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

from src.database import get_db
from src.database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    UserGroupEnum
)
from src.schemas.accounts.accounts import (
    UserRegistrationRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetSchema,
)
from src.security.passwords import hash_password, verify_password, truncate_password
from src.security.jwt_manager import JWTManager

router = APIRouter(tags=["Accounts"])
jwt_manager = JWTManager()


async def send_activation_email(email: str, token: str):
    print(f"Activation email to {email} with token {token}")


async def send_password_reset_email(email: str, token: str):
    print(f"Password reset email to {email} with token {token}")


def validate_password_strength(password: str):
    """
    Password complexity check. HTTPException 422 if invalid.
    """
    password = truncate_password(password)

    if len(password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password cannot be longer than 72 bytes."
        )
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must contain at least 8 characters.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one digit.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"[@$!%*?#&]", password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one special character: @$!%*?#&."
        )


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    existing_user = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    if existing_user.scalars().first():
        raise HTTPException(status_code=409, detail="User already exists.")

    password = truncate_password(payload.password)
    validate_password_strength(password)
    hashed = hash_password(password)

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(stmt_group)
    group = result.scalars().first()
    if not group:
        raise HTTPException(status_code=500, detail="Default user group not found.")

    user = UserModel(
        email=payload.email,
        _hashed_password=hashed,
        group_id=group.id,
        is_active=False
    )
    db.add(user)

    try:
        await db.flush()
        token = ActivationTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    await send_activation_email(payload.email, str(token.token))

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "User registered successfully. Activation email sent.",
            "id": user.id,
            "email": user.email
        }
    )


@router.post("/login/", status_code=status.HTTP_200_OK)
async def login_user(payload: UserLoginRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalars().first()

    if not user or not verify_password(truncate_password(payload.password), user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account not activated.")

    access_token = jwt_manager.create_access_token({"sub": user.email})
    refresh_token_value = jwt_manager.create_refresh_token({"sub": user.email})

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token_value
        }
    )


@router.get("/activate/{token}/", status_code=status.HTTP_200_OK)
async def activate_user(token: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == token))
    activation_token = result.scalars().first()
    if not activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token_expires_at = activation_token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    result_user = await db.execute(select(UserModel).where(UserModel.id == activation_token.user_id))
    user = result_user.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "User activated successfully."}
    )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(payload: TokenRefreshRequestSchema):
    try:
        data = jwt_manager.decode_refresh_token(payload.refresh_token)
        email = data.get("sub")
        new_access_token = jwt_manager.create_access_token({"sub": email})
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"access_token": new_access_token}
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(payload: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User with this email not found.")

    token = PasswordResetTokenModel(user_id=user.id)
    db.add(token)
    await db.commit()

    await send_password_reset_email(payload.email, str(token.token))

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Password reset email sent."}
    )


@router.post("/password-reset/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(payload: PasswordResetSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    result_token = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.token == payload.token)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    token = result_token.scalars().first()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    token_expires_at = token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    new_password = truncate_password(payload.new_password)
    validate_password_strength(new_password)

    user._hashed_password = hash_password(new_password)

    try:
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Password has been reset successfully."}
    )
