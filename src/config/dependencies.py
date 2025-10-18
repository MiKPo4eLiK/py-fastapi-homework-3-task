import os
from typing import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import TestingSettings, Settings, BaseAppSettings
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from database.session_sqlite import get_sqlite_db


def get_settings() -> BaseAppSettings:
    """
    Retrieve the application settings based on the current environment.
    ...
    """
    environment = os.getenv("ENVIRONMENT", "developing")
    if environment == "testing":
        return TestingSettings()
    return Settings()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session for FastAPI dependencies.
    Delegates to the configured database session function (SQLite for local/testing).
    """
    async for session in get_sqlite_db():
        yield session
# ---------------------------------------------


def get_jwt_auth_manager(settings: BaseAppSettings = Depends(get_settings)) -> JWTAuthManagerInterface:
    """
    Create and return a JWT authentication manager instance.
    ...
    """
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM
    )
