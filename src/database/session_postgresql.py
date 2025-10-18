from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional, Callable

from sqlalchemy import create_engine, Engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker

postgresql_engine: Optional[AsyncEngine] = None
sync_postgresql_engine: Optional[Engine] = None
AsyncPostgresqlSessionLocal: Optional[Callable[..., AsyncSession]] = None


def initialize_postgresql() -> None:
    from src.config.dependencies import get_settings

    settings = get_settings()

    global postgresql_engine, sync_postgresql_engine, AsyncPostgresqlSessionLocal

    POSTGRESQL_DATABASE_URL = (
        f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_DB_PORT}/{settings.POSTGRES_DB}"
    )

    postgresql_engine = create_async_engine(POSTGRESQL_DATABASE_URL, echo=False)

    AsyncPostgresqlSessionLocal = sessionmaker(
        bind=postgresql_engine,
        class_=AsyncSession,
        autoflush=True,
        expire_on_commit=False
    )

    SYNC_DATABASE_URL = (
        f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_DB_PORT}/{settings.POSTGRES_DB}"
    )
    sync_postgresql_engine = create_engine(SYNC_DATABASE_URL, echo=False)


async def get_postgresql_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous PostgreSQL database session.
    """
    if AsyncPostgresqlSessionLocal is None:
        initialize_postgresql()

    async with AsyncPostgresqlSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_postgresql_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous PostgreSQL session using a context manager.
    """
    if AsyncPostgresqlSessionLocal is None:
        initialize_postgresql()

    async with AsyncPostgresqlSessionLocal() as session:
        yield session
