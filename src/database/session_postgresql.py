from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import create_engine, Engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker


postgresql_engine: AsyncEngine | None = None
sync_postgresql_engine: Engine | None = None
AsyncPostgresqlSessionLocal: sessionmaker | None = None


def initialize_postgresql():
    from config import get_settings

    settings = get_settings()

    global postgresql_engine, sync_postgresql_engine, AsyncPostgresqlSessionLocal

    POSTGRESQL_DATABASE_URL = (f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@"
                               f"{settings.POSTGRES_HOST}:{settings.POSTGRES_DB_PORT}/{settings.POSTGRES_DB}")

    postgresql_engine = create_async_engine(POSTGRESQL_DATABASE_URL, echo=False)

    AsyncPostgresqlSessionLocal = sessionmaker(
        bind=postgresql_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    sync_database_url = POSTGRESQL_DATABASE_URL.replace("postgresql+asyncpg", "postgresql")
    sync_postgresql_engine = create_engine(sync_database_url, echo=False)


async def get_postgresql_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session.
    """
    if AsyncPostgresqlSessionLocal is None:
        initialize_postgresql()

    async with AsyncPostgresqlSessionLocal() as session:  # type: ignore
        yield session


@asynccontextmanager
async def get_postgresql_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session using a context manager.
    """
    if AsyncPostgresqlSessionLocal is None:
        initialize_postgresql()

    async with AsyncPostgresqlSessionLocal() as session:  # type: ignore
        yield session
