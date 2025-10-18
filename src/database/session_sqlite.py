from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional, Callable

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker

from src.database.models.base import Base

sqlite_engine: Optional[AsyncEngine] = None
AsyncSQLiteSessionLocal: Optional[Callable[..., AsyncSession]] = None


def initialize_sqlite() -> None:
    from src.config.dependencies import get_settings

    settings = get_settings()

    global sqlite_engine, AsyncSQLiteSessionLocal

    SQLITE_DATABASE_URL = f"sqlite+aiosqlite:///{settings.PATH_TO_DB}"
    sqlite_engine = create_async_engine(SQLITE_DATABASE_URL, echo=False)
    AsyncSQLiteSessionLocal = sessionmaker(
        bind=sqlite_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )


async def get_sqlite_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session.
    """
    if AsyncSQLiteSessionLocal is None:
        raise RuntimeError("SQLite session factory not initialized; call initialize_sqlite() first.")

    async with AsyncSQLiteSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session using a context manager.
    """
    if AsyncSQLiteSessionLocal is None:
        raise RuntimeError("SQLite session factory not initialized; call initialize_sqlite() first.")

    async with AsyncSQLiteSessionLocal() as session:
        yield session


async def reset_sqlite_database() -> None:
    """
    Reset the SQLite database.
    """
    if sqlite_engine is None:
        raise RuntimeError("SQLite engine not initialized; call initialize_sqlite() first.")

    async with sqlite_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
