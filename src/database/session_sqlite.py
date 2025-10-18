from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker

from database import Base

sqlite_engine: AsyncEngine
AsyncSQLiteSessionLocal: sessionmaker


def initialize_sqlite():
    """
    Ініціалізує базу даних та створює об'єкти Engine і SessionLocal.
    Імпорт get_settings відбувається тут, щоб розірвати циклічний імпорт.
    """
    from config import get_settings

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
    async with AsyncSQLiteSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an asynchronous database session using a context manager.
    """
    async with AsyncSQLiteSessionLocal() as session:
        yield session


async def reset_sqlite_database() -> None:
    """
    Reset the SQLite database.
    """
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
