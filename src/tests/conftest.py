import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import insert, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import AsyncGenerator

from src.config import get_settings
from src.database.models.accounts import UserGroupModel, UserGroupEnum, UserModel, RefreshTokenModel
from src.database import reset_database, get_db_contextmanager, initialize_sqlite
from src.database.populate import CSVDatabaseSeeder
from src.main import app
from src.security.interfaces import JWTAuthManagerInterface
from src.security.token_manager import JWTAuthManager
from src.security.passwords import hash_password, truncate_password
from src.tests.test_integration.test_constants import TEST_PASSWORD


initialize_sqlite()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_db() -> None:
    """Reset database before each test."""
    await reset_database()


@pytest_asyncio.fixture(scope="function")
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Asynchronous HTTP client for FastAPI."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as async_client:
        yield async_client


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Asynchronous SQLAlchemy session."""
    async with get_db_contextmanager() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def jwt_manager() -> JWTAuthManagerInterface:
    """JWT manager for tests."""
    settings = get_settings()
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM
    )


@pytest_asyncio.fixture(scope="function")
async def seed_user_groups(db_session: AsyncSession) -> None:
    """Create basic user groups."""
    count_stmt = await db_session.execute(select(func.count(UserGroupModel.id)))
    count = count_stmt.scalar() or 0
    if count == 0:
        groups = [{"name": group.value} for group in UserGroupEnum]
        await db_session.execute(insert(UserGroupModel).values(groups))
        await db_session.commit()


@pytest_asyncio.fixture(scope="function")
async def seed_database(db_session: AsyncSession, seed_user_groups: None):
    """Populate database with movies from CSV for tests."""
    csv_path = os.path.join(os.path.dirname(__file__), "fixtures", "movies.csv")
    if not os.path.exists(csv_path):
        pytest.skip(f"CSV file not found at path {csv_path}, skipping seeding.")

    seeder = CSVDatabaseSeeder(csv_file_path=csv_path, db_session=db_session)
    await seeder.seed()
    yield


async def _create_user(db_session: AsyncSession, email: str, password: str, active: bool = True) -> UserModel:
    """Utility for creating user with truncated password."""
    user = UserModel(
        email=email,
        _hashed_password=hash_password(truncate_password(password)),
        is_active=active,
        group_id=1
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture(scope="function")
async def active_user(db_session: AsyncSession, seed_user_groups: None) -> UserModel:
    """Active user."""
    return await _create_user(db_session, "active@example.com", TEST_PASSWORD, active=True)


@pytest_asyncio.fixture(scope="function")
async def inactive_user(db_session: AsyncSession, seed_user_groups: None) -> UserModel:
    """Inactive user."""
    return await _create_user(db_session, "inactive@example.com", TEST_PASSWORD, active=False)


@pytest_asyncio.fixture(scope="function")
async def user_for_reset(db_session: AsyncSession, seed_user_groups: None) -> UserModel:
    """User for password reset tests."""
    return await _create_user(db_session, "reset@example.com", TEST_PASSWORD, active=True)


@pytest_asyncio.fixture(scope="function")
async def refresh_token_for_active_user(
    db_session: AsyncSession,
    active_user: UserModel,
    jwt_manager: JWTAuthManagerInterface,
) -> RefreshTokenModel:
    """Refresh token for active user."""
    user_group = await db_session.get(UserGroupModel, active_user.group_id)
    token_str = jwt_manager.create_refresh_token(
        user_id=active_user.id,
        group=user_group.name.value
    )
    token = RefreshTokenModel(user_id=active_user.id, token=token_str)
    db_session.add(token)
    await db_session.commit()
    return token
