from datetime import (
    datetime,
    timezone,
    timedelta,
)
from unittest.mock import patch
import pytest
from sqlalchemy import (
    select,
    delete,
    func,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from src.database.models import (
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    UserGroupModel,
    UserGroupEnum,
    RefreshTokenModel
)
from src.tests.test_integration.test_constants import TEST_PASSWORD

TEST_EMAIL = "testuser@example.com"
TEST_FULL_NAME = "Test User"


@pytest.fixture
async def seed_user_groups(db_session) -> None:
    for group in UserGroupEnum:
        db_session.add(UserGroupModel(name=group))
    await db_session.commit()


@pytest.mark.asyncio
async def test_register_user_success(client, db_session, seed_user_groups) -> None:
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    response = await client.post("/api/v1/accounts/register/", json=payload)

    assert response.status_code == 201

    data = response.json()
    assert data["email"] == payload["email"]
    assert "id" in data

    # Check user in DB
    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    created_user = result.scalars().first()
    assert created_user is not None

    # Check activation token
    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == created_user.id)
    result = await db_session.execute(stmt_token)
    token = result.scalars().first()
    assert token is not None
    assert token.token is not None
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    assert expires_at > datetime.now(timezone.utc)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_password, expected_error",
    [
        ("short", "Password must contain at least 8 characters."),
        ("NoDigitHere!", "Password must contain at least one digit."),
        ("nodigitnorupper@", "Password must contain at least one uppercase letter."),
        ("NOLOWERCASE1@", "Password must contain at least one lowercase letter."),
        ("NoSpecial123", "Password must contain at least one special character: @$!%*?#&."),
    ],
)
async def test_register_user_password_validation(client, seed_user_groups, invalid_password, expected_error) -> None:
    payload = {"email": TEST_EMAIL, "password": invalid_password, "full_name": TEST_FULL_NAME}
    response = await client.post("/api/v1/accounts/register/", json=payload)
    assert response.status_code == 422
    assert expected_error in str(response.json()["detail"])


@pytest.mark.asyncio
async def test_register_user_conflict(client, db_session, seed_user_groups) -> None:
    payload = {"email": "conflictuser@example.com", "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    response_first = await client.post("/api/v1/accounts/register/", json=payload)
    assert response_first.status_code == 201

    response_second = await client.post("/api/v1/accounts/register/", json=payload)
    assert response_second.status_code == 409
    assert response_second.json()["detail"] == "User already exists."


@pytest.mark.asyncio
async def test_register_user_internal_server_error(client, seed_user_groups) -> None:
    payload = {"email": "erroruser@example.com", "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    with patch("src.routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await client.post("/api/v1/accounts/register/", json=payload)
    assert response.status_code == 500
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_activate_account_success(client, db_session, seed_user_groups) -> None:
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    reg_resp = await client.post("/api/v1/accounts/register/", json=payload)
    assert reg_resp.status_code == 201

    stmt = select(UserModel).options(joinedload(UserModel.activation_token)).where(UserModel.email == TEST_EMAIL)
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    activation_token = user.activation_token.token

    response = await client.get(f"/api/v1/accounts/activate/{activation_token}/")
    assert response.status_code == 200
    assert response.json()["message"] == "User activated successfully."

    await db_session.refresh(user)
    assert user.is_active


@pytest.mark.asyncio
async def test_activate_user_with_expired_token(client, db_session, seed_user_groups) -> None:
    """
    Test activation with an expired token.
    ...
    """
    registration_payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "full_name": TEST_FULL_NAME,
    }
    registration_response = await client.post("/api/v1/accounts/register/", json=registration_payload)
    assert registration_response.status_code == 201, "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."
    assert not user.is_active, "User should not be active before activation."

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    activation_token.expires_at = datetime.now(timezone.utc) - timedelta(days=2)
    await db_session.commit()

    activation_response = await client.get(f"/api/v1/accounts/activate/{activation_token.token}/")

    assert activation_response.status_code == 400, "Expected status code 400 for expired token."
    assert activation_response.json()["detail"] == "Invalid or expired activation token.", (
        "Expected error message for expired token."
    )


@pytest.mark.asyncio
async def test_activate_user_with_deleted_token(client, db_session, seed_user_groups) -> None:
    """
    Test activation with a deleted token.
    ...
    """
    registration_payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "full_name": TEST_FULL_NAME,
    }
    registration_response = await client.post("/api/v1/accounts/register/", json=registration_payload)
    assert registration_response.status_code == 201, "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."
    assert not user.is_active, "User should not be active before activation."

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    token_value = activation_token.token

    await db_session.execute(
        delete(ActivationTokenModel).where(ActivationTokenModel.id == activation_token.id)
    )
    await db_session.commit()

    activation_response = await client.get(f"/api/v1/accounts/activate/{token_value}/")
    assert activation_response.status_code == 400, "Expected status code 400 for deleted token."
    assert activation_response.json()["detail"] == "Invalid or expired activation token.", (
        "Expected error message for deleted token."
    )


@pytest.mark.asyncio
async def test_activate_already_active_user(client, db_session, seed_user_groups) -> None:
    """
    Test activation of an already active user.
    ...
    """
    registration_payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "full_name": TEST_FULL_NAME,
    }

    registration_response = await client.post("/api/v1/accounts/register/", json=registration_payload)
    assert registration_response.status_code == 201, "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    activation_response = await client.get(f"/api/v1/accounts/activate/{activation_token.token}/")

    assert activation_response.status_code == 200, "Expected status code 200 for already active user."
    assert activation_response.json()["message"] == "User activated successfully.", (
        "Expected success message even if already active."
    )


@pytest.mark.asyncio
async def test_request_password_reset_token_success(client, db_session, seed_user_groups) -> None:
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    await client.post("/api/v1/accounts/register/", json=payload)

    stmt = select(UserModel).where(UserModel.email == TEST_EMAIL)
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    user.is_active = True
    await db_session.commit()

    reset_payload = {"email": TEST_EMAIL}
    response = await client.post("/api/v1/accounts/password-reset/request/", json=reset_payload)
    assert response.status_code == 200
    assert response.json()["message"] == "Password reset email sent."


@pytest.mark.asyncio
async def test_request_password_reset_token_nonexistent_user(client, db_session) -> None:
    """
    Test password reset token request for a non-existent user.
    ...
    """
    reset_payload = {"email": "nonexistent@example.com"}

    reset_response = await client.post("/api/v1/accounts/password-reset/request/", json=reset_payload)
    assert reset_response.status_code == 404, "Expected status code 404 for non-existent user request."
    assert reset_response.json()["detail"] == "User with this email not found.", (
        "Expected error message for non-existent user request."
    )

    stmt = select(func.count(PasswordResetTokenModel.id))
    result = await db_session.execute(stmt)
    reset_token_count = result.scalar_one()
    assert reset_token_count == 0, "No password reset token should be created for non-existent user."


@pytest.mark.asyncio
async def test_request_password_reset_token_for_inactive_user(client, db_session, seed_user_groups) -> None:
    """
    Test password reset token request for a registered but inactive user.
    ...
    """
    registration_payload = {
        "email": "inactiveuser@example.com",
        "password": TEST_PASSWORD,
        "full_name": TEST_FULL_NAME,
    }
    registration_response = await client.post("/api/v1/accounts/register/", json=registration_payload)
    assert registration_response.status_code == 201, "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    created_user = result.scalars().first()
    assert created_user is not None, "User should be created in the database."
    assert not created_user.is_active, "User should not be active after registration."

    reset_payload = {"email": registration_payload["email"]}
    reset_response = await client.post("/api/v1/accounts/password-reset/request/", json=reset_payload)

    assert reset_response.status_code == 200, "Expected status code 200 for password reset request."
    assert reset_response.json()["message"] == "Password reset email sent.", (
        "Expected success message from API."
    )

    stmt_tokens = select(func.count(PasswordResetTokenModel.id)).where(
        PasswordResetTokenModel.user_id == created_user.id)
    result_tokens = await db_session.execute(stmt_tokens)
    reset_token_count = result_tokens.scalar_one()

    assert reset_token_count == 1, "Password reset token should be created even for an inactive user."


@pytest.mark.asyncio
async def test_reset_password_success(client, db_session, seed_user_groups) -> None:
    """Full successful password reset script."""
    reg_payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": TEST_FULL_NAME}
    reg_resp = await client.post("/api/v1/accounts/register/", json=reg_payload)
    assert reg_resp.status_code == 201

    stmt = select(UserModel).where(UserModel.email == TEST_EMAIL)
    result = await db_session.execute(stmt)
    user = result.scalars().first()

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()

    act_resp = await client.get(f"/api/v1/accounts/activate/{activation_token.token}/")
    assert act_resp.status_code == 200

    await db_session.refresh(user)
    assert user.is_active

    reset_req_payload = {"email": TEST_EMAIL}
    reset_req_resp = await client.post("/api/v1/accounts/password-reset/request/", json=reset_req_payload)
    assert reset_req_resp.status_code == 200

    stmt_reset = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_reset = await db_session.execute(stmt_reset)
    reset_token = result_reset.scalars().first()
    assert reset_token is not None

    new_password = "NewSecurePassword123!"
    reset_payload = {"email": TEST_EMAIL, "token": reset_token.token, "new_password": new_password}
    reset_resp = await client.post("/api/v1/accounts/password-reset/complete/", json=reset_payload)
    assert reset_resp.status_code == 200
    assert reset_resp.json()["message"] == "Password has been reset successfully."

    await db_session.refresh(user)
    assert user.verify_password(new_password)


@pytest.mark.asyncio
async def test_reset_password_invalid_email(client) -> None:
    """Resetting password with non-existent email returns 404."""
    payload = {"email": "notfound@example.com", "token": "any", "new_password": TEST_PASSWORD}
    resp = await client.post("/api/v1/accounts/password-reset/complete/", json=payload)

    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found."


@pytest.mark.asyncio
async def test_reset_password_invalid_token(client, db_session, seed_user_groups) -> None:
    """Resetting a password with an invalid token returns 400."""
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()

    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)

    await db_session.commit()

    reset_token_valid = PasswordResetTokenModel(user_id=user.id)
    db_session.add(reset_token_valid)
    await db_session.commit()

    payload = {"email": TEST_EMAIL, "token": "wrongtoken", "new_password": TEST_PASSWORD}
    resp = await client.post("/api/v1/accounts/password-reset/complete/", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid or expired token."

    stmt_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_token = await db_session.execute(stmt_token)
    token_record = result_token.scalars().first()
    assert token_record is not None


@pytest.mark.asyncio
async def test_reset_password_expired_token(client, db_session, seed_user_groups) -> None:
    """Resetting a password with an expired token returns 400."""
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    token_record = PasswordResetTokenModel(
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    db_session.add(token_record)
    await db_session.commit()

    payload = {"email": TEST_EMAIL, "token": token_record.token, "new_password": TEST_PASSWORD}
    resp = await client.post("/api/v1/accounts/password-reset/complete/", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid or expired token."

    stmt_check = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_check = await db_session.execute(stmt_check)
    expired_token = result_check.scalars().first()
    assert expired_token is None


@pytest.mark.asyncio
async def test_reset_password_sqlalchemy_error(client, db_session, seed_user_groups) -> None:
    """Reset password when commit throws SQLAlchemyError → 500."""
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    token_record = PasswordResetTokenModel(user_id=user.id)
    db_session.add(token_record)
    await db_session.commit()

    payload = {"email": TEST_EMAIL, "token": token_record.token, "new_password": TEST_PASSWORD}
    with patch("src.routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        resp = await client.post("/api/v1/accounts/password-reset/complete/", json=payload)
    assert resp.status_code == 500
    assert resp.json()["detail"] == "An error occurred while processing the request."


@pytest.mark.asyncio
async def test_login_user_success(client, db_session, jwt_manager, seed_user_groups) -> None:
    # Create user
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    # Login
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    response = await client.post("/api/v1/accounts/login/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data and "refresh_token" in data


@pytest.mark.asyncio
async def test_login_user_invalid_cases(client, db_session, seed_user_groups) -> None:
    """Login with non-existent user and incorrect password."""
    payload = {"email": "nonexistent@example.com", "password": TEST_PASSWORD}
    response = await client.post("/api/v1/accounts/login/", json=payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    payload_wrong = {"email": TEST_EMAIL, "password": "WrongPassword123!"}
    response = await client.post("/api/v1/accounts/login/", json=payload_wrong)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


@pytest.mark.asyncio
async def test_login_user_inactive_account(client, db_session, seed_user_groups) -> None:
    """Inactive user login."""
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email="inactive@example.com", raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = False
    db_session.add(user)
    await db_session.commit()

    payload = {"email": "inactive@example.com", "password": TEST_PASSWORD}
    response = await client.post("/api/v1/accounts/login/", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"] == "User account not activated."


@pytest.mark.asyncio
async def test_login_user_commit_error(client, db_session, seed_user_groups) -> None:
    """Login with database commit error."""
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    with patch("src.routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await client.post("/api/v1/accounts/login/", json=payload)
    assert response.status_code == 500
    assert response.json()["detail"] == "An error occurred while processing the request."


@pytest.mark.asyncio
async def test_refresh_access_token_success(client, db_session, jwt_manager, seed_user_groups) -> None:
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    group = result.scalars().first()
    user = UserModel.create(email=TEST_EMAIL, raw_password=TEST_PASSWORD, group_id=group.id)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    # Login to get refresh token
    login_payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    login_response = await client.post("/api/v1/accounts/login/", json=login_payload)
    refresh_token = login_response.json()["refresh_token"]

    payload = {"refresh_token": refresh_token}
    response = await client.post("/api/v1/accounts/refresh/", json=payload)
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_refresh_access_token_expired_token(client, jwt_manager) -> None:
    """Refresh token with expired token returns 401."""
    expired_token = jwt_manager.create_refresh_token({"sub": TEST_EMAIL}, expires_delta=timedelta(days=-1))
    payload = {"refresh_token": expired_token}
    response = await client.post("/api/v1/accounts/refresh/", json=payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."


@pytest.mark.asyncio
async def test_refresh_access_token_token_not_found(client, jwt_manager) -> None:
    """Refresh token not saved in the database → 401."""
    fake_token = jwt_manager.create_refresh_token({"sub": TEST_EMAIL})
    payload = {"refresh_token": fake_token}
    response = await client.post("/api/v1/accounts/refresh/", json=payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."


@pytest.mark.asyncio
async def test_refresh_access_token_user_not_found(client, db_session, jwt_manager, seed_user_groups) -> None:
    """Refresh token for non-existent user → 401."""
    fake_user_email = "nonexistent@example.com"
    token = jwt_manager.create_refresh_token({"sub": fake_user_email})

    record = RefreshTokenModel.create(user_id=9999, token=token, days_valid=7)
    db_session.add(record)
    await db_session.commit()

    payload = {"refresh_token": token}
    response = await client.post("/api/v1/accounts/refresh/", json=payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."
