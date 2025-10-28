import secrets
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Returns:
        str: Securely generated token.
    """
    return secrets.token_urlsafe(length)
