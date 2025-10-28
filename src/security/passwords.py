import re
from fastapi import HTTPException
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    bcrypt__rounds=14,
    deprecated="auto",
    bcrypt__ident="2y",
)

SPECIAL_CHARS = "@$!%*?#&"
SPECIAL_CHAR_REGEX = r"[" + re.escape(SPECIAL_CHARS) + r"]"

MAX_PASSWORD_BYTES = 72


def truncate_password(password: str) -> str:
    """Truncate password to 72 bytes to avoid bcrypt limit issues."""
    if not isinstance(password, str):
        raise HTTPException(status_code=422, detail="Password must be a string.")
    return password.encode("utf-8")[:MAX_PASSWORD_BYTES].decode("utf-8", errors="ignore")


def hash_password(password: str) -> str:
    """Hash a plain-text password after truncating to 72 bytes."""
    safe_password = truncate_password(password)
    return pwd_context.hash(safe_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hashed version."""
    safe_password = truncate_password(plain_password)
    return pwd_context.verify(safe_password, hashed_password)


def validate_password_strength(password: str) -> None:
    """
    Validate password complexity and length (max 72 bytes).
    Raises HTTPException(status_code=422) if invalid.
    """
    safe_password = truncate_password(password)

    errors = []

    if len(safe_password) < 8:
        errors.append("Password must contain at least 8 characters.")

    if not re.search(r"\d", safe_password):
        errors.append("Password must contain at least one digit.")

    if not re.search(r"[A-Z]", safe_password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", safe_password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(SPECIAL_CHAR_REGEX, safe_password):
        errors.append(f"Password must contain at least one special character: {SPECIAL_CHARS}.")

    if errors:
        detail = "Password validation failed: " + " ".join(errors)
        raise HTTPException(status_code=422, detail=detail)
