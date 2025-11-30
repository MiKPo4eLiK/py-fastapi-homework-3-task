from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    bcrypt__rounds=14,
    deprecated="auto",
)

MAX_BCRYPT_BYTES = 72


def _truncate_password(password: str) -> str:
    # bcrypt працює з байтами → потрібно обрізати по байтах, а не по символах
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > MAX_BCRYPT_BYTES:
        password_bytes = password_bytes[:MAX_BCRYPT_BYTES]

    return password_bytes.decode("utf-8", errors="ignore")


def hash_password(password: str) -> str:
    password = _truncate_password(password)
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_password = _truncate_password(plain_password)
    return pwd_context.verify(plain_password, hashed_password)
