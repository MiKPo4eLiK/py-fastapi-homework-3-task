from datetime import datetime, timedelta, timezone
import jwt
from src.security.interfaces import JWTAuthManagerInterface
from fastapi import HTTPException
from typing import Optional


class JWTManager(JWTAuthManagerInterface):
    SECRET_KEY = "your_secret_key_here"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    REFRESH_TOKEN_EXPIRE_DAYS = 7

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def decode_access_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Access token has expired.")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid access token.")

    def decode_refresh_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=400, detail="Token has expired.")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid refresh token.")

    def verify_refresh_token_or_raise(self, token: str) -> None:
        self.decode_refresh_token(token)

    def verify_access_token_or_raise(self, token: str) -> None:
        self.decode_access_token(token)
