from pydantic import BaseModel, EmailStr, field_validator
from src.security.passwords import validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password", mode="before")
    @classmethod
    def validate_password_field(cls, v: str) -> str:
        validate_password_strength(v)
        return v


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetSchema(BaseModel):
    email: EmailStr
    token: str
    new_password: str

    @field_validator("new_password", mode="before")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        validate_password_strength(v)
        return v
