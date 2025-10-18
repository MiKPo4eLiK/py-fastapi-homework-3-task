from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from src.database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    full_name: str

    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        if not accounts_validators.validate_password(v):
            raise ValueError("Password does not meet complexity requirements.")
        return v


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    activation_token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str

    @field_validator("new_password")
    def validate_new_password(cls, v: str) -> str:
        if not accounts_validators.validate_password(v):
            raise ValueError("Password does not meet complexity requirements.")
        return v


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    is_active: bool

    class Config:
        orm_mode = True


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AccessTokenResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
