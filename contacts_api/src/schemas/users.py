from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class UserModel(BaseModel):
    email: str
    password: str = Field(min_length=6, max_length=20)


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        orm_mode = True


class TokenModel(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RequestResetModel(BaseModel):
    email: EmailStr


class ResetPasswordModel(BaseModel):
    email: EmailStr
    token: str
    new_password: str
