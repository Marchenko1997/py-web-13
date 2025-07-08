import os
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from passlib.context import CryptContext

from src.database.db import get_db
from src.repository import users as repository_users
from fastapi.security.utils import get_authorization_scheme_param


async def custom_oauth2_scheme(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    scheme, token = get_authorization_scheme_param(auth_header)

    if not auth_header or scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid or missing token")

    return token


class Auth:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM")
    EMAIL_SECRET_KEY = os.getenv("EMAIL_SECRET_KEY") or SECRET_KEY

    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    async def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire, "scope": "access_token"})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def create_refresh_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update({"exp": expire, "scope": "refresh_token"})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def decode_refresh_token(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("scope") != "refresh_token":
                raise HTTPException(status_code=401, detail="Invalid token scope")
            return payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    async def get_current_user(
        self,
        token: str = Depends(custom_oauth2_scheme),
        db: Session = Depends(get_db),
    ):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("scope") != "access_token":
                raise HTTPException(status_code=401, detail="Invalid token scope")
            email = payload.get("sub")
            if email is None:
                raise HTTPException(status_code=401, detail="Email missing in token")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = await repository_users.get_user_by_email(email, db)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    
    async def create_email_token(self, data: dict) -> str:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
        to_encode = data.copy() | {"exp": expire}
        return jwt.encode(to_encode, self.EMAIL_SECRET_KEY, algorithm=self.ALGORITHM)

    
    async def get_email_from_token(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.EMAIL_SECRET_KEY, algorithms=[self.ALGORITHM])
            return payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=400, detail="Verification error")



auth_service = Auth()
