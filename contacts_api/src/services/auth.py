import os, json
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.repository import users as repository_users
from src.services.security import http_bearer
from src.services.deps import get_redis  


REDIS_KEY = "user:{email}"  
REDIS_TTL = 60 * 15  


class Auth:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = os.getenv("SECRET_KEY", "secret")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    EMAIL_SECRET_KEY = os.getenv("EMAIL_SECRET_KEY", SECRET_KEY)

    # ---------------- хэши ---------------- #
    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return self.pwd_context.verify(plain, hashed)

    # ---------------- токены -------------- #
    async def _create(self, data: dict, minutes: int, scope: str) -> str:
        payload = data | {
            "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
            "scope": scope,
        }
        return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def create_access_token(self, data: dict) -> str:
        return await self._create(data, 15, "access_token")

    async def create_refresh_token(self, data: dict) -> str:
        return await self._create(data, 7 * 24 * 60, "refresh_token")

    async def decode_refresh_token(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("scope") != "refresh_token":
                raise HTTPException(status_code=401, detail="Invalid scope")
            return payload["sub"]
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    # --------------- current user + Redis --------------- #
    async def get_current_user(
        self,
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
        db: Session = Depends(get_db),
        redis=Depends(get_redis), 
    ):
        token = credentials.credentials
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("scope") != "access_token":
                raise HTTPException(status_code=401, detail="Wrong token scope")
            email = payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    
        cache_key = REDIS_KEY.format(email=email)  
        cached = await redis.get(cache_key)
        if cached:
            return json.loads(cached)  
       
        user = await repository_users.get_user_by_email(email, db)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        user_data = {
            "id": user.id,
            "email": user.email,
            "confirmed": user.confirmed,
            "avatar": user.avatar,
        }

       
        await redis.set(cache_key, json.dumps(user_data), ex=REDIS_TTL)

        return user_data

    # --------------- email-токен --------------- #
    async def create_email_token(self, data: dict) -> str:
        payload = data | {"exp": datetime.now(timezone.utc) + timedelta(hours=24)}
        return jwt.encode(payload, self.EMAIL_SECRET_KEY, algorithm=self.ALGORITHM)

    async def get_email_from_token(self, token: str) -> str:
        try:
            return jwt.decode(
                token, self.EMAIL_SECRET_KEY, algorithms=[self.ALGORITHM]
            )["sub"]
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error"
            )


auth_service = Auth()
