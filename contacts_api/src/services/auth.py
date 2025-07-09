"""
services/auth.py

Ниже — полностью переписанная версия файла с «правильной»
OAuth2-схемой.  Всё, что связано с кастомным разбором заголовка,
удалено; теперь Swagger сам отдаёт токен и добавляет кнопку Authorize.
"""

import os
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer  # ✅
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.repository import users as repository_users

# ---------------------------------------------------------------------------
# 1) Объявляем схему авторизации. tokenUrl должен совпадать с эндпоинтом логина
#    (тот, который отдаёт access_token).
# ---------------------------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Auth:
    """
    Сервис-обёртка вокруг шифрования паролей и работы с JWT.
    """

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM")
    EMAIL_SECRET_KEY = os.getenv("EMAIL_SECRET_KEY") or SECRET_KEY

    # ---------------------------------------------------------------------
    # ХЭШИРОВАНИЕ ПАРОЛЕЙ
    # ---------------------------------------------------------------------
    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    # ---------------------------------------------------------------------
    # ГЕНЕРАЦИЯ JWT-ТОКЕНОВ
    # ---------------------------------------------------------------------
    async def create_access_token(self, data: dict) -> str:
        """
        Создаёт access-токен на 15 минут.
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire, "scope": "access_token"})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def create_refresh_token(self, data: dict) -> str:
        """
        Создаёт refresh-токен на 7 дней.
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update({"exp": expire, "scope": "refresh_token"})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    # ---------------------------------------------------------------------
    # ОБРАТНОЕ ДЕКОДИРОВАНИЕ refresh-ТОКЕНА
    # ---------------------------------------------------------------------
    async def decode_refresh_token(self, token: str) -> str:
        """
        Возвращает email внутри refresh-токена.
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("scope") != "refresh_token":
                raise HTTPException(status_code=401, detail="Invalid token scope")
            return payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    # ---------------------------------------------------------------------
    # ЗАЩИЩЁННЫЙ dependency для эндпоинтов
    # ---------------------------------------------------------------------
    async def get_current_user(
        self,
        token: str = Depends(oauth2_scheme),  # ⬅️ берём токен из заголовка
        db: Session = Depends(get_db),
    ):
        """
        Проверяет access-токен и отдаёт объект пользователя.
        """
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

    # ---------------------------------------------------------------------
    # ТОКЕН ДЛЯ ПОДТВЕРЖДЕНИЯ EMAIL
    # ---------------------------------------------------------------------
    async def create_email_token(self, data: dict) -> str:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
        to_encode = data.copy() | {"exp": expire}
        return jwt.encode(to_encode, self.EMAIL_SECRET_KEY, algorithm=self.ALGORITHM)

    async def get_email_from_token(self, token: str) -> str:
        try:
            payload = jwt.decode(
                token, self.EMAIL_SECRET_KEY, algorithms=[self.ALGORITHM]
            )
            return payload.get("sub")
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error"
            )


# Экземпляр, который будем импортировать в роуты
auth_service = Auth()
