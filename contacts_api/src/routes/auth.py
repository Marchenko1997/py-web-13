import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status, Security
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas.users import RequestResetModel, ResetPasswordModel, UserModel, UserResponse, TokenModel
from src.repository import users as repository_users
from src.services.auth import auth_service
from src.services.email import send_reset_email, send_verification_email
from src.services.security import oauth2_scheme, http_bearer

import json
from src.services.deps import get_redis
from src.services.auth import REDIS_KEY, REDIS_TTL

router = APIRouter(prefix="/auth", tags=["auth"])


# ───────── signup ───────── #
@router.post("/signup", response_model=UserResponse, status_code=201)
async def signup(body: UserModel, db: Session = Depends(get_db)):
    if await repository_users.get_user_by_email(body.email, db):
        raise HTTPException(status_code=409, detail="Account already exists")

    body.password = auth_service.get_password_hash(body.password)
    user = await repository_users.create_user(body, db)

    token = await auth_service.create_email_token({"sub": user.email})
    await send_verification_email(user.email, token)
    return user


# ───────── login ───────── #


@router.post("/login", response_model=TokenModel)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    redis=Depends(get_redis),  
):
    user = await repository_users.get_user_by_email(form.username, db)
    if not user or not auth_service.verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=401, detail="Email not verified")

    access = await auth_service.create_access_token({"sub": user.email})
    refresh = await auth_service.create_refresh_token({"sub": user.email})
    await repository_users.update_token(user, refresh, db)

  
    await redis.set(
        REDIS_KEY.format(email=user.email),
        json.dumps(
            {
                "id": user.id,
                "email": user.email,
                "confirmed": user.confirmed,
                "avatar": user.avatar,
            }
        ),
        ex=REDIS_TTL,
    )

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


# ─────── refresh ─────── #
@router.get("/refresh_token", response_model=TokenModel)
async def refresh_token(
    cred: HTTPAuthorizationCredentials = Security(http_bearer),
    db: Session = Depends(get_db),
):
    token = cred.credentials
    email = await auth_service.decode_refresh_token(token)

    user = await repository_users.get_user_by_email(email, db)
    if user.refresh_token != token:
        await repository_users.update_token(user, None, db)
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    access = await auth_service.create_access_token({"sub": email})
    refresh = await auth_service.create_refresh_token({"sub": email})
    await repository_users.update_token(user, refresh, db)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


# ───────── logout ───────── #
@router.post("/logout", status_code=204)
async def logout(
    cred: HTTPAuthorizationCredentials = Security(http_bearer),
    db: Session = Depends(get_db),
    redis=Depends(get_redis),  # ✅ получаем Redis
):
    token = cred.credentials
    try:
        email = jwt.decode(
            token, auth_service.SECRET_KEY, algorithms=[auth_service.ALGORITHM]
        ).get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await repository_users.get_user_by_email(email, db)
    if user:
        await repository_users.update_token(user, None, db)
        await redis.delete(REDIS_KEY.format(email=email)) 


# ───── confirm email ───── #
@router.get("/confirm_email/{token}")
async def confirm_email(token: str, db: Session = Depends(get_db)):
    email = await auth_service.get_email_from_token(token)
    user = await repository_users.get_user_by_email(email, db)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.confirmed:
        return {"message": "Email already confirmed"}

    await repository_users.confirm_email(email, db)
    return {"message": "Email confirmed successfully"}


@router.post("/request-reset-password")
async def request_reset_password(
    body: RequestResetModel, request: Request, db: Session = Depends(get_db)
):
    user = await repository_users.get_user_by_email(body.email, db)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    token = secrets.token_urlsafe(32)
    redis_key = f"reset:{body.email}"
    await request.app.state.redis.set(redis_key, token, ex=3600)  # 1 час

    reset_link = (
        f"http://localhost:3000/reset-password?token={token}&email={body.email}"
    )
    await send_reset_email(body.email, reset_link)

    return {"message": "Ссылка для сброса пароля отправлена на email"}


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordModel, request: Request, db: Session = Depends(get_db)
):
    redis_key = f"reset:{body.email}"
    token_from_redis = await request.app.state.redis.get(redis_key)

    if not token_from_redis or token_from_redis != body.token:
        raise HTTPException(status_code=400, detail="Неверный или истёкший токен")

    hashed_password = auth_service.get_password_hash(body.new_password)
    await repository_users.update_password(body.email, hashed_password, db)
    await request.app.state.redis.delete(redis_key)

    return {"message": "Пароль успешно обновлён"}
