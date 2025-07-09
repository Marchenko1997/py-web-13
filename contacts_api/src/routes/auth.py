from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas.users import UserModel, UserResponse, TokenModel
from src.repository import users as repository_users
from src.services.auth import auth_service
from src.services.email import send_verification_email
from src.services.security import oauth2_scheme, http_bearer

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
    form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = await repository_users.get_user_by_email(form.username, db)
    if not user or not auth_service.verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=401, detail="Email not verified")

    access = await auth_service.create_access_token({"sub": user.email})
    refresh = await auth_service.create_refresh_token({"sub": user.email})
    await repository_users.update_token(user, refresh, db)
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
