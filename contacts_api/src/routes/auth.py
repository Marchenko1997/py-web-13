from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import (
    OAuth2PasswordRequestForm,
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas.users import UserModel, UserResponse, TokenModel
from src.repository import users as repository_users
from src.services.auth import auth_service
from jose import jwt, JWTError
from src.services.email import send_verification_email


router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()


@router.post("/signup", response_model=UserResponse, status_code=201)
async def signup(body: UserModel, db: Session = Depends(get_db)):
    if await repository_users.get_user_by_email(body.email, db):
        raise HTTPException(status_code=409, detail="Account already exists")

    body.password = auth_service.get_password_hash(body.password)
    user = await repository_users.create_user(body, db)

  
    email_token = await auth_service.create_email_token({"sub": user.email})
    await send_verification_email(user.email, email_token)

    return user


@router.post("/login", response_model=TokenModel)
async def login(
    body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    
    user = await repository_users.get_user_by_email(body.username, db)

 
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

   
    if not user.confirmed:
        raise HTTPException(status_code=401, detail="Email not verified")

   
    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=401, detail="Wrong password")

  
    access_token = await auth_service.create_access_token(data={"sub": user.email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email})

   
    await repository_users.update_token(user, refresh_token, db)

   
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.get("/refresh_token", response_model=TokenModel)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db),
):
    email = await auth_service.decode_refresh_token(credentials.credentials)
    user = await repository_users.get_user_by_email(email, db)
    if user.refresh_token != credentials.credentials:
        await repository_users.update_token(user, None, db)
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    access_token = await auth_service.create_access_token(data={"sub": email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})
    await repository_users.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/logout", status_code=204)
async def logout(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, auth_service.SECRET_KEY, algorithms=[auth_service.ALGORITHM]
        )
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await repository_users.get_user_by_email(email, db)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    await repository_users.update_token(user, None, db)


@router.get("/confirm_email/{token}")
async def confirm_email(token: str, db: Session = Depends(get_db)):
    try:
        email = await auth_service.get_email_from_token(token)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token"
        )

    user = await repository_users.get_user_by_email(email, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user.confirmed:
        return {"message": "Email already confirmed"}

    await repository_users.confirm_email(email, db)
    return {"message": "Email confirmed successfully"}
