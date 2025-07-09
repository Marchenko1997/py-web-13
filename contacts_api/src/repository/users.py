from sqlalchemy.orm import Session
from src.database.models import User
from src.schemas.users import UserModel
from sqlalchemy import update


async def get_user_by_email(email: str, db: Session):
    return db.query(User).filter(User.email == email).first()


async def create_user(body: UserModel, db: Session):
    user = User(email=body.email, password=body.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


async def update_token(user: User, token: str | None, db: Session):
    user.refresh_token = token
    db.commit()


async def confirm_email(email: str, db: Session):
    user = await get_user_by_email(email, db)
    if user:
        user.confirmed = True
        db.commit()
        db.refresh(user)
        return user


async def update_avatar(user: User, url: str, db: Session) -> User:
    user.avatar = url
    db.commit()
    db.refresh(user)
    return user


async def update_password(email: str, hashed_password: str, db: Session):
    user = await get_user_by_email(email, db)
    if user:
        user.password = hashed_password
        db.commit()
        db.refresh(user)
