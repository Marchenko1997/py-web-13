
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
import cloudinary
import cloudinary.uploader

from src.database.db import get_db
from src.database.models import User
from src.repository import users as repository_users
from src.services.auth import auth_service
from src.conf.config import settings
from src.schemas.users import UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def read_me(current_user: User = Depends(auth_service.get_current_user)):
    return current_user


@router.patch(
    "/avatar",
    response_model=UserResponse,
    summary="Upload / update user avatar",
    description="One request per 30 s",  
)
async def update_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(auth_service.get_current_user),
    db: Session = Depends(get_db),
):
    
    cloudinary.config(
        cloud_name=settings.cloudinary_name,
        api_key=settings.cloudinary_api_key,
        api_secret=settings.cloudinary_api_secret,
        secure=True,
    )

 
    upload_result = cloudinary.uploader.upload(
        file.file,
        public_id=f"ContactApp/{current_user.id}",
        overwrite=True,
    )

  
    avatar_url = cloudinary.CloudinaryImage(f"ContactApp/{current_user.id}").build_url(
        width=250, height=250, crop="fill", version=upload_result.get("version")
    )

  
    user = await repository_users.update_avatar(current_user, avatar_url, db)
    return user
