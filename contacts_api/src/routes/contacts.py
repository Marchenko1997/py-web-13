from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from src.schemas.contacts import *
from src.database.db import get_db
from src.repository import contacts as repo
from src.database.models import User
from src.services.auth import auth_service
from fastapi_limiter.depends import RateLimiter

router = APIRouter(prefix="/contacts", tags=["contacts"])


@router.post(
    "/",
    response_model=ContactResponse,
    dependencies=[Depends(RateLimiter(times=2, seconds=300))],
)
def create(
    contact: ContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    return repo.create_contact(db, contact, current_user)


@router.get("/", response_model=List[ContactResponse])
def read_all(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    return repo.get_contacts(db, current_user)


@router.get("/{contact_id}", response_model=ContactResponse)
def read_one(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    contact = repo.get_contact_by_id(db, contact_id, current_user)
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@router.put("/{contact_id}", response_model=ContactResponse)
def update(
    contact_id: int,
    contact: ContactUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    updated_contact = repo.update_contact(db, contact_id, contact, current_user)
    if not updated_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return updated_contact


@router.delete("/{contact_id}", response_model=ContactResponse)
def delete(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    deleted_contact = repo.delete_contact(db, contact_id, current_user)
    if not deleted_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return deleted_contact


@router.get("/search/{query}", response_model=List[ContactResponse])
def search(
    query: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    return repo.search_contacts(query, db, current_user)


@router.get("/birthdays/upcoming", response_model=List[ContactResponse])
def birthdays(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_service.get_current_user),
):
    return repo.upcoming_birthdays(db, current_user)
