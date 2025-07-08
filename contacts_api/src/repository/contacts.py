from sqlalchemy.orm import Session
from src.database.models import Contact, User
from src.schemas.contacts import ContactCreate, ContactUpdate
from datetime import datetime, timedelta


def create_contact(db: Session, contact: ContactCreate, user: User):
    new_contact = Contact(**contact.model_dump(), user_id=user.id)
    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)
    return new_contact


def get_contacts(db: Session, user: User):
    return db.query(Contact).filter(Contact.user_id == user.id).all()


def get_contact_by_id(db: Session, contact_id: int, user: User):
    return (
        db.query(Contact)
        .filter(Contact.id == contact_id, Contact.user_id == user.id)
        .first()
    )


def update_contact(db: Session, contact_id: int, data: ContactUpdate, user: User):
    contact = get_contact_by_id(db, contact_id, user)
    if contact:
        for key, value in data.model_dump().items():
            setattr(contact, key, value)
        db.commit()
        db.refresh(contact)
    return contact


def delete_contact(db: Session, contact_id: int, user: User):
    contact = get_contact_by_id(db, contact_id, user)
    if contact:
        db.delete(contact)
        db.commit()
    return contact


def search_contacts(query: str, db: Session, user: User):
    return (
        db.query(Contact)
        .filter(Contact.user_id == user.id)
        .filter(
            (Contact.first_name.ilike(f"%{query}%"))
            | (Contact.last_name.ilike(f"%{query}%"))
            | (Contact.email.ilike(f"%{query}%"))
        )
        .all()
    )


def upcoming_birthdays(db: Session, user: User):
    today = datetime.today().date()
    next_week = today + timedelta(days=7)
    return (
        db.query(Contact)
        .filter(Contact.user_id == user.id)
        .filter(Contact.birthday.between(today, next_week))
        .all()
    )
