from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Date, func
from src.database.db import Base
from sqlalchemy.orm import relationship

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(100), unique=True, index=True)
    phone = Column(String(20))
    birthday = Column(Date)
    additional_info = Column(String(250), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="contacts")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    refresh_token = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=func.now())
    confirmed = Column(Boolean, default=False)
    avatar = Column(String(512), nullable=True)
    contacts = relationship("Contact", back_populates="user")
