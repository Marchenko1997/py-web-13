from pydantic_settings import BaseSettings 
from pydantic import EmailStr


class Settings(BaseSettings):
    database_url: str
    secret_key: str
    algorithm: str = "HS256"

    mail_username: EmailStr
    mail_password: str
    mail_from: EmailStr
    mail_port: int
    mail_server: str
    mail_from_name: str
    email_secret_key: str
    base_url: str

    cloudinary_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

    redis_host: str = "localhost"
    redis_port: int = 6379

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
