from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from src.conf.config import settings


conf = ConnectionConfig(
    MAIL_USERNAME=settings.mail_username,
    MAIL_PASSWORD=settings.mail_password,
    MAIL_FROM=settings.mail_from,
    MAIL_PORT=settings.mail_port,
    MAIL_SERVER=settings.mail_server,
    MAIL_FROM_NAME=settings.mail_from_name,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False,
)


async def send_verification_email(email: EmailStr, token: str):
    """Шлём письмо с ссылкой вида  http://localhost:8000/api/auth/confirm_email/{token}"""
    verify_link = f"{settings.base_url}/api/auth/confirm_email/{token}"
    html = f"""
        <h3>Привет!</h3>
        <p>Для подтверждения адреса нажмите на ссылку:</p>
        <a href="{verify_link}">{verify_link}</a>
    """
    message = MessageSchema(
        subject="Email confirmation", recipients=[email], body=html, subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
