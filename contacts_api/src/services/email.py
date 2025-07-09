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


async def send_reset_email(email: EmailStr, token: str):
   
    reset_link = f"{settings.base_url}/reset-password" f"?token={token}&email={email}"

    html = f"""
        <h3>Запрос на сброс пароля</h3>
        <p>Если вы не запрашивали сброс, просто проигнорируйте письмо.</p>
        <p>Иначе нажмите на ссылку ниже, чтобы задать новый пароль:</p>
        <a href="{reset_link}">{reset_link}</a>
        <p>Ссылка действительна 1 час.</p>
    """

    msg = MessageSchema(
        subject="Сброс пароля",
        recipients=[email],
        body=html,
        subtype="html",
    )
    await FastMail(conf).send_message(msg)
