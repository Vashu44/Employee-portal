from fastapi_mail import ConnectionConfig
# from pydantic import EmailStr
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Simple direct approach - no Pydantic settings
MAIL_USERNAME = os.getenv("MAIL_USERNAME") 
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_USERNAME")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_STARTTLS = os.getenv("MAIL_STARTTLS", "True").lower() == "true"
MAIL_SSL_TLS = os.getenv("MAIL_SSL_TLS", "False").lower() == "true"

# Validate that required settings are provided
if not all([MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM]):
    raise ValueError("Email configuration is incomplete. Please check your .env file.")

conf = ConnectionConfig(
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_FROM=MAIL_FROM,
    MAIL_PORT=MAIL_PORT,
    MAIL_SERVER=MAIL_SERVER,
    MAIL_STARTTLS=MAIL_STARTTLS,
    MAIL_SSL_TLS=MAIL_SSL_TLS,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)