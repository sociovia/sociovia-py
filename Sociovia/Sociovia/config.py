# config.py
from datetime import timedelta

class Config:
    # Security
    # NOTE: For quick local testing you can hardcode, but DO NOT commit this file to any repo.
    SECRET_KEY = "change_me_super_secret_production_key"

    # Database (hardcoded sqlite file)
    SQLALCHEMY_DATABASE_URI = "sqlite:///sociovia.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Email Configuration (HARDCODED - replace SMTP_PASS below)
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "noreply.sociovia@gmail.com"
    SMTP_PASS = "sirr tpif vhku limb"  
    MAIL_FROM = "Sociovia <noreply.sociovia@gmail.com>"

    # Admin Configuration (hardcoded)
    ADMIN_EMAILS = ["sharan1114411@gmail.com"]

    # Application URLs
    APP_BASE_URL = "http://localhost:5000"
    FRONTEND_ORIGIN = "http://localhost:8080"

    # Timing Configuration
    VERIFY_TTL_MIN = 15
    ADMIN_LINK_TTL_HOURS = 48

    # Session lifetime (optional)
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
