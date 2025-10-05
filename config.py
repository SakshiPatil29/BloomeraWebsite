import os
from dotenv import load_dotenv

# Load environment variables from .env file (must be in the root directory)
load_dotenv()


class Config:
    """
    Configuration settings for the Bloomera Jewels Flask application.
    Uses environment variables for sensitive data and application settings.
    """

    # --- 1. CORE FLASK & DATABASE SETTINGS ---
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///bloomera.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- 2. UPLOAD SETTINGS ---
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_MB", 6)) * 1024 * 1024

    # --- 3. STRIPE PAYMENT GATEWAY CONFIGURATION ---
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")

    # --- 4. GOOGLE OAUTH CONFIGURATION ---
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
