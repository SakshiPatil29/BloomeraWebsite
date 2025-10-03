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
    
    # SECRET_KEY is crucial for session management, form security, etc.
    # The default 'dev-secret-change-me' is only for local development if the .env key is missing.
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    
    # Database Configuration (Uses bloomera.db by default)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///bloomera.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # --- 2. UPLOAD SETTINGS ---
    
    # Max file size for uploads (6 MB default)
    # MAX_CONTENT_LENGTH is expected in bytes
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_MB", 6)) * 1024 * 1024
    
    # --- 3. STRIPE PAYMENT GATEWAY CONFIGURATION ---
    
    # The Publishable Key (pk_...) is used by the frontend. Must be set in .env
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")
    
    # The Secret Key (sk_...) is used by the backend Python code. Must be set in .env
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
