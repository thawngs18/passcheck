import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Google AI Studio API Key
    GOOGLE_AI_API_KEY = os.getenv('GOOGLE_AI_API_KEY', 'your_api_key_here')
    
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Debug mode
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
