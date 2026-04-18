import sys
import os
from dotenv import load_dotenv

# Racine du projet
sys.path.insert(0, os.path.dirname(__file__))

# Charge le .env automatiquement pour les tests
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))