import sys
import os
from dotenv import load_dotenv
from unittest.mock import patch

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
sys.path.insert(0, os.path.dirname(__file__))

# Mock email — pas d'envoi réel pendant les tests
patch(
    "app.application.services.email.send_verification_email",
    return_value=None
).start()