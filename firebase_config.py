import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("path/to/your/firebase-service-account.json")
firebase_admin.initialize_app(cred)
