from typing import Dict
from firebase_admin import firestore
import bcrypt
import jwt
import datetime

# Initialize Firebase Admin (make sure you have credentials)
import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("backend/firebase-service-account.json")


db = firestore.client()

SECRET_KEY = "your-secret-key"

class AuthService:
    @staticmethod
    def register_user(email: str, password: str) -> Dict:
        # check if user exists
        users_ref = db.collection("users")
        existing = users_ref.where("email", "==", email).get()
        if existing:
            raise Exception("Email already registered")

        # hash password
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # create user document with timestamp
        doc_ref = users_ref.document()
        doc_ref.set({
            "email": email,
            "password": hashed_pw.decode("utf-8"),
            "created_at": datetime.datetime.utcnow(),
        })
        return {"uid": doc_ref.id, "email": email}

    @staticmethod
    def login_user(email: str, password: str):
        users_ref = db.collection("users")
        docs = users_ref.where("email", "==", email).get()
        if not docs:
            raise Exception("Invalid email or password")
        user_doc = docs[0]
        user_data = user_doc.to_dict()
        if not bcrypt.checkpw(password.encode("utf-8"), user_data["password"].encode("utf-8")):
            raise Exception("Invalid email or password")
        
        # generate JWT token
        payload = {
            "sub": user_doc.id,
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return {"uid": user_doc.id, "email": email}, token