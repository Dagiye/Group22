# services/auth_service.py
from core import datastore
import hashlib
import secrets

class AuthService:
    def __init__(self):
        self.datastore = datastore.DataStore()

    def hash_password(self, password: str) -> str:
        """
        Hash the password using SHA256.
        (For production, use bcrypt/argon2 instead)
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username: str, password: str, role: str = "user") -> dict:
        """
        Register a new user with hashed password.
        """
        password_hash = self.hash_password(password)
        user_id = self.datastore.save_user(username, role, password_hash)
        return {"user_id": user_id, "username": username, "role": role}

    def authenticate(self, username: str, password: str) -> dict:
        """
        Authenticate a user and return an access token if valid.
        """
        user = self.datastore.find_user(username)
        if not user:
            return {"status": "failed", "reason": "user not found"}

        if user["password"] != self.hash_password(password):
            return {"status": "failed", "reason": "invalid credentials"}

        token = secrets.token_hex(16)
        self.datastore.save_session(user["id"], token)
        return {"status": "success", "token": token, "user_id": user["id"], "role": user["role"]}

    def validate_token(self, token: str) -> dict:
        """
        Check if a token is valid and return user context.
        """
        session = self.datastore.get_session(token)
        if not session:
            return {"status": "invalid"}

        user = self.datastore.load_user(session["user_id"])
        return {"status": "valid", "user": user}

    def logout(self, token: str) -> dict:
        """
        Destroy a session.
        """
        self.datastore.delete_session(token)
        return {"status": "logged out"}
