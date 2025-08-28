# services/user_service.py
from core import datastore

class UserService:
    def __init__(self):
        self.datastore = datastore.DataStore()

    def create_user(self, username: str, role: str = "user") -> dict:
        """
        Register a new user.
        """
        user_id = self.datastore.save_user(username, role)
        return {"user_id": user_id, "username": username, "role": role}

    def get_user(self, user_id: str) -> dict:
        """
        Retrieve user profile by ID.
        """
        return self.datastore.load_user(user_id)

    def list_users(self) -> list:
        """
        List all registered users.
        """
        return self.datastore.list_users()

    def delete_user(self, user_id: str) -> dict:
        """
        Remove a user.
        """
        self.datastore.delete_user(user_id)
        return {"user_id": user_id, "status": "deleted"}
