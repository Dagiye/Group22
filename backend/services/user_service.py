# backend/services/user_service.py
from typing import Optional, Dict, List
from fastapi import HTTPException, status

from backend.services.firebase_admin import firestore_client, firebase_auth

USERS_COLLECTION = "users"

class UserService:
    def init(self):
        self.db = firestore_client

    def create_user(self, email: str, password: str, role: str = "user") -> Dict:
        try:
            user_record = firebase_auth.create_user(email=email, password=password)
            self.db.collection(USERS_COLLECTION).document(user_record.uid).set({
                "email": email,
                "role": role,
            })
            return {"uid": user_record.uid, "email": email, "role": role}
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    def get_user(self, uid: str) -> Optional[Dict]:
        doc = self.db.collection(USERS_COLLECTION).document(uid).get()
        return doc.to_dict() if doc.exists else None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        query = self.db.collection(USERS_COLLECTION).where("email", "==", email).limit(1).get()
        return query[0].to_dict() if query else None

    def list_users(self) -> List[Dict]:
        return [doc.to_dict() for doc in self.db.collection(USERS_COLLECTION).stream()]

    def update_role(self, uid: str, role: str) -> Dict:
        doc_ref = self.db.collection(USERS_COLLECTION).document(uid)
        if not doc_ref.get().exists:
            raise HTTPException(status_code=404, detail="User not found")
        doc_ref.update({"role": role})
        # set custom claims in firebase auth so token can reflect role
        firebase_auth.set_custom_user_claims(uid, {"role": role})
        return {"uid": uid, "role": role}

    def delete_user(self, uid: str):
        try:
            firebase_auth.delete_user(uid)
            self.db.collection(USERS_COLLECTION).document(uid).delete()
            return {"status": "deleted", "uid": uid}
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))