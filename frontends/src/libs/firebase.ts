
import { initializeApp, getApps } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyA9LvIz7ueK6q7bHECkmTJw9CYgpDTam8U",
  authDomain: "vulnerabilityscanner-88028.firebaseapp.com",
  projectId: "vulnerabilityscanner-88028",
  storageBucket: "vulnerabilityscanner-88028.firebasestorage.app",
  messagingSenderId: "94404191791",
  appId: "1:94404191791:web:40301c20e2d9b8028088da",
};

if (!getApps().length) {
  initializeApp(firebaseConfig);
}

export const firebaseAuth = getAuth();
export const firebaseDb = getFirestore();
