// frontends/src/services/firebase.ts
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY ?? "AIzaSyA9LvIz7ueK6q7bHECkmTJw9CYgpDTam8U",
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN ?? "vulnerabilityscanner-88028.firebaseapp.com",
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID ?? "vulnerabilityscanner-88028",
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET ?? "vulnerabilityscanner-88028.appspot.com",
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID ?? "94404191791",
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID ?? "1:94404191791:web:40301c20e2d9b8028088da",
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export default app;
 