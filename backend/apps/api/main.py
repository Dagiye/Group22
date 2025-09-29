
import logging
import importlib
import pkgutil
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# initialize firebase early
import backend.apps.api.firebase_init  # ensures admin SDK is ready

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Web Vulnerability Scanner Backend")

# allow your frontend origin(s); during dev we'll allow localhost ports
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# include routers explicitly
from backend.apps.api.routers import auth, scan
app.include_router(auth.router)
app.include_router(scan.router)

@app.get("/")
async def root():
    return {"message": "Backend running ✅"}
