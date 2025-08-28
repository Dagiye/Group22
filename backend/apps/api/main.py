# backend/apps/api/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.routers import scan, auth, report, status, admin

app = FastAPI(
    title="WebScanner API",
    description="API backend for a universal web application vulnerability scanner",
    version="1.0.0",
)

# CORS setup
origins = [
    "http://localhost",
    "http://localhost:3000",  # Frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(scan.router, prefix="/scan", tags=["scan"])
app.include_router(report.router, prefix="/report", tags=["report"])
app.include_router(status.router, prefix="/status", tags=["status"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])

@app.get("/")
async def root():
    return {"message": "Welcome to WebScanner API"}
