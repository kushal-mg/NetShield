import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load env variables from .env file
load_dotenv()

from app.store.alert_store import init_db
from app.routes import router

app = FastAPI(
    title="NetShield API",
    description="Backend API for NetShield Intrusion Detection System",
    version="1.0.0"
)

# CORS Middleware Configurations
# Allows frontend dashboard running on Vite local development server to query endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event to ensure database connection and table structures are created
@app.on_event("startup")
def on_startup():
    print("Initializing Database tables...")
    init_db()
    print("Database initialization successful.")

# Mount routing groups
app.include_router(router)

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    print(f"Starting NetShield FastAPI server on {host}:{port}...")
    uvicorn.run("main:app", host=host, port=port, reload=True)
