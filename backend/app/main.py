from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import traffic, alerts, users, replay
from . import notifications
from .database import init_db

app = FastAPI(title="Cyber Analyzer", version="1.0.0")

@app.on_event("startup")
def startup_event():
    print("🚀 Starting Cyber Analyzer backend...")
    init_db()  # ensures DB is ready

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router, prefix="/api/traffic", tags=["Traffic"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(replay.router, prefix="/api/replay", tags=["Replay"])
app.include_router(notifications.router, prefix="/api/notify", tags=["Notifications"])

@app.get("/")
def root():
    return {"status": "Cyber Analyzer backend running 🚀"}
