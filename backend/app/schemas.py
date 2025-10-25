from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

# --- User models ---
class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "viewer"

class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime
    class Config:
        from_attributes = True

class UserMe(BaseModel):
    id: int
    username: str
    role: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Packet model ---
class PacketOut(BaseModel):
    id: Optional[int]
    timestamp: datetime
    src: Optional[str]
    dst: Optional[str]
    proto: Optional[str]
    sport: Optional[int]
    dport: Optional[int]
    length: int
    dns: Optional[str]
    payload_sample: Optional[str]
    class Config:
        from_attributes = True

# --- Alert model ---
class AlertOut(BaseModel):
    id: Optional[int]
    type: str
    details: Dict[str, Any]
    created_at: datetime
    resolved: bool = False
    risk_score: Optional[str] = None
    geo_info: Optional[str] = None
    isp: Optional[str] = None
    dns_queries: Optional[str] = None
    threat_score: Optional[int] = 0
    entropy_score: Optional[int] = None
    vt_report: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True