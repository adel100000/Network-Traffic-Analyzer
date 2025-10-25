from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer")
    created_at = Column(DateTime, default=datetime.utcnow)

class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src = Column(String)
    dst = Column(String)
    proto = Column(String)
    sport = Column(Integer, nullable=True)
    dport = Column(Integer, nullable=True)
    length = Column(Integer)
    dns = Column(String, nullable=True)
    payload_sample = Column(String, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    details = Column(JSON, nullable=False, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)
    risk_score = Column(String, nullable=True)
    geo_info = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    dns_queries = Column(String, nullable=True)
    threat_score = Column(Integer, nullable=True)
    entropy_score = Column(Integer, nullable=True)
    vt_report = Column(JSON, nullable=True)
