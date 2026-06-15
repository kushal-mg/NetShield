import os
import json
import platform
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Get DATABASE_URL or fallback to local SQLite database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netshield.db")

# If running on Windows and the URL points to the Docker host "db", force SQLite fallback for local testing
if "db:5432" in DATABASE_URL and platform.system().lower() == "windows":
    DATABASE_URL = "sqlite:///./netshield.db"

# SQLite needs special flags for multi-threading
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(50), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(String(50), nullable=False)
    dst_port = Column(Integer, nullable=False)
    attack_type = Column(String(50), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    features_json = Column(Text, nullable=False)  # Stores raw input features as JSON
    ai_summary = Column(Text, nullable=True)      # Gemini threat report / SIGMA rule

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# CRUD operations
def save_alert(db, alert_data):
    features_str = json.dumps(alert_data.get("features", {}))
    
    alert = Alert(
        src_ip=alert_data["src_ip"],
        src_port=alert_data["src_port"],
        dst_ip=alert_data["dst_ip"],
        dst_port=alert_data["dst_port"],
        attack_type=alert_data["attack_type"],
        confidence=float(alert_data["confidence"]),
        severity=alert_data["severity"],
        features_json=features_str,
        ai_summary=alert_data.get("ai_summary")
    )
    
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

def get_alerts(db, limit=50):
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()

def get_stats(db):
    # Retrieve alerts breakdown for charts
    total_alerts = db.query(Alert).count()
    
    # Severity breakdown
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for sev in severity_counts.keys():
        severity_counts[sev] = db.query(Alert).filter(Alert.severity == sev).count()
        
    # Attack type breakdown
    attack_types = ["DDoS", "Port Scan", "Brute Force", "Botnet"]
    attack_counts = {attack: 0 for attack in attack_types}
    for attack in attack_types:
        attack_counts[attack] = db.query(Alert).filter(Alert.attack_type == attack).count()
        
    # Model average confidence
    avg_confidence = 0.0
    if total_alerts > 0:
        confidences = [a.confidence for a in db.query(Alert.confidence).all()]
        avg_confidence = sum(confidences) / len(confidences)
        
    return {
        "total_alerts": total_alerts,
        "severity_breakdown": severity_counts,
        "attack_breakdown": attack_counts,
        "average_confidence": round(avg_confidence, 4)
    }
