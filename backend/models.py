from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, default="visitor")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AccessZone(Base):
    __tablename__ = "access_zones"
    id = Column(Integer, primary_key=True, index=True)
    zone_name = Column(String, unique=True, nullable=False)
    description = Column(String)
    required_role = Column(String, default="visitor")

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    zone_id = Column(Integer, ForeignKey("access_zones.id"))
    zone_name = Column(String)
    access_granted = Column(Boolean, default=False)
    reader_location = Column(String)
    reason = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String)
    status = Column(String, default="new")
    reported_by = Column(Integer, ForeignKey("users.id"))
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)
    details = Column(Text)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)