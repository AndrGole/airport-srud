from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List
from database import get_db
from models import User, Incident, AccessZone, AccessLog, AuditLog
from schemas import *
from auth import get_current_user, require_role, create_token, verify_password, log_action, hash_password
import re

router = APIRouter()

# ----- Аутентификация -----
@router.post("/api/auth/register", response_model=TokenResponse)
def register(user: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(400, "Email already registered")
    
    if len(user.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters long")
    
    if not re.search(r"\d", user.password):
        raise HTTPException(400, "Password must contain at least one digit")
    
    if "@" not in user.email or "." not in user.email:
        raise HTTPException(400, "Invalid email format")
    
    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
        full_name=user.full_name,
        role="visitor"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    token = create_token(new_user.id, new_user.role)
    log_action(new_user.id, "REGISTER", f"User {new_user.email} registered", None, db)
    return {"access_token": token, "role": new_user.role, "user_id": new_user.id, "full_name": new_user.full_name}

@router.post("/api/auth/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    
    if not db_user.is_active:
        raise HTTPException(403, "Account disabled")
    
    token = create_token(db_user.id, db_user.role)
    log_action(db_user.id, "LOGIN", f"User {user.email} logged in", None, db)
    return {"access_token": token, "role": db_user.role, "user_id": db_user.id, "full_name": db_user.full_name}

# ----- Пользователи -----
@router.get("/api/users", response_model=List[UserResponse])
def get_users(current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    return db.query(User).all()

@router.get("/api/users/me")
def get_me(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role}

@router.put("/api/users/{user_id}/role")
def update_user_role(user_id: int, role: str, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    if role not in ["visitor", "guard", "admin"]:
        raise HTTPException(400, "Invalid role")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.role = role
    db.commit()
    log_action(current_user["user_id"], "UPDATE_ROLE", f"Changed user {user.email} role to {role}", None, db)
    return {"message": "Role updated"}

# ----- Инциденты -----
@router.get("/api/incidents")
def get_incidents(
    status: Optional[str] = None,
    current_user = Depends(require_role(["visitor", "guard", "admin"])),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if current_user["role"] == "visitor":
        query = query.filter(Incident.reported_by == current_user["user_id"])
    return query.order_by(Incident.created_at.desc()).all()

@router.post("/api/incidents")
def create_incident(incident: IncidentCreate, current_user = Depends(require_role(["visitor", "guard"])), db: Session = Depends(get_db)):
    new_incident = Incident(
        description=incident.description,
        severity=incident.severity,
        reported_by=current_user["user_id"]
    )
    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)
    log_action(current_user["user_id"], "CREATE_INCIDENT", incident.description[:50], None, db)
    return new_incident

@router.put("/api/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate, current_user = Depends(require_role(["guard", "admin"])), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    if update.status:
        incident.status = update.status
    if update.assigned_to:
        incident.assigned_to = update.assigned_to
    incident.updated_at = datetime.utcnow()
    db.commit()
    log_action(current_user["user_id"], "UPDATE_INCIDENT", f"Updated incident {incident_id}", None, db)
    return {"message": "Incident updated"}

@router.delete("/api/incidents/{incident_id}")
def delete_incident(incident_id: int, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    incident_info = f"Incident {incident_id}: {incident.description[:50]}"
    db.delete(incident)
    db.commit()
    log_action(current_user["user_id"], "DELETE_INCIDENT", incident_info, None, db)
    return {"message": "Incident deleted"}

# ----- Зоны доступа -----
@router.get("/api/zones")
def get_zones(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AccessZone).all()

@router.post("/api/zones")
def create_zone(zone: AccessZoneCreate, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    existing = db.query(AccessZone).filter(AccessZone.zone_name == zone.zone_name).first()
    if existing:
        raise HTTPException(400, "Zone already exists")
    new_zone = AccessZone(
        zone_name=zone.zone_name,
        description=zone.description,
        required_role=zone.required_role
    )
    db.add(new_zone)
    db.commit()
    log_action(current_user["user_id"], "CREATE_ZONE", f"Zone: {zone.zone_name}, required_role: {zone.required_role}", None, db)
    return {"message": "Zone created", "zone": new_zone}

# ----- Проверка доступа -----
@router.post("/api/access-logs/check")
def check_access(log: AccessLogCreate, current_user = Depends(require_role(["visitor", "guard", "admin"])), db: Session = Depends(get_db)):
    zone = db.query(AccessZone).filter(AccessZone.id == log.zone_id).first()
    if not zone:
        raise HTTPException(404, "Zone not found")
    
    user_role = current_user["role"]
    required_role = zone.required_role
    
    def role_allows(user_role, required_role):
        if user_role == "visitor":
            return required_role == "visitor"
        if user_role == "guard":
            return required_role in ["visitor", "guard"]
        if user_role == "admin":
            return required_role in ["visitor", "admin"]
        return False
    
    granted = role_allows(user_role, required_role)
    reason = None
    if not granted:
        reason = f"Access denied: {user_role} cannot access {zone.zone_name} (requires {required_role})"
    
    access_log = AccessLog(
        user_id=current_user["user_id"],
        zone_id=zone.id,
        zone_name=zone.zone_name,
        access_granted=granted,
        reader_location=log.reader_location,
        reason=reason
    )
    db.add(access_log)
    db.commit()
    
    incident_created = False
    if not granted:
        incident = Incident(
            description=f"UNAUTHORIZED ACCESS: User {current_user['email']} attempted to enter {zone.zone_name} at {log.reader_location}. User role: {user_role}, required: {required_role}",
            severity="high",
            reported_by=current_user["user_id"],
            status="new"
        )
        db.add(incident)
        db.commit()
        incident_created = True
        log_action(current_user["user_id"], "UNAUTHORIZED_ACCESS", f"Zone {zone.zone_name}, Location {log.reader_location}", None, db)
    
    return {
        "granted": granted,
        "zone": zone.zone_name,
        "required_role": required_role,
        "user_role": user_role,
        "message": "Access granted" if granted else "Access denied",
        "incident_created": incident_created
    }

# ----- Логи доступа -----
@router.get("/api/access-logs/my")
def get_my_logs(limit: int = 50, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AccessLog).filter(AccessLog.user_id == current_user["user_id"]).order_by(AccessLog.timestamp.desc()).limit(limit).all()

@router.get("/api/access-logs/all")
def get_all_logs(limit: int = 100, current_user = Depends(require_role(["guard", "admin"])), db: Session = Depends(get_db)):
    return db.query(AccessLog).order_by(AccessLog.timestamp.desc()).limit(limit).all()

# ----- Аудит -----
@router.get("/api/audit-log")
def get_audit_log(limit: int = 50, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

# ----- Статистика -----
@router.get("/api/stats")
def get_stats(current_user = Depends(require_role(["guard", "admin"])), db: Session = Depends(get_db)):
    return {
        "total_incidents": db.query(Incident).count(),
        "open_incidents": db.query(Incident).filter(Incident.status == "new").count(),
        "total_users": db.query(User).count(),
        "total_zones": db.query(AccessZone).count(),
        "today_access": db.query(AccessLog).filter(AccessLog.timestamp >= datetime.utcnow().date()).count()
    }

@router.get("/")
def root():
    return {"message": "Airport SRUD API is running", "docs": "/docs"}