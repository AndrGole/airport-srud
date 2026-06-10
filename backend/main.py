from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List, Optional
import bcrypt

# === КОНФИГ ===
SECRET_KEY = "a7f3e9d2c1b5a8e4f6d2c9b3a1e5f8d2c7b4a1e9f3d6c8b2a5e7f9d4c1b3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# === БД ===
DATABASE_URL = "sqlite:///./airport.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === ХЕЛПЕРЫ ПАРОЛЕЙ ===
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# === МОДЕЛИ БД ===
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

# Создаём таблицы
Base.metadata.create_all(bind=engine)

# === PYDANTIC СХЕМЫ ===
class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool

class IncidentCreate(BaseModel):
    description: str
    severity: str

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[int] = None

class AccessZoneCreate(BaseModel):
    zone_name: str
    description: Optional[str] = None
    required_role: str = "visitor"

class AccessLogCreate(BaseModel):
    zone_id: int
    reader_location: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int

# === ХЕЛПЕРЫ ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(user_id: int, role: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"user_id": user_id, "role": role, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        role = payload.get("role")
        if user_id is None:
            raise HTTPException(401, "Invalid token")
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(401, "User not active")
        return {"user_id": user_id, "role": role, "email": user.email}
    except JWTError:
        raise HTTPException(401, "Invalid token")

def require_role(allowed_roles: List[str]):
    def role_checker(current_user = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(403, f"Access denied. Required role: {allowed_roles}")
        return current_user
    return role_checker

def log_action(user_id: int, action: str, details: str, ip_address: str = None, db: Session = None):
    log = AuditLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
    db.add(log)
    db.commit()

# === ИНИЦИАЛИЗАЦИЯ ===
def init_db():
    db = SessionLocal()
    
    # Создаём админа
    admin = db.query(User).filter(User.email == "admin@airport.com").first()
    if not admin:
        admin = User(
            email="admin@airport.com",
            password_hash=hash_password("admin123"),
            full_name="System Administrator",
            role="admin"
        )
        db.add(admin)
        print("✅ Admin created: admin@airport.com / admin123")
    
    # Создаём тестового охранника
    guard = db.query(User).filter(User.email == "guard@airport.com").first()
    if not guard:
        guard = User(
            email="guard@airport.com",
            password_hash=hash_password("guard123"),
            full_name="Security Guard",
            role="guard"
        )
        db.add(guard)
        print("✅ Guard created: guard@airport.com / guard123")
    
    # Создаём тестового посетителя
    visitor = db.query(User).filter(User.email == "visitor@airport.com").first()
    if not visitor:
        visitor = User(
            email="visitor@airport.com",
            password_hash=hash_password("visitor123"),
            full_name="Regular Visitor",
            role="visitor"
        )
        db.add(visitor)
        print("✅ Visitor created: visitor@airport.com / visitor123")
    
    db.commit()
    
    # Создаём зоны доступа
    zones = [
        {"name": "Public Area", "desc": "Check-in, shops, cafes", "role": "visitor"},
        {"name": "Departure Lounge", "desc": "Gate areas for passengers", "role": "visitor"},
        {"name": "Security Checkpoint", "desc": "Staff only", "role": "guard"},
        {"name": "Baggage Handling", "desc": "Restricted area", "role": "guard"},
        {"name": "Runway Access", "desc": "Airside operations", "role": "guard"},
        {"name": "Control Tower", "desc": "Air traffic control", "role": "guard"},
        {"name": "Server Room", "desc": "IT infrastructure", "role": "admin"},
        {"name": "Admin Office", "desc": "Management only", "role": "admin"},
    ]
    
    for zone in zones:
        existing = db.query(AccessZone).filter(AccessZone.zone_name == zone["name"]).first()
        if not existing:
            new_zone = AccessZone(
                zone_name=zone["name"],
                description=zone["desc"],
                required_role=zone["role"]
            )
            db.add(new_zone)
    db.commit()
    print("✅ Zones created")
    db.close()

# === APP ===
app = FastAPI(title="Airport SRUD API", version="3.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

# === ЭНДПОИНТЫ ===

@app.get("/")
def root():
    return {"message": "Airport SRUD API is running", "docs": "/docs"}

# ----- Аутентификация -----
@app.post("/api/auth/register", response_model=TokenResponse)
def register(user: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(400, "Email already registered")
    
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
    return {"access_token": token, "role": new_user.role, "user_id": new_user.id}

@app.post("/api/auth/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    
    if not db_user.is_active:
        raise HTTPException(403, "Account disabled")
    
    token = create_token(db_user.id, db_user.role)
    log_action(db_user.id, "LOGIN", f"User {user.email} logged in", None, db)
    return {"access_token": token, "role": db_user.role, "user_id": db_user.id}

# ----- Пользователи (только admin) -----
@app.get("/api/users", response_model=List[UserResponse])
def get_users(current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get("/api/users/me")
def get_me(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role}

@app.put("/api/users/{user_id}/role")
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
@app.get("/api/incidents")
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

@app.post("/api/incidents")
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

@app.put("/api/incidents/{incident_id}")
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

@app.delete("/api/incidents/{incident_id}")
def delete_incident(incident_id: int, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    db.delete(incident)
    db.commit()
    return {"message": "Incident deleted"}

# ----- Зоны доступа -----
@app.get("/api/zones")
def get_zones(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    zones = db.query(AccessZone).all()
    return zones

@app.post("/api/zones")
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
    return {"message": "Zone created", "zone": new_zone}

# ----- Проверка доступа -----
@app.post("/api/access-logs/check")
def check_access(log: AccessLogCreate, current_user = Depends(require_role(["visitor", "guard", "admin"])), db: Session = Depends(get_db)):
    zone = db.query(AccessZone).filter(AccessZone.id == log.zone_id).first()
    if not zone:
        raise HTTPException(404, "Zone not found")
    
    user_role = current_user["role"]
    required_role = zone.required_role
    
    def role_allows(user_role, required_role):
        # visitor может только visitor
        if user_role == "visitor":
            return required_role == "visitor"
        # guard может visitor и guard
        if user_role == "guard":
            return required_role in ["visitor", "guard"]
        # admin может visitor и admin
        if user_role == "admin":
            return required_role in ["visitor", "admin"]
        return False
    
    granted = role_allows(user_role, required_role)
    reason = None
    
    if not granted:
        reason = f"Access denied: {user_role} cannot access {zone.zone_name} (requires {required_role})"
    
    # Логируем попытку
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
    
    # Если доступ запрещён — создаём инцидент
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
@app.get("/api/access-logs/my")
def get_my_logs(limit: int = 50, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AccessLog).filter(AccessLog.user_id == current_user["user_id"]).order_by(AccessLog.timestamp.desc()).limit(limit).all()

@app.get("/api/access-logs/all")
def get_all_logs(limit: int = 100, current_user = Depends(require_role(["guard", "admin"])), db: Session = Depends(get_db)):
    return db.query(AccessLog).order_by(AccessLog.timestamp.desc()).limit(limit).all()

# ----- Аудит (только admin) -----
@app.get("/api/audit-log")
def get_audit_log(limit: int = 50, current_user = Depends(require_role(["admin"])), db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

# ----- Статистика -----
@app.get("/api/stats")
def get_stats(current_user = Depends(require_role(["guard", "admin"])), db: Session = Depends(get_db)):
    return {
        "total_incidents": db.query(Incident).count(),
        "open_incidents": db.query(Incident).filter(Incident.status == "new").count(),
        "total_users": db.query(User).count(),
        "total_zones": db.query(AccessZone).count(),
        "today_access": db.query(AccessLog).filter(AccessLog.timestamp >= datetime.utcnow().date()).count()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)