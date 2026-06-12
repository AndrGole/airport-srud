from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import bcrypt
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import get_db
from models import User

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

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

def require_role(allowed_roles):
    def role_checker(current_user = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(403, f"Access denied. Required role: {allowed_roles}")
        return current_user
    return role_checker

def log_action(user_id: int, action: str, details: str, ip_address: str = None, db: Session = None):
    from models import AuditLog
    log = AuditLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
    db.add(log)
    db.commit()