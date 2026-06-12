from pydantic import BaseModel
from typing import Optional, List

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
    full_name: str