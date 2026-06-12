from sqlalchemy.orm import Session
from models import User, AccessZone, Incident, AccessLog, AuditLog
from auth import hash_password
from datetime import datetime

def init_db(db: Session):
    admin = db.query(User).filter(User.email == "admin@airport.com").first()
    if not admin:
        admin = User(
            email="admin@airport.com",
            password_hash=hash_password("admin123"),
            full_name="System Administrator",
            role="admin"
        )
        db.add(admin)
        print("Admin created: admin@airport.com / admin123")
    
    guard = db.query(User).filter(User.email == "guard@airport.com").first()
    if not guard:
        guard = User(
            email="guard@airport.com",
            password_hash=hash_password("guard123"),
            full_name="Security Guard",
            role="guard"
        )
        db.add(guard)
        print("Guard created: guard@airport.com / guard123")
    
    visitor = db.query(User).filter(User.email == "visitor@airport.com").first()
    if not visitor:
        visitor = User(
            email="visitor@airport.com",
            password_hash=hash_password("visitor123"),
            full_name="Regular Visitor",
            role="visitor"
        )
        db.add(visitor)
        print("Visitor created: visitor@airport.com / visitor123")
    
    db.commit()
    
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
    print("Zones created")