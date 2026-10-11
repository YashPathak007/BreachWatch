from datetime import datetime, timedelta, timezone
from random import choice
from sqlalchemy import select
from .config import get_settings
from .db import Base, SessionLocal, engine
from .detection import default_rules
from .main import ingest
from .models import DetectionRule, Role, User
from .schemas import EventIn
from .security import hash_password


def seed():
    Base.metadata.create_all(bind=engine); db=SessionLocal(); settings=get_settings()
    users=[("admin@breachwatch.local","Avery Admin",Role.ADMIN.value,settings.demo_admin_password),("analyst@breachwatch.local","Morgan Analyst",Role.ANALYST.value,settings.demo_analyst_password),("viewer@breachwatch.local","Taylor Viewer",Role.VIEWER.value,settings.demo_viewer_password)]
    for email,name,role,password in users:
        if not db.scalar(select(User).where(User.email==email)): db.add(User(email=email,full_name=name,role=role,password_hash=hash_password(password)))
    for item in default_rules():
        if not db.scalar(select(DetectionRule).where(DetectionRule.rule_key==item["rule_key"])): db.add(DetectionRule(**item))
    db.commit(); db.close()

if __name__ == "__main__": seed()
