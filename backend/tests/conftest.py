import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.detection import default_rules
from app.main import app
from app.models import DetectionRule, User
from app.security import hash_password


@pytest.fixture(scope="session")
def demo_hashes():
    return {role: hash_password(f"{role.title()}Pass123!") for role in ("ADMIN", "ANALYST", "VIEWER")}


@pytest.fixture
def db(demo_hashes):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as session:
        for role, password_hash in demo_hashes.items():
            session.add(User(email=f"{role.lower()}@breachwatch.local", full_name=f"Demo {role.title()}", role=role, password_hash=password_hash))
        session.add_all(DetectionRule(**rule) for rule in default_rules())
        session.commit()
        yield session
    engine.dispose()


@pytest.fixture
def client(db):
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    # No application startup needed: the fixture owns the isolated database.
    test_client = TestClient(app, raise_server_exceptions=True)
    try:
        yield test_client
    finally:
        test_client.close()
        app.dependency_overrides.clear()


@pytest.fixture
def auth(client):
    def headers(role="ANALYST"):
        response = client.post("/api/auth/login", json={"email": f"{role.lower()}@breachwatch.local", "password": f"{role.title()}Pass123!"})
        assert response.status_code == 200
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return headers
