from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .models import AlertStatus, Role, Severity

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; email: str; full_name: str; role: Role
class LoginIn(BaseModel): email: str; password: str = Field(min_length=8, max_length=128)
class RegisterIn(LoginIn): full_name: str = Field(min_length=1, max_length=120)
class TokenOut(BaseModel): access_token: str; token_type: str = "bearer"; user: UserOut
class EventIn(BaseModel):
    timestamp: datetime | None = None; source: str = Field(min_length=1, max_length=80); event_type: str = Field(min_length=1, max_length=80)
    severity: Severity = Severity.LOW; username: str | None = None; source_ip: str | None = None; destination_ip: str | None = None
    hostname: str | None = None; application: str | None = None; action: str | None = None; status: str | None = None
    message: str = Field(min_length=1, max_length=4000); metadata: dict = Field(default_factory=dict); raw_event: dict = Field(default_factory=dict)
class EventOut(EventIn):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: int; created_at: datetime
class StatusIn(BaseModel): status: AlertStatus
class NoteIn(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Note content must not be blank")
        return value

class RuleUpdate(BaseModel): enabled: bool | None = None; config: dict | None = None
