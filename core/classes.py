from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class RawData(BaseModel):
    data: List[str]

class Type(str, Enum):
    exposed_port = "exposed_port"
    suid_set = "suid_set"
    sudoers_abuse = "sudoers_abuse"
    unsecure_code = "unsecure_code"

class Host(BaseModel):
    hostname: str
    ip_addr: str

class Threat(BaseModel):
    type: Type
    port: Optional[int] = None
    service: Optional[str] = None
    file_name: Optional[str] = None
    comment: Optional[str] = None

    fix_available: bool = Field(default=False)
    fixed: bool = Field(default=False)

class Task(BaseModel):
    type: Type
    port: Optional[int] = None
    file_name: Optional[str] = None
    comment: Optional[str] = None

class ThreatList(BaseModel):
    threats: List[Threat]

class TaskList(BaseModel):
    tasks: List[Task] = Field(default_factory=list)
