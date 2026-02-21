from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class Type(str, Enum):
    exposed_port = "exposed_port"
    suid_set = "suid_set"
    sudoers_abuse = "sudoers_abuse"

class Host(BaseModel):
    hostname: str
    ip_addr: str

class Threat(BaseModel):
    type: Type
    port: Optional[str] = None
    service: Optional[str] = None
    fix_available: bool = Field(default=False)
    fixed: bool = Field(default=False)

class Issue(BaseModel):
    host: Host
    threats: List[Threat]