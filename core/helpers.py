from fastapi import HTTPException

from classes import Threat, Type, Task

tempStorage = {
    "clients": {},
    "scans": {},
    "tasks": {},
    "fixes": {}
}

def authenticate(token: str) -> str:
    for host_id, data in tempStorage["clients"].items():
        if data['token'] == token:
            return host_id
    raise HTTPException(status_code=401, detail="Unauthorized")

def task_manager(threat: Threat):
    if threat.type == Type.exposed_port:
        return Task(
        type = Type.exposed_port,
        port = threat.port,
        comment = f"Close port {threat.port}!")
    else:
        return Task(
        type = threat.type,
        port = threat.port,
        comment = f"No fix available")


