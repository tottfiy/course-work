from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field
from enum import Enum

class Response(str, Enum):
    ok = "ok"
    error = "error"

class Type(str, Enum):
    exposed_port = "exposed_port"
    suid_set = "suid_set"
    sudoers_abuse = "sudoers_abuse"

class Host(BaseModel):
    host_id: int
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


tempStorage = {
    "clients": {}, 
    "scans": {}
    }

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}


# fetches scan results of a given client, forms tasks that can be run, saves it in database and waits for given client to fetch the result
@app.get("/tasks/{host_id}")
async def get_tasks(host_id: int):
    if host_id in tempStorage["clients"]:
        return {"status": "ok", "tasks": tempStorage.get("scans", {}).get(host_id, [])}
    else:
        return Response.error

# registers the client machine, returns a token for it, adds the machine to database
@app.post("/register")
async def register_client(client: Host):
    tempStorage["clients"][client.host_id] = client
    return client

# client sends scan results here
@app.post("/scan-results")
async def add_scan(scan: Issue):
    tempStorage["scans"][scan.host.host_id] = scan
    return scan

# client sends applied fixes results here
@app.post("/fix-results")
async def add_fix(fix: Issue):
    host_id = fix.host.host_id
    # You can merge fix results into previous scans or track separately
    tempStorage.setdefault("fixes", {})[host_id] = fix
    return {"status": "ok", "fix": fix}
