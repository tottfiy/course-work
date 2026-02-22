from fastapi import FastAPI, HTTPException, Header
from classes import Host, RawData, TaskList, ThreatList
import uuid
from parser import parse_scan_line
from helpers import authenticate, task_manager, tempStorage

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

# fetches scan results of a given client, forms tasks that can be run, saves it in database and waits for given client to fetch the result
@app.get("/tasks")
async def get_tasks(authorization: str = Header(...)):
    host_id = authenticate(authorization)
    if host_id in tempStorage["clients"]:
        task_list = TaskList()
        for threat in tempStorage["scans"][host_id]:
            print(threat)
            task = task_manager(threat)
            task_list.tasks.append(task)

        return task_list
    else:
        raise HTTPException(status_code=404, detail="Not found")

# registers the client machine, returns a token for it, adds the machine to database
@app.post("/register")
async def register_client(client: Host):
    host_id = str(uuid.uuid4())
    token = str(uuid.uuid4())
    tempStorage["clients"][host_id] = {
        "client": client,
        "token": token
    }
    tempStorage["scans"][host_id] = []
    tempStorage["fixes"][host_id] = []
    tempStorage["tasks"][host_id] = []
    return token, host_id

# client sends scan results here
@app.post("/scan-results")
async def add_scan(raw: RawData, authorization: str = Header(...)):
    host_id = authenticate(authorization)
    for line in raw.data:
        threat = parse_scan_line(line)
        tempStorage["scans"][host_id].append(threat)
    return {"detail": "Success"}

# client sends applied fixes results here
@app.post("/fix-results")
async def add_fix(data: RawData, authorization: str = Header(...)):
    host_id = authenticate(authorization)
    
    tempStorage["fixes"][host_id].append(data)
    return {"detail": "Success"}




