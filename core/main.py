from fastapi import FastAPI
import classes
import uuid

tempStorage = {
    "clients": {},
    "scans": {},
    "tasks": {},
    "fixes": {}
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
        return classes.Response.error

# registers the client machine, returns a token for it, adds the machine to database
@app.post("/register")
async def register_client(client: classes.Host):
    host_id = str(uuid.uuid4())
    token = str(uuid.uuid4())
    print(client)
    tempStorage["clients"][host_id] = {
        "client": client,
        "token": token
    }
    print(tempStorage)
    return token

# client sends scan results here
@app.post("/scan-results")
async def add_scan(scan: classes.Issue):
    tempStorage["scans"][scan.host.host_id] = scan
    return scan

# client sends applied fixes results here
@app.post("/fix-results")
async def add_fix(fix: classes.Issue):
    host_id = fix.host.host_id
    tempStorage.setdefault("fixes", {})[host_id] = fix
    return {"status": "ok", "fix": fix}
