from typing import List
import requests
import time
import threading
from main import URL

INTERVAL = 30

# sends request to core, obtains token
def register(url: str, data: dict) -> str:
    request = requests.post(url, json=data)
    response = str(request.text )
    return response

def send_scan(data: List[str], token: str):
    r = requests.post(
        url=URL+'/scan-results',
        data=data,
        headers={"Authorization": token}
    )

def check_for_tasks(token: str):
    r = requests.get(
        url=URL,
        headers={"Authorization": token}
    )

    if r.status_code == 200:
        print("Tasks:", r.json())


def task_listener(token: str):
    while True:
        check_for_tasks(token)
        time.sleep(INTERVAL)

def start_listener(token: str):
    t = threading.Thread(
        target=task_listener,
        args=(token,),
        daemon=True
    )
    t.start()

