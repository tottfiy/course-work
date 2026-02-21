import requests
CORE_SERVER = "http://127.0.0.1:8000"

# sends request to core, obtains token
def register(url: str, data: dict) -> str:
    request = requests.post(url, json=data)
    response = str(request.text )
    return response