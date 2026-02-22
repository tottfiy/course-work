import scans
from client.helpers import register, send_scan, start_listener

URL = "http://127.0.0.1:8000"


def main():
    host = scans.fetch_host()
    output = scans.run_nmap("127.0.0.1")
    token = register(URL+"/register", host).strip('"')
    send_scan(output, token)
    start_listener(token)

    if not output or not host:
        return

    print(host)
    print(output)
    print(token)


if __name__ == "__main__":
    main()