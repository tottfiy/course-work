import scans
import register

CORE_SERVER = "http://127.0.0.1:8000"


def main():
    host = scans.fetch_host()
    output = scans.run_nmap("127.0.0.1")
    token = register(CORE_SERVER, host)

    if not output or not host:
        return

    print(host)
    print(output)
    print(token)


if __name__ == "__main__":
    main()