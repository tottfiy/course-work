import subprocess

def scan(ipaddress):
    report = ""
    nmap_stream = subprocess.run(
        ['nmap', '-p-', {ipaddress}], 
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    if nmap_stream.returncode != 0:
        print(f"Error: {nmap_stream.stderr.decode('utf-8')}")
    else:
        nmap_output = nmap_stream.stdout.decode('utf-8')
        print(nmap_output)