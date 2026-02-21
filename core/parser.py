from classes import Threat, Type

def parse_scan_line(line: str) -> Threat:
    line = line.lower()
    if "open" in line:  # exposed port
        parts = line.split()
        port = int(parts[0])
        service = parts[2] if len(parts) > 2 else None
        return Threat(
            type=Type.exposed_port,
            port=port,
            service=service,
            comment="Port is open",
            fix_available=True
        )
    elif "suid" in line:  # SUID file
        file_name = line.split()[1]
        return Threat(
            type=Type.suid_set,
            file_name=file_name,
            comment="SUID bit set",
            fix_available=True
        )
    elif "sudoers" in line:
        return Threat(
            type=Type.sudoers_abuse,
            comment="Suspicious sudoers entry",
            fix_available=True
        )
    else:
        return Threat(
            type=Type.unsecure_code,
            comment=line,
            fix_available=False
        )