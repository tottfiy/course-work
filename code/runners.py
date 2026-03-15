import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import shutil
import re
import threading
import xml.etree.ElementTree as ET
from .config import BASE_URL, HOSTPORT, TLS_HOSTPORT, SCAN_DIR
from .storage import run_dir, write_json


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR.parent / "tools"


try:
    import jc  
except Exception:
    jc = None  


@dataclass
class ToolResult:
    name: str
    cmd: List[str]
    rc: int
    duration_sec: float
    stdout_file: str
    stderr_file: str
    parsed_file: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


# ----------------------------
# Tool registry
# ----------------------------
# Notes:
# - Prefer JSON / machine-readable formats where supported.
# - For nmap we emit XML to stdout so we can parse via jc's XML parser.
# - For tools that require root (raw sockets, deep system checks), we fail fast with a clear error.
TOOLS: Dict[str, Dict[str, Any]] = {

    # ----------------------------
    # network scanning
    # ----------------------------
    "Nmap": {
        "cmd": ["nmap", "-sV", "-sC", "-p-", "127.0.0.1", "-oX", "-"],
        "timeout": 1800,
        "requires_root": False,
        "postprocess": {"type": "jc", "parser": "xml", "summarizer": "nmap_xml"},
        "human_hint": "Saved as XML for parsing. Use the Parsed view for highlights."
    },

    # ----------------------------
    # privilege escalation scripts (local tools folder)
    # ----------------------------
    "linpeas": {
        "cmd": ["stdbuf", "-oL", "-eL", "bash", str(TOOLS_DIR / "linpeas.sh"), "-a"],
        "timeout": 1800,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "linpeas_text"},
    },

    "LinEnum": {
        "cmd": ["bash", str(TOOLS_DIR / "LinEnum.sh")],
        "timeout": 1800,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "generic_text"},
    },

    # ----------------------------
    # fast port scanners
    # ----------------------------
    "MasScan": {
        "cmd": ["masscan", "127.0.0.1", "-p1-65535", "--rate", "1000"],
        "timeout": 600,
        "requires_root": True,
        "postprocess": {"type": "text", "summarizer": "masscan_text"},
    },


    # ----------------------------
    # web vulnerability scanners
    # ----------------------------
    "nikto": {
        "cmd": ["nikto", "-h", BASE_URL],
        "timeout": 3600
    },

    "dalfox": {
        "cmd": ["dalfox", "url", BASE_URL],
        "timeout": 1800,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "generic_text"},
    },

    "WPscan": {
        "cmd": ["bash", "-lc", f"wpscan --update >/dev/null 2>&1 || true; wpscan --url {BASE_URL} --format json"],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "json", "summarizer": "wpscan_json"},
    },
    # ----------------------------
    # secrets scanning
    # ----------------------------
    "Trufflehog": {
        "cmd": ["trufflehog", "filesystem", "."],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "generic_text"},
    },

    # ----------------------------
    # host security scanners
    # ----------------------------
    "Lynis": {
        "cmd": ["lynis", "audit", "system", "--pentest", "--quiet"],
        "timeout": 3600,
        "requires_root": True,
        "postprocess": {"type": "text", "summarizer": "lynis_text"},
        "human_hint": "Lynis is much more complete as root."
    },

    "Rkhunter": {
        "cmd": ["rkhunter", "--check", "--sk"],
        "timeout": 3600,
        "requires_root": True,
        "postprocess": {"type": "text", "summarizer": "rkhunter_text"},
        "human_hint": "rkhunter should be run as root."
    },

    "chkrootkit": {
        "cmd": ["chkrootkit"],
        "timeout": 1800,
        "requires_root": True,
        "postprocess": {"type": "text", "summarizer": "chkrootkit_text"},
    },

    "Clamav": {
        "cmd": ["clamscan", "-r", "-i", SCAN_DIR],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "clamav_text"},
    },

    # ----------------------------
    # code scanners (prefer machine-readable output)
    # ----------------------------
    "Bandit": {
        "cmd": ["bandit", "-r", SCAN_DIR, "-f", "json"],
        "timeout": 1800,
        "requires_root": False,
        "postprocess": {"type": "json", "summarizer": "bandit_json"},
    },

    "Semgrep": {
        "cmd": ["semgrep", "--config", "auto", "--json", SCAN_DIR],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "json", "summarizer": "semgrep_json"},
    },

    "Trivy": {
        "cmd": ["trivy", "fs", SCAN_DIR, "--format", "json"],
        "timeout": 7200,
        "requires_root": False,
        "postprocess": {"type": "json", "summarizer": "trivy_json"},
    },

    "Nuclei": {
        "cmd": [
            "nuclei",
            "-u", BASE_URL,
            "-severity", "critical,high",
            "-tags", "cve,exposure,misconfig,default-login",
            "-exclude-tags", "dos",
            "-jsonl",
        ],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "jsonl", "summarizer": "nuclei_jsonl"},
    },

    "WhatWeb": {
        "cmd": ["whatweb", "-a", "3", BASE_URL],
        "timeout": 600,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "whatweb_text"},
    },

    "TestSSL": {
        "cmd": ["testssl.sh", TLS_HOSTPORT],
        "timeout": 3600,
        "requires_root": False,
        "postprocess": {"type": "text", "summarizer": "generic_text"},
    }
}


# ----------------------------
# tool availability
# ----------------------------
def tool_available(cmd: List[str]) -> Tuple[bool, str]:
    if not cmd:
        return False, "empty command"

    exe = cmd[0]


    if exe == "bash":
        if len(cmd) >= 2 and cmd[1] in ("-lc", "-c"):
            if shutil.which("bash") is None:
                return False, "bash not installed"
            return True, "available"

        if len(cmd) >= 2:
            script = Path(cmd[1])
            if not script.exists():
                return False, f"{cmd[1]} not found"
            return True, "available"

        return False, "invalid bash command"


    if shutil.which(exe) is None:
        return False, f"{exe} not installed"

    return True, "available"


def available_tools_config() -> Dict[str, Tuple[bool, str]]:
    result: Dict[str, Tuple[bool, str]] = {}
    for name, tool in TOOLS.items():
        ok, reason = tool_available(tool["cmd"])
       
        if ok and tool.get("requires_root") and not _is_root():
            ok, reason = True, "requires sudo/root"
        result[name] = (ok, reason)
    return result


# ----------------------------
# postprocessing + summaries
# ----------------------------
def _safe_write_json(path: Path, data: Any) -> None:
    try:
        path.write_text(json_dumps(data), encoding="utf-8")
    except Exception:
        pass


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False)


def _summarize(name: str, raw_stdout: str, parsed: Any) -> Optional[Dict[str, Any]]:
    try:
        if name == "Nmap":
            return summarize_nmap(parsed)
        if name == "ZMap":
            return summarize_zmap(parsed)
        if name == "Nuclei":
            return summarize_nuclei_jsonl(raw_stdout)
        if name == "Bandit":
            return summarize_bandit(parsed)
        if name == "Semgrep":
            return summarize_semgrep(parsed)
        if name == "Trivy":
            return summarize_trivy(parsed)
        if name == "WPscan":
            return summarize_wpscan(parsed)
        if name == "WhatWeb":
            return summarize_whatweb(raw_stdout)
        if name == "Lynis":
            return summarize_lynis(raw_stdout)
        if name == "Rkhunter":
            return summarize_rkhunter(raw_stdout)
        if name == "chkrootkit":
            return summarize_chkrootkit(raw_stdout)
        if name == "MasScan":
            return summarize_masscan(raw_stdout)
        if name == "Clamav":
            return summarize_clamav(raw_stdout)
        if name == "linpeas":
            return summarize_linpeas(raw_stdout)
        return summarize_generic_text(raw_stdout)
    except Exception:
        return None


def summarize_generic_text(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    return {"highlights": lines[:15], "lines": len(lines)}


def summarize_masscan(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    open_lines = [ln for ln in lines if "open" in ln.lower()]
    return {"open_lines": open_lines[:20], "open_count": len(open_lines), "lines": len(lines)}


def summarize_whatweb(s: str) -> Dict[str, Any]:
    
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    return {"detections": lines[:5], "lines": len(lines)}


def summarize_lynis(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    warn = [ln for ln in lines if ln.startswith("Warning:") or "warning" in ln.lower()]
    sugg = [ln for ln in lines if ln.startswith("Suggestion:") or "suggestion" in ln.lower()]
    score = None
    for ln in lines:
        if "Hardening index" in ln:
            score = ln
            break
    return {"hardening": score, "warnings": warn[:10], "suggestions": sugg[:10]}


def summarize_rkhunter(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    warn = [ln for ln in lines if "Warning:" in ln or "warning" in ln.lower()]
    return {"warnings": warn[:15], "lines": len(lines)}


def summarize_chkrootkit(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    infected = [ln for ln in lines if "INFECTED" in ln or "infected" in ln.lower()]
    return {"infected": infected[:20], "infected_count": len(infected)}


def summarize_clamav(s: str) -> Dict[str, Any]:
    
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    tail = lines[-30:] if len(lines) > 30 else lines
    interesting = [ln for ln in tail if ":" in ln]
    return {"summary": interesting[-12:]}


def summarize_linpeas(s: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in strip_ansi(s).splitlines() if ln.strip()]
    hot = [ln for ln in lines if "CVE" in ln or "VULN" in ln or "SUID" in ln or "sudo" in ln.lower()]
    return {"highlights": hot[:20], "lines": len(lines)}


def summarize_bandit(obj: Any) -> Dict[str, Any]:
    import json
    if isinstance(obj, str):
        obj = json.loads(obj)
    results = obj.get("results", []) if isinstance(obj, dict) else []
    sev_counts: Dict[str, int] = {}
    for r in results:
        sev = (r.get("issue_severity") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    return {"issues": len(results), "severity": sev_counts}


def summarize_semgrep(obj: Any) -> Dict[str, Any]:
    
    results = obj.get("results", []) if isinstance(obj, dict) else []
    by_sev: Dict[str, int] = {}
    for r in results:
        sev = ((r.get("extra", {}).get("severity")) or "INFO").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return {"findings": len(results), "severity": by_sev, "errors": len(obj.get("errors", []) if isinstance(obj, dict) else [])}


def summarize_trivy(obj: Any) -> Dict[str, Any]:
    
    results = obj.get("Results", []) if isinstance(obj, dict) else []
    by_sev: Dict[str, int] = {}
    total = 0
    for r in results:
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            total += 1
            sev = (v.get("Severity") or "UNKNOWN").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
    return {"vulns": total, "severity": by_sev, "targets": len(results)}


def summarize_wpscan(obj: Any) -> Dict[str, Any]:
    
    if not isinstance(obj, dict):
        return {"note": "wpscan output not parsed"}
    version = obj.get("version") or obj.get("wp_scan_version") or None
    vulns = 0
    interesting = []
    
    for k in ("vulnerabilities", "interesting_findings", "plugins", "themes"):
        if k in obj:
            interesting.append(k)
    
    def count_vuln(x: Any) -> int:
        if isinstance(x, list):
            return len(x)
        if isinstance(x, dict) and "vulnerabilities" in x and isinstance(x["vulnerabilities"], list):
            return len(x["vulnerabilities"])
        return 0
    vulns += count_vuln(obj.get("vulnerabilities"))
    return {"version": version, "top_keys": interesting[:8], "vulns": vulns}


def summarize_nuclei_jsonl(raw: str) -> Dict[str, Any]:
    import json
    by_sev: Dict[str, int] = {}
    total = 0
    samples: List[str] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        total += 1
        sev = (j.get("severity") or "unknown").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if len(samples) < 10:
            tmpl = j.get("template-id") or j.get("template") or j.get("templateID") or ""
            name = j.get("info", {}).get("name") if isinstance(j.get("info"), dict) else None
            host = j.get("host") or j.get("matched-at") or ""
            samples.append(f"{sev}: {name or tmpl} @ {host}".strip())
    return {"findings": total, "severity": by_sev, "samples": samples}


def summarize_zmap(obj: Any) -> Dict[str, Any]:
    
    if isinstance(obj, dict):
        ips = obj.get("ips") or []
        if isinstance(ips, list):
            return {"responses": int(obj.get("responses") or len(ips)), "sample": ips[:10]}
        return {"responses": int(obj.get("responses") or 0), "sample": []}

    if not isinstance(obj, list):
        return {"responses": 0}

    ips = []
    for row in obj:
        if isinstance(row, dict):
            ips.append(row.get("saddr") or row.get("0") or "")
    ips = [x for x in ips if x]
    return {"responses": len(ips), "sample": ips[:10]}


def summarize_nmap(parsed_xml: Any) -> Dict[str, Any]:
   
    if isinstance(parsed_xml, dict) and "open_ports" in parsed_xml and "open_count" in parsed_xml:
        open_ports = parsed_xml.get("open_ports") or []
        if isinstance(open_ports, list):
            pretty = []
            for p in open_ports[:50]:
                if not isinstance(p, dict):
                    continue
                portid = p.get("portid")
                proto = p.get("proto")
                svc = p.get("service") if isinstance(p.get("service"), dict) else {}
                name = svc.get("name") or ""
                product = svc.get("product") or ""
                version = svc.get("version") or ""
                extra = " ".join([x for x in [name, product, version] if x])
                pretty.append(f"{portid}/{proto} {extra}".strip())
            return {"open_ports": pretty[:30], "open_count": int(parsed_xml.get("open_count") or len(open_ports))}
        return {"open_ports": [], "open_count": int(parsed_xml.get("open_count") or 0)}


    if not isinstance(parsed_xml, dict):
        return {"open_ports": []}
    nmaprun = parsed_xml.get("nmaprun") if "nmaprun" in parsed_xml else parsed_xml
    hosts = nmaprun.get("host") if isinstance(nmaprun, dict) else None
    if hosts is None:
        return {"open_ports": []}
    if isinstance(hosts, dict):
        hosts = [hosts]
    open_ports = []
    for host in hosts:
        ports = (((host or {}).get("ports") or {}).get("port")) if isinstance(host, dict) else None
        if ports is None:
            continue
        if isinstance(ports, dict):
            ports = [ports]
        for p in ports:
            if not isinstance(p, dict):
                continue
            state = ((p.get("state") or {}).get("state")) if isinstance(p.get("state"), dict) else None
            if state != "open":
                continue
            portid = p.get("portid")
            proto = p.get("protocol")
            svc = p.get("service") if isinstance(p.get("service"), dict) else {}
            name = svc.get("name")
            product = svc.get("product")
            version = svc.get("version")
            extra = " ".join([x for x in [name, product, version] if x])
            open_ports.append(f"{portid}/{proto} {extra}".strip())
    return {"open_ports": open_ports[:30], "open_count": len(open_ports)}


def parse_nmap_xml(raw_xml: str) -> Optional[Dict[str, Any]]:
    """Parse nmap -oX output (XML) and return a compact structured dict."""
    raw_xml = (raw_xml or "").strip()
    if not raw_xml:
        return None
    
    if "<?xml" in raw_xml:
        raw_xml = raw_xml[raw_xml.index("<?xml"):]
    try:
        root = ET.fromstring(raw_xml)
    except Exception:
        return None

    if root.tag != "nmaprun":
        nmaprun = root.find(".//nmaprun")
        if nmaprun is None:
            return None
        root = nmaprun

    hosts_out: List[Dict[str, Any]] = []
    open_ports_out: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        status = host.find("status")
        state = status.get("state") if status is not None else None

        host_entry: Dict[str, Any] = {"addr": addr, "state": state, "ports": []}

        for port in host.findall("./ports/port"):
            proto = port.get("protocol") or ""
            portid = port.get("portid") or ""
            st_el = port.find("state")
            st = st_el.get("state") if st_el is not None else "unknown"
            svc_el = port.find("service")
            svc = {
                "name": svc_el.get("name") if svc_el is not None else "",
                "product": svc_el.get("product") if svc_el is not None else "",
                "version": svc_el.get("version") if svc_el is not None else "",
                "extrainfo": svc_el.get("extrainfo") if svc_el is not None else "",
                "tunnel": svc_el.get("tunnel") if svc_el is not None else "",
            }

            scripts = []
            for s in port.findall("script"):
                scripts.append({
                    "id": s.get("id") or "",
                    "output": s.get("output") or "",
                })

            p_entry = {
                "proto": proto,
                "portid": portid,
                "state": st,
                "service": svc,
                "scripts": scripts,
            }

            host_entry["ports"].append(p_entry)
            if st == "open":
                open_ports_out.append({
                    "addr": addr,
                    "portid": portid,
                    "proto": proto,
                    "service": svc,
                    "scripts": scripts,
                })

        hosts_out.append(host_entry)

    return {
        "hosts": hosts_out,
        "open_ports": open_ports_out,
        "open_count": len(open_ports_out),
    }


def parse_csv_single_col(raw: str) -> List[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    out: List[str] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        out.append(ln.split(",")[0].strip())
    return [x for x in out if x]


# ----------------------------
# tool runner
# ----------------------------
def _parse_with_jc(parser: str, raw_stdout: str) -> Optional[Any]:
    if jc is None:
        return None
    try:
        return jc.parse(parser, raw_stdout)
    except Exception:
        return None


def run_tool(name: str, tool: Dict[str, Any], out_dir: Path) -> ToolResult:
    cmd: List[str] = tool["cmd"]
    timeout: int = int(tool.get("timeout", 1800))
    requires_root: bool = bool(tool.get("requires_root", False))

    tool_dir = out_dir / name
    tool_dir.mkdir(parents=True, exist_ok=True)

    stdout_file = tool_dir / "stdout.log"
    stderr_file = tool_dir / "stderr.log"

    start = time.time()
    raw_out = ""
    raw_err = ""
    rc = 0
    parsed_file_rel: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None

    effective_cmd = cmd
    used_sudo = False
    if requires_root and not _is_root():
        if shutil.which("sudo"):
            effective_cmd = ["sudo", "-n"] + cmd
            used_sudo = True
        else:
            raw_err = "Tool requires root but sudo is not available.\n"
            rc = 2
            stdout_file.write_text("", encoding="utf-8")
            stderr_file.write_text(raw_err, encoding="utf-8")
            duration = time.time() - start
            return ToolResult(
                name=name,
                cmd=cmd,
                rc=rc,
                duration_sec=duration,
                stdout_file=str(stdout_file.relative_to(out_dir)),
                stderr_file=str(stderr_file.relative_to(out_dir)),
                parsed_file=None,
                summary={"error": "requires root"}
            )

    with stdout_file.open("w", encoding="utf-8") as out, stderr_file.open("w", encoding="utf-8") as err:
        try:
            p = subprocess.run(
                effective_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                errors="replace",
            )
            rc = p.returncode
            raw_out = strip_ansi(p.stdout)
            raw_err = strip_ansi(p.stderr)

            out.write(raw_out)
            err.write(raw_err)

        except subprocess.TimeoutExpired as e:
            rc = 124
            raw_out = strip_ansi((e.stdout or ""))
            raw_err = "Timeout\n" + strip_ansi((e.stderr or ""))
            out.write(raw_out)
            err.write(raw_err)

        except Exception as e:
            rc = 1
            raw_err = str(e)
            err.write(raw_err)


    pp = tool.get("postprocess") or {}
    parsed_obj: Any = None

    if name == "Nmap":
        parsed_obj = parse_nmap_xml(raw_out)
    elif name == "ZMap":
        ips = parse_csv_single_col(raw_out)
        parsed_obj = {"responses": len(ips), "ips": ips[:200]}

   
    if parsed_obj is None and pp.get("type") == "jc":
        parser = pp.get("parser")
        if isinstance(parser, str):
            parsed_obj = _parse_with_jc(parser, raw_out)
    elif pp.get("type") == "json":
        import json
        try:
            parsed_obj = json.loads(raw_out) if raw_out.strip() else None
        except Exception:
            parsed_obj = None
    elif pp.get("type") == "jsonl":

        parsed_obj = None

    if parsed_obj is not None:
        parsed_path = tool_dir / "parsed.json"
        _safe_write_json(parsed_path, parsed_obj)
        parsed_file_rel = str(parsed_path.relative_to(out_dir))

    summary = _summarize(name, raw_out, parsed_obj)
    if used_sudo and summary is not None:
        summary.setdefault("note", "executed via sudo")

    duration = time.time() - start

    return ToolResult(
        name=name,
        cmd=cmd,
        rc=rc,
        duration_sec=duration,
        stdout_file=str(stdout_file.relative_to(out_dir)),
        stderr_file=str(stderr_file.relative_to(out_dir)),
        parsed_file=parsed_file_rel,
        summary=summary
    )


# ----------------------------
# scan execution
# ----------------------------
def run_scan(run_id: str, tools: List[str]) -> Dict[str, Any]:
    out_dir = run_dir(run_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta_lock = threading.Lock()

    meta: Dict[str, Any] = {
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "tools_requested": tools,
        "tools": []
    }

    write_json(out_dir / "meta.json", meta)

    def update_meta(tool_entry: Dict[str, Any]) -> None:
        with meta_lock:
            meta["tools"].append(tool_entry)
            write_json(out_dir / "meta.json", meta)

    def worker(name: str) -> None:
        if name not in TOOLS:
            update_meta({"name": name, "error": "unknown tool"})
            return

        tool = TOOLS[name]

        ok, reason = tool_available(tool["cmd"])
        if not ok:
            update_meta({"name": name, "error": reason})
            return

        tr = run_tool(name, tool, out_dir)

        entry: Dict[str, Any] = {
            "name": tr.name,
            "cmd": " ".join(shlex.quote(x) for x in tr.cmd),
            "rc": tr.rc,
            "duration_sec": round(tr.duration_sec, 2),
            "stdout_file": tr.stdout_file,
            "stderr_file": tr.stderr_file
        }
        if tr.parsed_file:
            entry["parsed_file"] = tr.parsed_file
        if tr.summary:
            entry["summary"] = tr.summary

        update_meta(entry)

    threads: List[threading.Thread] = []
    for name in tools:
        t = threading.Thread(target=worker, args=(name,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    meta["status"] = "done"
    meta["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    write_json(out_dir / "meta.json", meta)

    return meta
