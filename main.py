import json
import ipaddress
import logging
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader

from config import settings
from ssh_pool import ssh_pool

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("gateway.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("gateway")

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Gateway API",
    description="Smart Home Network Security Device — pfSense + Suricata backend",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ───────────────────────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def require_api_key(key: str = Depends(api_key_header)):
    if key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return key

# ── Helpers ────────────────────────────────────────────────────────────────────
def validate_ip(ip: str) -> str:
    """Raise 400 if ip is not a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IPv4 address")

def run(command: str) -> str:
    """Run SSH command and return stdout. Raises 503 on SSH failure."""
    try:
        out, err = ssh_pool.execute(command)
        if err:
            logger.debug(f"SSH stderr: {err.strip()}")
        return out
    except Exception as e:
        logger.error(f"SSH error: {e}")
        raise HTTPException(status_code=503, detail=f"Cannot reach pfSense: {e}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def home():
    return {
        "status": "Security Gateway Running",
        "version": "2.0.0",
        "time": datetime.now().isoformat(),
    }


@app.get("/status", tags=["Firewall"], dependencies=[Depends(require_api_key)])
def get_status():
    """pfSense firewall status and uptime."""
    raw = run("pfctl -si")
    uptime = run("uptime")
    return {
        "firewall_status": raw.strip(),
        "uptime": uptime.strip(),
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/devices", tags=["Network"], dependencies=[Depends(require_api_key)])
def get_devices():
    """
    All devices currently visible in the ARP table.
    Tries to resolve a friendly hostname via reverse-DNS.
    """
    output = run("arp -a")
    devices = []
    for line in output.splitlines():
        parts = line.split()
        # arp -a line: hostname (ip) at mac on iface
        if len(parts) < 4:
            continue
        ip = parts[1].strip("()")
        mac = parts[3]
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            continue
        if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
            continue
        hostname = parts[0] if parts[0] != "?" else None
        devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    logger.info(f"/devices → {len(devices)} devices found")
    return {"count": len(devices), "devices": devices}


@app.get("/blocked-ips", tags=["Firewall"], dependencies=[Depends(require_api_key)])
def get_blocked_ips():
    """List all IPs currently in the pfctl blocklist table."""
    output = run("pfctl -t blocklist -T show")
    ips = [line.strip() for line in output.splitlines() if line.strip()]
    logger.info(f"/blocked-ips → {len(ips)} entries")
    return {"count": len(ips), "blocked_ips": ips}


@app.get("/alerts", tags=["IDS/IPS"], dependencies=[Depends(require_api_key)])
def get_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Number of recent alerts"),
    severity: Optional[int] = Query(default=None, ge=1, le=4, description="Filter by severity 1–4 (1=critical)"),
    src_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
):
    """
    Fetch Suricata alerts from eve.json.
    - limit: how many recent events to scan (default 50, max 500)
    - severity: 1=critical, 2=high, 3=medium, 4=low
    - src_ip: filter by attacker IP
    """
    ##output = run(f"tail -{limit * 3} /var/log/suricata/eve.json")
    output = run(f"tail -{limit * 3} /var/log/suricata/eve.json 2>/dev/null")
    alerts = []

    for line in output.splitlines():
        try:
            log = json.loads(line)
        except json.JSONDecodeError:
            continue

        if log.get("event_type") != "alert":
            continue

        alert_block = log.get("alert", {})
        sev = alert_block.get("severity")
        s_ip = log.get("src_ip")

        if severity is not None and sev != severity:
            continue
        if src_ip is not None and s_ip != src_ip:
            continue

        # Map numeric severity → label
        sev_label = {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(sev, "unknown")

        alerts.append({
            "time": log.get("timestamp"),
            "src_ip": s_ip,
            "src_port": log.get("src_port"),
            "dest_ip": log.get("dest_ip"),
            "dest_port": log.get("dest_port"),
            "proto": log.get("proto"),
            "signature": alert_block.get("signature"),
            "category": alert_block.get("category"),
            "severity": sev,
            "severity_label": sev_label,
        })

    # Return newest first
    alerts.reverse()
    logger.info(f"/alerts → {len(alerts)} alerts returned (limit={limit}, severity={severity})")
    return {"count": len(alerts), "alerts": alerts}


@app.get("/stats", tags=["Dashboard"], dependencies=[Depends(require_api_key)])
def get_stats():
    """
    Summary stats for the mobile app dashboard:
    total devices, total alerts, blocked IPs, alerts by severity.
    """
    # Run all queries in parallel would be nicer but keep it simple for now
    devices_out = run("arp -a")
    blocked_out = run("pfctl -t blocklist -T show")
    alerts_out  = run("tail -1000 /var/log/suricata/eve.json")

    device_count  = sum(1 for l in devices_out.splitlines() if len(l.split()) >= 4)
    blocked_count = len([l for l in blocked_out.splitlines() if l.strip()])

    severity_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    alert_count = 0
    for line in alerts_out.splitlines():
        try:
            log = json.loads(line)
            if log.get("event_type") == "alert":
                alert_count += 1
                sev = log.get("alert", {}).get("severity")
                if sev in severity_counts:
                    severity_counts[sev] += 1
        except Exception:
            continue

    logger.info(f"/stats → devices={device_count}, alerts={alert_count}, blocked={blocked_count}")
    return {
        "timestamp": datetime.now().isoformat(),
        "devices_online": device_count,
        "blocked_ips": blocked_count,
        "alerts": {
            "total": alert_count,
            "critical": severity_counts[1],
            "high":     severity_counts[2],
            "medium":   severity_counts[3],
            "low":      severity_counts[4],
        },
    }


@app.post("/block-ip/{ip}", tags=["Firewall"], dependencies=[Depends(require_api_key)])
def block_ip(ip: str):
    """Block an IP via pfctl blocklist. Validates IPv4 format first."""
    validate_ip(ip)
    run(f"pfctl -t blocklist -T add {ip}")
    logger.warning(f"BLOCKED {ip}")
    return {"status": "blocked", "ip": ip, "timestamp": datetime.now().isoformat()}


@app.post("/unblock-ip/{ip}", tags=["Firewall"], dependencies=[Depends(require_api_key)])
def unblock_ip(ip: str):
    """Remove an IP from the pfctl blocklist."""
    validate_ip(ip)
    run(f"pfctl -t blocklist -T delete {ip}")
    logger.warning(f"UNBLOCKED {ip}")
    return {"status": "unblocked", "ip": ip, "timestamp": datetime.now().isoformat()}


# ── Shutdown ───────────────────────────────────────────────────────────────────
@app.on_event("shutdown")
def shutdown():
    ssh_pool.close()
    logger.info("SSH pool closed — app shutdown")
