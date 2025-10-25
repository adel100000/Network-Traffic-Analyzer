from fastapi import APIRouter, BackgroundTasks, HTTPException
from typing import List, Dict, Any
from datetime import datetime
from collections import deque
import threading
import asyncio
import logging

from sqlalchemy.orm import Session

from ..schemas import AlertOut
from ..models import Alert
from ..database import SessionLocal
from ..notifications import notify_all
from ..threat_intel import (
    check_ip_virustotal,
    check_ip_abuseipdb,
    geolocate_ip,
    lookup_isp,
    compute_threat_score,
)

router = APIRouter()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

alerts_deque = deque(maxlen=200)
capture_thread = None
stop_flag = False
deque_lock = threading.Lock()


def alert_model_to_dict(alert: Alert) -> Dict[str, Any]:
    """Convert ORM Alert model into serializable dict for frontend."""
    return {
        "id": alert.id,
        "type": alert.type,
        "details": alert.details or {},
        "created_at": alert.created_at.isoformat()
        if hasattr(alert.created_at, "isoformat")
        else str(alert.created_at),
        "resolved": bool(alert.resolved),
        "risk_score": alert.risk_score,
        "geo_info": alert.geo_info,
        "isp": alert.isp,
        "dns_queries": alert.dns_queries,
        "threat_score": alert.threat_score,
        "entropy_score": alert.entropy_score,
        "vt_report": alert.vt_report,
    }


def enrich_alert(src_ip: str, dst_ip: str, message: str, port: int | None = None) -> Dict[str, Any]:
    """Run full enrichment pipeline for a detected alert."""
    try:
        vt_stats = check_ip_virustotal(src_ip)
        abuse_score = check_ip_abuseipdb(src_ip)
        geo_info = geolocate_ip(src_ip)
        isp = lookup_isp(src_ip)
        threat_score = compute_threat_score(vt_stats, abuse_score)

        severity = (
            "high" if threat_score >= 7
            else "medium" if threat_score >= 4
            else "low"
        )

        alert_type = "Unusual Port" if port else "Suspicious Activity"

        geo_summary = (
            f"{geo_info.get('city', '-')}, "
            f"{geo_info.get('region', '-')}, "
            f"{geo_info.get('country', '-')}"
        ).strip(", ")

        return {
            "type": alert_type,
            "details": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "message": message,
                "severity": severity,
                "threat_score": threat_score,
                "geo": geo_summary,
                "isp": isp,
                "city": geo_info.get("city"),
                "region": geo_info.get("region"),
                "country": geo_info.get("country"),
                "timezone": geo_info.get("timezone"),
                "latitude": geo_info.get("latitude"),
                "longitude": geo_info.get("longitude"),
            },
            "resolved": False,
            "geo_info": geo_summary,
            "isp": isp,
            "threat_score": threat_score,
            "created_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.exception(f"Error enriching alert for {src_ip}: {e}")
        raise


def process_packet(pkt, db: Session):
    """Analyze packet and create alerts if suspicious activity is found."""
    from scapy.all import IP, TCP, UDP

    try:
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        port = None

        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport

        alert_type, message = None, None
        if port and port not in [80, 443, 22, 53]:
            alert_type, message = "Unusual Port", f"Connection to uncommon port {port}"
        elif port and port > 49152:
            alert_type, message = "Ephemeral Port Spike", f"Potential port scan on {port}"

        if not alert_type:
            return

        enriched = enrich_alert(src_ip, dst_ip, message, port)

        db_alert = Alert(
            type=enriched["type"],
            details=enriched["details"],
            created_at=datetime.utcnow(),
            resolved=False,
            threat_score=enriched["threat_score"],
            geo_info=enriched["geo_info"],
            isp=enriched["isp"],
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        serialized = alert_model_to_dict(db_alert)
        with deque_lock:
            alerts_deque.append(serialized)

        logger.info(f"Stored alert {db_alert.id} from {src_ip} ({message})")

        try:
            asyncio.run(notify_all(f"🚨 {enriched['type']} from {src_ip} — {message}"))
        except Exception as e:
            logger.warning(f"Notification send failed: {e}")

    except Exception as e:
        logger.exception(f"Error processing packet: {e}")


def live_capture_thread():
    """Live sniffing thread — captures and processes packets continuously."""
    from scapy.all import sniff

    global stop_flag
    stop_flag = False
    db = SessionLocal()
    logger.info("Live capture thread started")

    def pkt_callback(pkt):
        if stop_flag:
            return False
        process_packet(pkt, db)

    try:
        sniff(filter="ip", prn=pkt_callback, store=False)
    except Exception as e:
        logger.exception(f"Sniff error: {e}")
    finally:
        db.close()
        logger.info("Live capture stopped")


@router.post("/start")
def start_live_monitoring():
    global capture_thread, stop_flag
    if capture_thread and capture_thread.is_alive():
        return {"status": "already running"}

    stop_flag = False
    capture_thread = threading.Thread(target=live_capture_thread, daemon=True)
    capture_thread.start()
    logger.info("Started live monitoring")
    return {"status": "live monitoring started"}


@router.post("/stop")
def stop_live_monitoring():
    global stop_flag
    stop_flag = True
    logger.info("Stopped live monitoring")
    return {"status": "stopped"}


@router.post("/test", summary="Insert a test alert (dev only)")
def insert_test_alert():
    """Manually insert a synthetic test alert for frontend dev."""
    db = SessionLocal()
    try:
        created_at = datetime.utcnow()
        details = {
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "message": "Synthetic test alert",
            "severity": "high",
            "threat_score": 9,
            "geo": "Toronto, Ontario, Canada",
            "isp": "Test ISP",
        }

        db_alert = Alert(
            type="Synthetic Test Alert",
            details=details,
            created_at=created_at,
            resolved=False,
            threat_score=9,
            geo_info=details["geo"],
            isp=details["isp"],
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        serialized = alert_model_to_dict(db_alert)
        with deque_lock:
            alerts_deque.appendleft(serialized)

        logger.info(f"Inserted synthetic test alert id={db_alert.id}")
        return {"ok": True, "alert": serialized}

    except Exception as e:
        logger.exception("Failed to insert test alert")
        raise HTTPException(status_code=500, detail="Failed to insert test alert")
    finally:
        db.close()


@router.get("/", response_model=List[AlertOut])
def get_alerts():
    db = SessionLocal()
    try:
        persisted = db.query(Alert).order_by(Alert.created_at.desc()).limit(200).all()
        persisted_serialized = [alert_model_to_dict(a) for a in persisted]
    except Exception as e:
        logger.exception("DB read failed")
        persisted_serialized = []
    finally:
        db.close()

    with deque_lock:
        combined = persisted_serialized + list(alerts_deque)

    seen = set()
    result = []
    for a in combined:
        ident = a.get("id") or f"{a.get('created_at')}-{a.get('type')}-{a.get('details', {}).get('src_ip','')}"
        if ident in seen:
            continue
        seen.add(ident)
        result.append(a)

    result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return [AlertOut(**r) for r in result]
