from fastapi import APIRouter, UploadFile, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime
import os
import pyshark
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
from sqlalchemy.orm import Session

from ..schemas import PacketOut, AlertOut
from ..database import get_db
from ..models import Alert
from ..threat_intel import (
    check_ip_virustotal,
    check_ip_abuseipdb,
    geolocate_ip,
    lookup_isp,
    compute_threat_score,
)

router = APIRouter()
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def pyshark_pkt_to_model(pkt) -> PacketOut:
    src = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else None
    dst = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None
    proto, sport, dport, dns, payload_sample = None, None, None, None, None

    if hasattr(pkt, "ip"):
        proto_num = int(pkt.ip.proto)
        proto = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else str(proto_num)

    if hasattr(pkt, "tcp"):
        sport = int(pkt.tcp.srcport)
        dport = int(pkt.tcp.dstport)
    elif hasattr(pkt, "udp"):
        sport = int(pkt.udp.srcport)
        dport = int(pkt.udp.dstport)

    if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
        dns = str(pkt.dns.qry_name)

    if hasattr(pkt, "data"):
        try:
            payload_sample = bytes.fromhex(pkt.data.data.replace(":", "")).hex()[:50]
        except Exception:
            payload_sample = None

    ts = datetime.fromtimestamp(float(pkt.sniff_timestamp)) if hasattr(pkt, "sniff_timestamp") else datetime.utcnow()

    return PacketOut(
        id=0,
        timestamp=ts,
        src=src,
        dst=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        length=int(pkt.length) if hasattr(pkt, "length") else 0,
        dns=dns,
        payload_sample=payload_sample
    )


@router.post("/upload", response_model=List[PacketOut])
async def upload_pcap(
    file: UploadFile,
    db: Session = Depends(get_db),
    src_filter: Optional[str] = Query(None),
    dst_filter: Optional[str] = Query(None),
    proto_filter: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None)
):
    try:
        file_location = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_location, "wb") as f:
            f.write(await file.read())

        cap = pyshark.FileCapture(file_location, keep_packets=False)
        packets: List[PacketOut] = []

        for i, pkt in enumerate(cap):
            pkt_model = pyshark_pkt_to_model(pkt)

            if src_filter and pkt_model.src != src_filter:
                continue
            if dst_filter and pkt_model.dst != dst_filter:
                continue
            if proto_filter and pkt_model.proto != proto_filter:
                continue
            if start_time and pkt_model.timestamp < start_time:
                continue
            if end_time and pkt_model.timestamp > end_time:
                continue

            packets.append(pkt_model)

            # Alerts (optional)
            alert_type = None
            message = None
            port = pkt_model.dport
            if port and port not in [80, 443, 22, 53]:
                alert_type = "Unusual Port"
                message = f"Connection to uncommon port {port}"

            if pkt_model.dns and (len(pkt_model.dns) > 40 or any(c.isdigit() for c in pkt_model.dns[:10])):
                alert_type = "Suspicious DNS Query"
                message = f"Suspicious domain query: {pkt_model.dns}"

            if alert_type and pkt_model.src:
                vt_stats = check_ip_virustotal(pkt_model.src)
                abuse_score = check_ip_abuseipdb(pkt_model.src)
                geo_info = geolocate_ip(pkt_model.src)
                isp = lookup_isp(pkt_model.src)
                threat_score = compute_threat_score(vt_stats, abuse_score)

                db_alert = Alert(
                    type=alert_type,
                    details={
                        "src_ip": pkt_model.src,
                        "dst_ip": pkt_model.dst,
                        "message": message,
                        "severity": "high" if threat_score >= 7 else "medium" if threat_score >= 4 else "low",
                        "threat_score": threat_score,
                        "geo": geo_info,
                        "isp": isp
                    },
                    created_at=datetime.utcnow(),
                    resolved=False,
                    threat_score=threat_score,
                    geo_info=str(geo_info),
                    isp=isp
                )
                db.add(db_alert)

            if i >= 200:
                break

        db.commit()
        cap.close()
        return packets

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process PCAP: {str(e)}")


@router.get("/alerts", response_model=List[AlertOut])
async def get_alerts_from_db(db: Session = Depends(get_db)):
    try:
        persisted = db.query(Alert).order_by(Alert.created_at.desc()).limit(50).all()
        return [
            AlertOut(
                created_at=a.created_at,
                type=a.type,
                details=a.details,
                resolved=a.resolved
            ) for a in persisted
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts from DB: {str(e)}")


@router.get("/summary")
def get_replay_summary() -> Dict[str, Any]:
    try:
        packets = sniff(count=100, filter="ip", timeout=5)
        talker_counts = Counter()
        proto_counts = Counter()

        for pkt in packets:
            if IP in pkt:
                talker_counts[pkt[IP].src] += 1
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(pkt[IP].proto)
                proto_counts[proto] += 1

        top_talkers = talker_counts.most_common(10)
        top_protocols = proto_counts.most_common(10)

        return {
            "top_talkers": [[ip, count] for ip, count in top_talkers],
            "top_protocols": [[proto, count] for proto, count in top_protocols],
        }

    except Exception as e:
        print("get_replay_summary error:", e)
        return {"top_talkers": [], "top_protocols": []}
