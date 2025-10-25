from fastapi import APIRouter
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from typing import List
import pyshark
import os
from collections import deque, Counter
from threading import Thread, Lock
from ..schemas import PacketOut

router = APIRouter()

# ------------------------------
# Rolling buffer for live packets
# ------------------------------
BUFFER_SIZE = 500
packet_buffer = deque(maxlen=BUFFER_SIZE)
buffer_lock = Lock()

def packet_to_model(pkt) -> PacketOut:
    proto = None
    if IP in pkt:
        proto_num = pkt[IP].proto
        proto = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else str(proto_num)

    sport = None
    dport = None
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    return PacketOut(
        id=0,
        timestamp=datetime.utcnow(),
        src=pkt[IP].src if IP in pkt else None,
        dst=pkt[IP].dst if IP in pkt else None,
        proto=proto,
        sport=sport,
        dport=dport,
        src_port=sport,
        dst_port=dport,
        length=len(pkt),
        dns=None,
        payload_sample=None,
        anomaly=False,
        port_scan=False,
        traffic_burst=False,
        payload_entropy=None,
        threat_score=0,
        critical=False,
    )

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

    ts = datetime.fromtimestamp(float(pkt.sniff_timestamp)) if hasattr(pkt, "sniff_timestamp") else datetime.utcnow()

    return PacketOut(
        id=0,
        timestamp=ts,
        src=src,
        dst=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        src_port=sport,
        dst_port=dport,
        length=int(pkt.length) if hasattr(pkt, "length") else 0,
        dns=dns,
        payload_sample=payload_sample,
        anomaly=False,
        port_scan=False,
        traffic_burst=False,
        payload_entropy=None,
        threat_score=0,
        critical=False,
    )

# ------------------------------
# Background sniff thread
# ------------------------------
def packet_callback(pkt):
    model = packet_to_model(pkt)
    with buffer_lock:
        packet_buffer.append(model)

def start_sniff():
    sniff(prn=packet_callback, filter="ip", store=False)

sniff_thread = Thread(target=start_sniff, daemon=True)
sniff_thread.start()

# ------------------------------
# Routes
# ------------------------------
@router.get("/live", response_model=List[PacketOut])
def get_live_packets() -> List[PacketOut]:
    with buffer_lock:
        # Return the latest 20 packets from buffer
        return list(packet_buffer)[-20:]

@router.get("/summary")
def get_summary():
    with buffer_lock:
        packets = list(packet_buffer)

    talker_counts = Counter()
    proto_counts = Counter()

    for pkt in packets:
        if pkt.src:
            talker_counts[pkt.src] += 1
        if pkt.proto:
            proto_counts[pkt.proto] += 1

    top_talkers = talker_counts.most_common(10)
    top_protocols = proto_counts.most_common(10)

    return {
        "top_talkers": [[ip, count] for ip, count in top_talkers],
        "top_protocols": [[proto, count] for proto, count in top_protocols],
    }
