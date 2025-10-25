from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from typing import Dict
from datetime import datetime

def packet_callback(pkt) -> Dict:
    data = {
        "timestamp": datetime.utcnow(),
        "src": pkt[IP].src if IP in pkt else None,
        "dst": pkt[IP].dst if IP in pkt else None,
        "proto": None,
        "sport": None,
        "dport": None,
        "length": len(pkt)
    }

    if IP in pkt:
        proto_num = pkt[IP].proto
        if proto_num == 6:
            data["proto"] = "TCP"
        elif proto_num == 17:
            data["proto"] = "UDP"
        else:
            data["proto"] = str(proto_num)

    if TCP in pkt:
        data["sport"] = pkt[TCP].sport
        data["dport"] = pkt[TCP].dport
    elif UDP in pkt:
        data["sport"] = pkt[UDP].sport
        data["dport"] = pkt[UDP].dport

    if DNS in pkt:
        data["dns"] = str(pkt[DNS].qd.qname)
    if Raw in pkt:
        data["payload_sample"] = bytes(pkt[Raw].load)[:50].hex()

    return data

def start_capture(callback, iface="eth0"):
    sniff(prn=lambda x: callback(packet_callback(x)), store=False, iface=iface)
