from typing import List, Dict
import statistics, math, time
from collections import defaultdict, deque

# Sliding windows for frequency analysis
packet_times = deque(maxlen=1000)
src_port_map = defaultdict(set)
src_timestamps = defaultdict(list)

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a hex string payload."""
    if not data:
        return 0.0
    data_bytes = bytes.fromhex(data)
    length = len(data_bytes)
    if length == 0:
        return 0.0
    freqs = {}
    for b in data_bytes:
        freqs[b] = freqs.get(b, 0) + 1
    entropy = 0.0
    for f in freqs.values():
        p = f / length
        entropy -= p * math.log2(p)
    return entropy

def detect_anomalies(packets: List[Dict]) -> List[Dict]:
    alerts = []
    now = time.time()

    if not packets:
        return alerts

    # 1. Large packet detection
    sizes = [p["length"] for p in packets if "length" in p]
    if sizes:
        avg_size = statistics.mean(sizes)
        for p in packets:
            if p["length"] > avg_size * 3:
                alerts.append({
                    "type": "Large Packet",
                    "details": p,
                    "anomaly_flag": True
                })

    # 2. Port scan detection per src IP
    for p in packets:
        src = p.get("src")
        dport = p.get("dport")
        if src and dport:
            src_port_map[src].add(dport)
            if len(src_port_map[src]) > 50:  # threshold for scan
                alerts.append({
                    "type": "Port Scan Detected",
                    "details": {"src": src, "ports": list(src_port_map[src])[:20]},
                    "anomaly_flag": True
                })

    # 3. Frequency / burst detection
    for p in packets:
        packet_times.append(now)
        src = p.get("src")
        if src:
            src_timestamps[src].append(now)
            # keep window small
            src_timestamps[src] = [t for t in src_timestamps[src] if now - t < 10]
            if len(src_timestamps[src]) > 100:
                alerts.append({
                    "type": "Traffic Burst",
                    "details": {"src": src, "rate": len(src_timestamps[src])},
                    "anomaly_flag": True
                })

    # 4. Entropy analysis
    for p in packets:
        payload = p.get("payload_sample")
        if payload:
            entropy = shannon_entropy(payload)
            if entropy > 7.5:  # high entropy suspicious payload
                alerts.append({
                    "type": "High Entropy Payload",
                    "details": {"src": p.get("src"), "entropy": entropy},
                    "anomaly_flag": True
                })

    return alerts
