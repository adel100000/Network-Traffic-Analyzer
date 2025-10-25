// src/api/traffic.ts
import axios from "axios";

// Adjust base URLs to match backend structure
const TRAFFIC_BASE = "http://localhost:8000/api/traffic";
const REPLAY_BASE = "http://localhost:8000/api/replay";

// --------------------
// Live traffic
// --------------------
export async function getTraffic(token: string) {
  try {
    const res = await axios.get(`${TRAFFIC_BASE}/live`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 5000,
    });

    // Add threat_score if missing (best-effort local scoring)
    const data = (res.data || []).map((pkt: any) => ({
      ...pkt,
      threat_score: pkt.threat_score ?? computeThreatScore(pkt),
    }));

    return data;
  } catch (err) {
    console.error("getTraffic error:", err);
    return [];
  }
}

// --------------------
// Replay summary
// --------------------
export interface ReplaySummary {
  top_talkers: [string, number][];
  top_protocols: [string, number][];
}

export async function getReplaySummary(token: string): Promise<ReplaySummary> {
  try {
    const res = await axios.get(`${REPLAY_BASE}/summary`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 7000,
    });

    const { top_talkers = [], top_protocols = [] } = res.data || {};
    return { top_talkers, top_protocols };
  } catch (err) {
    console.error("getReplaySummary error:", err);
    return { top_talkers: [], top_protocols: [] };
  }
}

// --------------------
// Optional: Threat score calculator (fallback)
// --------------------
function computeThreatScore(pkt: any): number {
  let score = 0;

  if (pkt.anomaly) score += 50;

  // common sensitive ports bump
  const sensitive = [20, 21, 22, 23, 25, 80, 443];
  if (sensitive.includes(pkt.src_port) || sensitive.includes(pkt.dst_port)) score += 10;

  if (pkt.length > 1500) score += 5;

  if (pkt.severity === "medium") score += 10;
  if (pkt.severity === "high") score += 25;

  return Math.min(score, 100);
}
