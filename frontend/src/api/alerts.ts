// src/api/alerts.ts
import axios from "axios";
const BASE_URL = "http://localhost:8000/api/alerts";

/**
 * Fetch alerts from backend.
 * Returns [] on error (frontend handles empty gracefully).
 */
export async function getAlerts(token: string) {
  try {
    const res = await axios.get(`${BASE_URL}/`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    let data: any[] = [];

    if (Array.isArray(res.data)) data = res.data;
    else if (res.data && Array.isArray((res.data as any).results)) data = (res.data as any).results;
    else return [];

    // Normalize each alert to a stable frontend shape
    return data.map((a: any) => {
      const created_at =
        a.created_at ??
        (a.createdAt ? a.createdAt : new Date().toISOString());

      // details normalization
      const details = a.details || {};
      const severity = details.severity ?? a.severity ?? "low";
      return {
        id: a.id ?? undefined,
        created_at: typeof created_at === "string" ? created_at : new Date(created_at).toISOString(),
        type: a.type ?? "Unknown",
        details: {
          src_ip: details.src_ip ?? details.src ?? "-",
          dst_ip: details.dst_ip ?? details.dst ?? "-",
          severity,
          message: details.message ?? details.msg ?? "",
          threat_score: details.threat_score ?? a.threat_score ?? 0,
        },
        resolved: a.resolved ?? false,
        geo_info:
          typeof a.geo_info === "string"
            ? a.geo_info
            : a.geo_info && typeof a.geo_info === "object"
            ? Object.values(a.geo_info).join(", ")
            : (details.geo ?? "-"),
        isp: a.isp ?? details.isp ?? "-",
        threat_score: a.threat_score ?? details.threat_score ?? 0,
      };
    });
  } catch (err) {
    console.error("getAlerts error:", err);
    return [];
  }
}
