import React, { useEffect, useState, useRef } from "react";
import { getAlerts as apiGetAlerts } from "../api/alerts";

type Alert = {
  id?: number;
  created_at: string;
  type: string;
  details: {
    src_ip?: string;
    dst_ip?: string;
    severity?: string | number;
    message?: string;
    threat_score?: number;
    geo?: string;
    isp?: string;
  };
  resolved: boolean;
  geo_info?: string | Record<string, any> | null;
  isp?: string | null;
};

function countryToFlagEmoji(countryName?: string | null) {
  if (!countryName) return "";
  const parts = countryName.split(",").map((p) => p.trim()).filter(Boolean);
  const maybeCountry = parts[parts.length - 1] || countryName;
  const smallMap: Record<string, string> = {
    "United States": "US",
    "USA": "US",
    "United Kingdom": "GB",
    "Great Britain": "GB",
    "Canada": "CA",
    "Germany": "DE",
    "France": "FR",
    "Netherlands": "NL",
    "Sweden": "SE",
    "Australia": "AU",
    "India": "IN",
  };
  const iso = smallMap[maybeCountry] || maybeCountry.toUpperCase().slice(0, 2);
  if (!iso || iso.length !== 2) return "";
  const codePoints = [...iso.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

export default function Alerts({ token }: { token: string }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data: Alert[] = await apiGetAlerts(token);
      const normalized = data.map((a) => {
        let geo = "-";
        if (typeof a.geo_info === "string") geo = a.geo_info;
        else if (a.geo_info && typeof a.geo_info === "object")
          geo = Object.values(a.geo_info).join(", ");
        else if (a.details?.geo) geo = a.details.geo;

        return {
          ...a,
          geo_info: geo,
          isp: a.isp ?? a.details?.isp ?? "Unknown",
          details: {
            ...a.details,
            threat_score: a.details?.threat_score ?? 0,
          },
        };
      });

      setAlerts(normalized);
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(() => fetchData(true), 5000);
    return () => clearInterval(iv);
  }, [token]);

  const filtered = alerts.filter((a) =>
    filter
      ? a.details?.src_ip?.includes(filter) ||
        a.details?.dst_ip?.includes(filter) ||
        a.type?.toLowerCase().includes(filter.toLowerCase()) ||
        a.details?.message?.toLowerCase().includes(filter.toLowerCase())
      : true
  );

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  function severityClass(s?: string | number) {
    if (!s) return "text-white";
    if (typeof s === "string") {
      const lower = s.toLowerCase();
      if (lower === "high") return "text-red-400 font-bold";
      if (lower === "medium") return "text-yellow-300";
      return "text-green-300";
    }
    if (typeof s === "number") {
      if (s >= 7) return "text-red-400 font-bold";
      if (s >= 4) return "text-yellow-300";
    }
    return "text-green-300";
  }

  return (
    <div className="card w-full overflow-x-auto animate-fadeIn">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-xl font-bold text-hackerGreen">Alerts</h2>
      </div>

      <input
        type="text"
        placeholder="Filter by IP, type, message..."
        className="mb-2 p-2 rounded bg-hackerBlack text-white w-full"
        value={filter}
        onChange={(e) => {
          setFilter(e.target.value);
          setPage(1);
        }}
      />

      {loading && <p className="text-gray-300">Loading alerts…</p>}
      {error && <p className="text-red-500">{error}</p>}

      <table className="table-auto w-full text-left text-white border-collapse">
        <thead className="sticky top-0 bg-hackerGray z-10 text-hackerGreen">
          <tr>
            <th className="px-2 py-1">Timestamp</th>
            <th className="px-2 py-1">Type</th>
            <th className="px-2 py-1">Source</th>
            <th className="px-2 py-1">Destination</th>
            <th className="px-2 py-1">Geo / ISP</th>
            <th className="px-2 py-1">Severity</th>
            <th className="px-2 py-1">Threat</th>
            <th className="px-2 py-1">Message</th>
          </tr>
        </thead>
        <tbody>
          {paginated.length === 0 ? (
            <tr>
              <td colSpan={8} className="p-4 text-center text-gray-300">
                No alerts to show
              </td>
            </tr>
          ) : (
            paginated.map((a, idx) => {
              const geoString = typeof a.geo_info === "string" ? a.geo_info : "-";
              const flag = countryToFlagEmoji(geoString);
              return (
                <tr key={a.id ?? idx} className="hover:bg-hackerBlack transition">
                  <td className="px-2 py-1">
                    {new Date(a.created_at).toLocaleString()}
                  </td>
                  <td className="px-2 py-1 text-hackerGreen font-bold">{a.type}</td>
                  <td className="px-2 py-1">{a.details?.src_ip ?? "-"}</td>
                  <td className="px-2 py-1">{a.details?.dst_ip ?? "-"}</td>
                  <td className="px-2 py-1 truncate max-w-[160px]">
                    {flag} {geoString} <br />
                    <span className="text-gray-400 text-sm">{a.isp ?? "-"}</span>
                  </td>
                  <td className={`px-2 py-1 ${severityClass(a.details?.severity)}`}>
                    {String(a.details?.severity ?? "-")}
                  </td>
                  <td className={`px-2 py-1 ${severityClass(a.details?.threat_score)}`}>
                    {a.details?.threat_score ?? "-"}
                  </td>
                  <td className="px-2 py-1 truncate max-w-[200px]">
                    {a.details?.message ?? "-"}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>

      <div className="flex justify-between items-center mt-3 text-white">
        <span>
          Page {page} of {totalPages}
        </span>
        <div className="space-x-2">
          <button
            disabled={page === 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            className="px-2 py-1 bg-hackerBlack rounded disabled:opacity-50"
          >
            Prev
          </button>
          <button
            disabled={page === totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            className="px-2 py-1 bg-hackerBlack rounded disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
