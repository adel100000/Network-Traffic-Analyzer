// src/components/LiveTable.tsx
import React, { useEffect, useState } from "react";
import { getTraffic } from "../api/traffic";

type Packet = {
  timestamp: string;
  src?: string;
  src_port?: number;
  dst?: string;
  dst_port?: number;
  proto?: string;
  length: number;
  dns?: string;
  payload_sample?: string;
  anomaly?: boolean;
  port_scan?: boolean;
  payload_entropy?: number;
  traffic_burst?: boolean;
  threat_score?: number;
  critical?: boolean;
};

interface LiveTableProps {
  token: string;
  role?: "admin" | "viewer";
}

export default function LiveTable({ token, role = "viewer" }: LiveTableProps) {
  const [traffic, setTraffic] = useState<Packet[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<keyof Packet | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const fetchData = async () => {
    try {
      const data: Packet[] = await getTraffic(token);
      setTraffic(data || []);
      setError(null);

      if (typeof window !== "undefined" && "Notification" in window && Notification.permission === "granted") {
        data?.forEach((pkt) => {
          if (pkt.critical && role === "admin") {
            try {
              new Notification("Critical Packet!", {
                body: `Src: ${pkt.src} → Dst: ${pkt.dst} | Score: ${pkt.threat_score}`,
              });
            } catch (e) {
              // ignore
            }
          }
        });
      }
    } catch (err) {
      console.error("LiveTable error:", err);
      setError("Failed to load traffic data");
      setTraffic([]);
    }
  };

  useEffect(() => {
    if (typeof window !== "undefined" && "Notification" in window && Notification.permission !== "granted") {
      Notification.requestPermission();
    }
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const filtered = traffic
    .filter((pkt) =>
      filter
        ? pkt.src?.includes(filter) || pkt.dst?.includes(filter) || pkt.proto?.includes(filter)
        : true
    )
    .sort((a, b) => {
      if (!sortKey) return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      const aVal = a[sortKey] as any;
      const bVal = b[sortKey] as any;
      if (typeof aVal === "number" && typeof bVal === "number") return sortAsc ? aVal - bVal : bVal - aVal;
      return sortAsc ? String(aVal ?? "").localeCompare(String(bVal ?? "")) : String(bVal ?? "").localeCompare(String(aVal ?? ""));
    });

  const toggleSort = (key: keyof Packet) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  // pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="bg-hackerGray p-4 rounded-xl shadow-lg w-full overflow-x-auto">
      <h2 className="text-xl font-bold text-hackerGreen mb-2 text-center">Live Traffic</h2>

      <input
        type="text"
        placeholder="Filter by IP or Protocol"
        className="mb-2 p-2 rounded bg-hackerBlack text-white w-full"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />

      {error && <p className="text-red-500 text-sm text-center">{error}</p>}

      <table className="table-auto w-full text-left text-white border-collapse">
        <thead className="sticky top-0 bg-hackerGray z-10">
          <tr className="text-hackerGreen cursor-pointer">
            {[
              "timestamp",
              "src",
              "src_port",
              "dst",
              "dst_port",
              "proto",
              "length",
              "dns",
              "payload_sample",
              "payload_entropy",
              "port_scan",
              "traffic_burst",
              "threat_score",
            ].map((col) => (
              <th key={col} onClick={() => toggleSort(col as keyof Packet)} className="px-2 py-1">
                {col.replace("_", " ").toUpperCase()}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {paginated.map((pkt, idx) => (
            <tr
              key={idx}
              className={`hover:bg-hackerBlack transition duration-200 ${
                pkt.anomaly ? "bg-red-900 animate-pulse" : pkt.length > 1500 ? "bg-yellow-900" : ""
              }`}
            >
              <td className="px-2 py-1">{new Date(pkt.timestamp).toLocaleString()}</td>
              <td className="px-2 py-1">{pkt.src ?? "-"}</td>
              <td className="px-2 py-1">{pkt.src_port ?? "-"}</td>
              <td className="px-2 py-1">{pkt.dst ?? "-"}</td>
              <td className="px-2 py-1">{pkt.dst_port ?? "-"}</td>
              <td className="px-2 py-1">{pkt.proto ?? "-"}</td>
              <td className="px-2 py-1">{pkt.length}</td>
              <td className="px-2 py-1">{pkt.dns ?? "-"}</td>
              <td className="px-2 py-1 truncate max-w-[150px]">{pkt.payload_sample ?? "-"}</td>
              <td className="px-2 py-1">{pkt.payload_entropy ?? "-"}</td>
              <td className="px-2 py-1">{pkt.port_scan ? "Yes" : "No"}</td>
              <td className="px-2 py-1">{pkt.traffic_burst ? "Yes" : "No"}</td>
              <td className="px-2 py-1">{role === "admin" ? pkt.threat_score ?? "-" : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Pagination controls */}
      <div className="flex justify-between items-center mt-3 text-white">
        <span>Page {page} of {totalPages || 1}</span>
        <div className="space-x-2">
          <button disabled={page === 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="px-2 py-1 bg-hackerBlack rounded disabled:opacity-50">Prev</button>
          <button disabled={page === totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} className="px-2 py-1 bg-hackerBlack rounded disabled:opacity-50">Next</button>
        </div>
      </div>
    </div>
  );
}
