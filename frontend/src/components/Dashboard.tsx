// src/components/Dashboard.tsx
import React, { useEffect, useState } from "react";
import LiveTable from "./LiveTable";
import Charts from "./Charts";
import Alerts from "./Alerts";
import { getReplaySummary } from "../api/traffic";

type TopTalker = { ip: string; count: number };
type Protocol = { protocol: string; count: number };

interface DashboardProps {
  token: string;
  role?: "admin" | "viewer";
  onLogout: () => void;
}

export default function Dashboard({ token, role, onLogout }: DashboardProps) {
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);
  const [topProtocols, setTopProtocols] = useState<Protocol[]>([]);
  const [talkerHistory, setTalkerHistory] = useState<{ [ip: string]: number[] }>({});
  const [protocolHistory, setProtocolHistory] = useState<{ [proto: string]: number[] }>({});

  const fetchReplayData = async () => {
    setLoadingSummary(true);
    try {
      const data = await getReplaySummary(token);

      // Map top_talkers → TopTalker[]
      const topTalkersData: TopTalker[] = (data.top_talkers ?? []).map(([ip, count]) => ({
        ip: String(ip),
        count: Number(count),
      }));

      // Map top_protocols → Protocol[]
      const topProtocolsData: Protocol[] = (data.top_protocols ?? []).map(([protocol, count]) => ({
        protocol: String(protocol),
        count: Number(count),
      }));

      setTopTalkers(topTalkersData);
      setTopProtocols(topProtocolsData);

      // Update talker history (keep last 50)
      setTalkerHistory(prev => {
        const newHist = { ...prev };
        topTalkersData.forEach(({ ip, count }) => {
          newHist[ip] = [...(newHist[ip] ?? []), count].slice(-50);
        });
        return newHist;
      });

      // Update protocol history (keep last 50)
      setProtocolHistory(prev => {
        const newHist = { ...prev };
        topProtocolsData.forEach(({ protocol, count }) => {
          newHist[protocol] = [...(newHist[protocol] ?? []), count].slice(-50);
        });
        return newHist;
      });
    } catch (err) {
      console.error("Replay fetch error:", err);
      setTopTalkers([]);
      setTopProtocols([]);
      setTalkerHistory({});
      setProtocolHistory({});
    } finally {
      setLoadingSummary(false);
    }
  };

  useEffect(() => {
    fetchReplayData();
    const interval = setInterval(fetchReplayData, 4000);
    return () => clearInterval(interval);
  }, [token]);

  return (
    <div className="w-full max-w-7xl space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-4xl font-bold text-hackerGreen animate-pulse">Network Traffic Analyzer</h1>
          <p className="text-sm text-gray-300 mt-1">
            Live monitoring - replay analysis - threat enrichment
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-sm text-gray-300">Role: {role ?? "viewer"}</div>
          <button
            onClick={onLogout}
            className="px-4 py-2 bg-red-600 rounded-lg hover:bg-red-700 transition text-white"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Live traffic + Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <LiveTable token={token} role={role} />
        <Alerts token={token} />
      </div>

      {/* Charts + Network Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Charts talkerHistory={talkerHistory} protocolHistory={protocolHistory} />

        <div className="bg-hackerGray p-4 rounded-xl shadow-lg w-full min-h-[250px]">
          <h2 className="text-xl font-bold text-hackerGreen mb-4 text-center">Network Insights</h2>
          {loadingSummary ? (
            <p className="text-center text-gray-300">Loading summary...</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Top Talkers */}
              <div>
                <h3 className="text-lg font-semibold text-hackerGreen mb-2">Top Talkers</h3>
                {topTalkers.length === 0 ? (
                  <p className="text-sm text-gray-300">No data available</p>
                ) : (
                  <ul className="space-y-1 text-white">
                    {topTalkers.map((t, idx) => (
                      <li
                        key={idx}
                        className="flex justify-between bg-hackerBlack/40 rounded px-2 py-1 items-center"
                      >
                        <div className="truncate max-w-[140px]">{t.ip}</div>
                        <div className="text-hackerGreen font-bold">{t.count}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Top Protocols */}
              <div>
                <h3 className="text-lg font-semibold text-hackerGreen mb-2">Top Protocols</h3>
                {topProtocols.length === 0 ? (
                  <p className="text-sm text-gray-300">No data available</p>
                ) : (
                  <ul className="space-y-1 text-white">
                    {topProtocols.map((p, idx) => (
                      <li
                        key={idx}
                        className="flex justify-between bg-hackerBlack/40 rounded px-2 py-1 items-center"
                      >
                        <span>{p.protocol}</span>
                        <span className="text-hackerGreen font-bold">{p.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
