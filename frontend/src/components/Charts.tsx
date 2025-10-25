// src/components/Charts.tsx
import React from "react";
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

interface ChartsProps {
  talkerHistory: { [ip: string]: number[] };
  protocolHistory: { [proto: string]: number[] };
}

export default function Charts({ talkerHistory, protocolHistory }: ChartsProps) {
  const COLORS = ["#22c55e", "#3b82f6", "#f59e0b", "#ef4444", "#a855f7"];

  // Line chart data (latest packet count per IP)
  const lineData = Object.entries(talkerHistory).map(([ip, counts]) => ({
    time: ip,
    packets: counts && counts.length > 0 ? Number(counts[counts.length - 1]) || 0 : 0,
  }));

  // Protocol pie/bar chart data (latest count per protocol)
  const protocolData = Object.entries(protocolHistory).map(([protocol, counts]) => ({
    protocol,
    count: counts && counts.length > 0 ? Number(counts[counts.length - 1]) || 0 : 0,
  }));

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 w-full">
      {/* Line Chart */}
      <div className="bg-hackerGray p-4 rounded-xl shadow-lg">
        <h3 className="text-lg font-semibold text-hackerGreen mb-2 text-center">
          Traffic Over Time
        </h3>
        <div className="min-h-[220px]">
          {lineData.length === 0 ? (
            <p className="text-center text-gray-300 mt-8">No replay data</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={lineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fill: "#c7ffe0" }} />
                <YAxis tick={{ fill: "#c7ffe0" }} />
                <Tooltip contentStyle={{ backgroundColor: "#111", border: "none", color: "#fff" }} />
                <Line type="monotone" dataKey="packets" stroke="#22c55e" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Protocol Pie */}
      <div className="bg-hackerGray p-4 rounded-xl shadow-lg">
        <h3 className="text-lg font-semibold text-hackerGreen mb-2 text-center">
          Protocol Distribution
        </h3>
        <div className="min-h-[220px]">
          {protocolData.length === 0 ? (
            <p className="text-center text-gray-300 mt-8">No protocol data</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={protocolData}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label
                >
                  {protocolData.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: "#111", border: "none", color: "#fff" }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Protocol Bar */}
      <div className="bg-hackerGray p-4 rounded-xl shadow-lg sm:col-span-2">
        <h3 className="text-lg font-semibold text-hackerGreen mb-2 text-center">
          Protocol Counts
        </h3>
        <div className="min-h-[220px]">
          {protocolData.length === 0 ? (
            <p className="text-center text-gray-300 mt-8">No protocol counts</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={protocolData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="protocol" tick={{ fill: "#c7ffe0" }} />
                <YAxis tick={{ fill: "#c7ffe0" }} />
                <Tooltip contentStyle={{ backgroundColor: "#111", border: "none", color: "#fff" }} />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
