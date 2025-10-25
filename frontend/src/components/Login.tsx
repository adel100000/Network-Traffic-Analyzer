import React, { useState } from "react";
import { login as apiLogin } from "../api/auth";
import { useAuth, UserRole } from "../context/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { token, role } = await apiLogin(username, password);
      // enforce role type
      const typedRole: UserRole = role === "admin" ? "admin" : "viewer";
      login(token, typedRole);
    } catch (err: any) {
      console.error("Login error:", err);
      setError(err.message || "Login failed. Check username/password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-hackerBlack">
      <div className="w-full max-w-md bg-hackerGray p-6 rounded-2xl shadow-lg">
        <h2 className="text-2xl font-bold text-hackerGreen mb-4 text-center"> Login </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            className="w-full px-4 py-2 rounded-lg bg-hackerBlack text-white outline-none"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            className="w-full px-4 py-2 rounded-lg bg-hackerBlack text-white outline-none"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {error && <p className="text-red-500 text-sm">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-hackerGreen text-black font-bold rounded-lg hover:bg-green-400 disabled:opacity-50"
          >
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}
