import React, { useState } from "react";
import { register } from "../api/auth";

interface RegisterProps {
  onRegistered: () => void;
}

export default function Register({ onRegistered }: RegisterProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      await register(username, password);
      setSuccess("Account created! You can log in now.");
      setTimeout(() => onRegistered(), 1500);
    } catch (err: any) {
      console.error("Register error:", err);
      setError(err.message || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-hackerBlack">
      <div className="w-full max-w-md bg-hackerGray p-6 rounded-2xl shadow-lg">
        <h2 className="text-2xl font-bold text-hackerGreen mb-4 text-center"> Register </h2>
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
          {success && <p className="text-green-400 text-sm">{success}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-hackerGreen text-black font-bold rounded-lg hover:bg-green-400 disabled:opacity-50"
          >
            {loading ? "Creating..." : "Register"}
          </button>
        </form>
        <p className="mt-4 text-center text-sm">
          Already have an account?{" "}
          <button onClick={onRegistered} className="text-hackerGreen hover:underline">
            Login
          </button>
        </p>
      </div>
    </div>
  );
}
