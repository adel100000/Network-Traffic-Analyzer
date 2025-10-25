import React, { useState } from "react";
import Dashboard from "./components/Dashboard";
import Login from "./components/Login";
import Register from "./components/Register";
import { AuthProvider, useAuth, UserRole } from "./context/AuthContext";

function AppContent() {
  const { token, role, logout } = useAuth();
  const [showRegister, setShowRegister] = useState(false);

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-hackerBlack">
      <div className="flex flex-col items-center justify-center w-full max-w-6xl px-4 py-8 space-y-6">
        {token ? (
          <Dashboard
            token={token}
            role={role ?? undefined} // fixes TS type issue
            onLogout={logout}
          />
        ) : showRegister ? (
          <Register onRegistered={() => setShowRegister(false)} />
        ) : (
          <Login />
        )}

        {!token && !showRegister && (
          <p className="mt-4 text-center text-sm text-white">
            Don’t have an account?{" "}
            <button
              onClick={() => setShowRegister(true)}
              className="text-hackerGreen hover:underline"
            >
              Register
            </button>
          </p>
        )}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
