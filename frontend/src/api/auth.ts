import axios from "axios";
const BASE_URL = "http://localhost:8000/api/users";

export async function login(username: string, password: string): Promise<{ token: string, role: string }> {
  try {
    const res = await axios.post(`${BASE_URL}/login`, { username, password });
    return { token: res.data.access_token, role: res.data.role || "viewer" };
  } catch (err: any) {
    console.error("Login failed:", err.response?.data || err.message);
    throw new Error(err.response?.data?.detail || "Login failed");
  }
}

export async function register(username: string, password: string): Promise<void> {
  try {
    await axios.post(`${BASE_URL}/register`, { username, password });
  } catch (err: any) {
    console.error("Registration failed:", err.response?.data || err.message);
    throw new Error(err.response?.data?.detail || "Registration failed");
  }
}
