/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        hackerBlack: "#0a0a0a",
        hackerGreen: "#14df80",
        hackerGray: "#1f1f1f",
        highRed: "#ff4c4c",
        medYellow: "#ffd500",
        lowGreen: "#00ff88",
        neonBlue: "#00ffff",
        neonPurple: "#bb00ff",
      },
      animation: {
        pulseGlow: "pulseGlow 1.5s infinite",
        fadeIn: "fadeIn 0.5s ease-in-out forwards",
      },
      boxShadow: {
        neon: "0 0 10px #14df80, 0 0 20px #00ff88",
      },
      fontFamily: {
        mono: ["'Fira Code', monospace"],
      },
    },
  },
  plugins: [],
};
