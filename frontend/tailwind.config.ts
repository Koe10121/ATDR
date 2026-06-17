import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#eef3f8",
        panel: "#ffffff",
        panel2: "#f8fafc",
        line: "#d8e0ea",
        muted: "#64748b",
        text: "#172033",
        cyan: "#2563eb",
        teal: "#0f766e",
        amber: "#d97706",
        danger: "#8c1515",
        success: "#16a34a"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Arial", "sans-serif"]
      },
      boxShadow: {
        panel: "0 10px 28px rgba(15, 23, 42, 0.07)"
      }
    }
  },
  plugins: []
} satisfies Config;
