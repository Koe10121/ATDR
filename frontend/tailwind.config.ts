import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#f4f7fb",
        panel: "#ffffff",
        panel2: "#f8fafc",
        line: "#d6dee8",
        muted: "#64748b",
        text: "#172033",
        cyan: "#0ea5b7",
        teal: "#0f766e",
        amber: "#d97706",
        danger: "#dc2626",
        success: "#16a34a"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Arial", "sans-serif"]
      },
      boxShadow: {
        panel: "0 14px 36px rgba(15, 23, 42, 0.08)"
      }
    }
  },
  plugins: []
} satisfies Config;
