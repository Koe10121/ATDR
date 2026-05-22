import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#070b10",
        panel: "#0f151d",
        panel2: "#151d27",
        line: "#263445",
        muted: "#93a4b7",
        text: "#e5edf6",
        cyan: "#22d3ee",
        teal: "#14b8a6",
        amber: "#f59e0b",
        danger: "#ef4444",
        success: "#22c55e"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Arial", "sans-serif"]
      },
      boxShadow: {
        panel: "0 18px 42px rgba(0, 0, 0, 0.28)"
      }
    }
  },
  plugins: []
} satisfies Config;
