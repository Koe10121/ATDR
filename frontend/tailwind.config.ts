import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#0a0e16",
        panel: "#121927",
        panel2: "#1a2335",
        line: "#2a3650",
        muted: "#8b96ac",
        text: "#e8edf7",
        cyan: "#22d3ee",
        teal: "#2dd4bf",
        amber: "#fbbf24",
        gold: "#e8b64a",
        goldSoft: "#3a2f1a",
        danger: "#f87171",
        success: "#4ade80",
        maroon: "#5c0f12",
        maroonDeep: "#450a0c"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Arial", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"]
      },
      boxShadow: {
        panel: "0 8px 24px rgba(0, 0, 0, 0.35)",
        glow: "0 0 0 1px rgba(34, 211, 238, 0.15), 0 8px 24px rgba(0, 0, 0, 0.4)"
      }
    }
  },
  plugins: []
} satisfies Config;
