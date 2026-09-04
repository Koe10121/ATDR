import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#f2f4f7",
        panel: "#ffffff",
        panel2: "#f8f9fb",
        line: "#d9dee7",
        muted: "#5f6b7a",
        text: "#243047",
        cyan: "#8c1515",
        teal: "#0f766e",
        amber: "#8a460f",
        gold: "#c77f28",
        goldSoft: "#fff4df",
        danger: "#8c1515",
        success: "#166534"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Arial", "sans-serif"]
      },
      boxShadow: {
        panel: "0 8px 22px rgba(36, 48, 71, 0.07)"
      }
    }
  },
  plugins: []
} satisfies Config;
