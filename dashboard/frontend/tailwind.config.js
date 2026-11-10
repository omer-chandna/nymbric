/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#10140f",
        panel: "#171e16",
        line: "#2c3828",
        moss: "#9aa892",
        lime: "#d6f25c",
        tide: "#8ec8c3",
        clay: "#ef6f5e",
        amber: "#e3a008",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "system-ui"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
