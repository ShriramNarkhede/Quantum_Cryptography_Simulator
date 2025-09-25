export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        quantum: { 50: '#f0f9ff', 500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1' },
        alice: '#10b981',
        bob: '#3b82f6',
        eve: '#ef4444'
      }
    },
  },
  plugins: [],
}