export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Menlo', 'monospace']
      },
      colors: {
        quantum: {
          50: '#e0f2fe',
          100: '#bae6fd',
          200: '#7dd3fc',
          300: '#38bdf8',
          400: '#0ea5e9',
          500: '#0284c7',
          600: '#0369a1',
          700: '#0b60a2',
        },
        lab: {
          space: '#0a0e27',
          galaxy: '#151b3d',
          panel: 'rgba(15,19,46,0.85)',
          accent: '#00d4ff',
          accentSoft: '#3b82f6',
        },
        alice: '#00d4ff',
        bob: '#8b5cf6',
        eve: '#ef4444',
        success: '#10b981',
        qber: {
          amber: '#fbbf24',
          danger: '#ef4444'
        }
      },
      boxShadow: {
        'quantum-glow': '0 0 30px rgba(0, 212, 255, 0.2)',
        'panel': '0 20px 60px rgba(5, 8, 26, 0.65)'
      },
      backdropBlur: {
        xl: '32px'
      },
      borderRadius: {
        '4xl': '2.5rem'
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: 0.7, transform: 'scale(1)' },
          '50%': { opacity: 1, transform: 'scale(1.05)' }
        },
        particleDrift: {
          '0%': { transform: 'translate3d(0,0,0)' },
          '100%': { transform: 'translate3d(0,-40px,20px)' }
        },
        qubitFlow: {
          '0%': { transform: 'translateX(0)', opacity: 0 },
          '30%': { opacity: 1 },
          '100%': { transform: 'translateX(100%)', opacity: 0 }
        }
      },
      animation: {
        'pulse-glow': 'pulseGlow 2.5s ease-in-out infinite',
        'particle-drift': 'particleDrift 8s linear infinite',
        'qubit-flow': 'qubitFlow 5s ease-in-out infinite'
      }
    },
  },
  plugins: [],
}