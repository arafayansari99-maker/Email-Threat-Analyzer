/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      screens: {
        'xs': '320px',
        'sm': '640px',
        'md': '768px',
        'lg': '1024px',
        'xl': '1280px',
        '2xl': '1536px',
        'tall': { 'raw': '(min-height: 600px)' },
        'short': { 'raw': '(max-height: 500px)' },
      },
      fontFamily: {
        mono: ['"Share Tech Mono"', '"JetBrains Mono"', 'ui-monospace', 'monospace'],
        sans: ['"DM Sans"', 'ui-sans-serif', 'system-ui'],
      },
      colors: {
        threat: {
          bg:      '#070B14',
          surface: '#0D1420',
          card:    '#111827',
          border:  '#1E2D40',
          muted:   '#1F2D3D',
        }
      },
      spacing: {
        'safe-top': 'env(safe-area-inset-top)',
        'safe-right': 'env(safe-area-inset-right)',
        'safe-bottom': 'env(safe-area-inset-bottom)',
        'safe-left': 'env(safe-area-inset-left)',
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan-line': 'scanLine 2s linear infinite',
      },
      keyframes: {
        scanLine: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        }
      }
    }
  },
  plugins: [],
}

