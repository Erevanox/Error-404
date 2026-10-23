/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // TraceX Clean Professional White Theme
        forensic: {
          bg: '#F8FAFC',          // light gray-white background
          sidebar: '#F8FAFC',     // light gray sidebar
          card: '#FFFFFF',        // clean white cards
          cardHover: '#F1F5F9',
          border: '#E2E8F0',      // subtle gray border
          borderSubtle: '#F1F5F9',
          primary: '#10B981',     // muted green accent
          primaryHover: '#059669',
          accent: '#10B981',
          warning: '#F59E0B',     // restrained amber
          warningBg: '#FFFBEB',
          critical: '#EF4444',    // controlled red
          criticalBg: '#FEF2F2',
          text: '#0F172A',        // dark readable text
          textSecondary: '#64748B', // readable cool gray
          textMuted: '#94A3B8',
        },
        // Backward-compatible token mappings to guarantee clean white aesthetics across all components
        wazuh: {
          bg: '#F8FAFC',
          surface: '#FFFFFF',
          card: '#FFFFFF',
          sidebar: '#F8FAFC',
          border: '#E2E8F0',
          borderLight: '#F1F5F9',
          header: '#FFFFFF',
          primary: '#10B981',
          hover: '#F1F5F9',
          text: '#0F172A',
          textSecondary: '#64748B',
          muted: '#F1F5F9',
          critical: '#EF4444',
          criticalBg: '#FEF2F2',
          high: '#F59E0B',
          highBg: '#FFFBEB',
          medium: '#EAB308',
          mediumBg: '#FEFCE8',
          low: '#10B981',
          lowBg: '#ECFDF5',
          info: '#64748B',
          infoBg: '#F1F5F9',
        },
        soc: {
          bg: '#F8FAFC',
          surface: '#FFFFFF',
          card: '#FFFFFF',
          border: '#E2E8F0',
          highlight: '#10B981',
          cyan: '#10B981',
          blue: '#10B981',
          purple: '#8B5CF6',
          red: '#EF4444',
          amber: '#F59E0B',
          emerald: '#10B981',
          text: '#0F172A',
          muted: '#64748B'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.07), 0 1px 2px -1px rgba(0, 0, 0, 0.07)',
        'dropdown': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)',
      }
    },
  },
  plugins: [],
}
