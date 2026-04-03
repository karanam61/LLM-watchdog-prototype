/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // WATCHDOG Design System — Deep Navy + Electric Teal
                // Researched from CyFocus, SOCius, CrowdStrike, SentraLock
                sentinel: {
                    950: '#070B14',  // Deep navy background
                    900: '#0D1321',  // Panel base
                    850: '#111827',  // Elevated panel
                    800: '#1A2540',  // Surface / cards
                    700: '#243352',  // Borders, dividers
                    600: '#2E4068',  // Hover borders
                    500: '#3D5280',  // Muted decorative elements
                    400: '#7B8DA8',  // Secondary text (5:1 on 950)
                    300: '#94A3BB',  // Body text (6.5:1 on 950)
                    200: '#B8C4D6',  // Emphasized text
                    100: '#D4DCE8',  // Headings
                    50:  '#EEF1F6',  // Primary / brightest text
                },
                // Primary — Electric Teal ("active protection")
                // Why teal: sits between blue (trust) and green (safe)
                // Used by CrowdStrike, SentinelOne for active monitoring state
                cyber: {
                    950: '#021F1A',
                    900: '#043D32',
                    800: '#065C4B',
                    700: '#089A7E',
                    600: '#0AB898',
                    500: '#00D4AA',  // PRIMARY — the watchdog color
                    400: '#33E0BC',
                    300: '#66EACE',
                    200: '#99F2DF',
                    100: '#CCF9EF',
                    50:  '#E6FCF7',
                },
                // Secondary — Slate Blue (data, links, informational)
                steel: {
                    500: '#5B8DEF',
                    400: '#7BA4F4',
                    300: '#9BBBF8',
                },
                // Signal colors — Industry-standard threat severity
                // Matches NIST/CVSS color conventions
                threat: {
                    critical: '#EF4444',
                    high: '#F97316',
                    medium: '#EAB308',
                    low: '#22C55E',
                    info: '#5B8DEF',
                },
                // Status indicators
                status: {
                    live: '#00D4AA',    // Same as primary = "protected"
                    warn: '#F59E0B',
                    error: '#EF4444',
                    offline: '#7B8DA8',
                },
            },
            fontFamily: {
                sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'SFMono-Regular', 'monospace'],
            },
            fontSize: {
                '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'pulse-fast': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'spin-slow': 'spin 3s linear infinite',
                'glow': 'glow 2s ease-in-out infinite alternate',
                'slide-in': 'slideIn 0.3s ease-out',
                'fade-up': 'fadeUp 0.3s ease-out',
            },
            keyframes: {
                glow: {
                    '0%': { opacity: '0.4' },
                    '100%': { opacity: '1' },
                },
                slideIn: {
                    '0%': { transform: 'translateX(-10px)', opacity: '0' },
                    '100%': { transform: 'translateX(0)', opacity: '1' },
                },
                fadeUp: {
                    '0%': { transform: 'translateY(8px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' },
                },
            },
            boxShadow: {
                'glow-cyber': '0 0 20px rgba(0, 212, 170, 0.15)',
                'glow-cyber-lg': '0 0 40px rgba(0, 212, 170, 0.2)',
                'glow-green': '0 0 20px rgba(0, 212, 170, 0.15)',
                'glow-red': '0 0 20px rgba(239, 68, 68, 0.15)',
                'panel': '0 1px 3px rgba(0,0,0,0.3), 0 4px 12px rgba(0,0,0,0.2)',
                'panel-lg': '0 4px 12px rgba(0,0,0,0.3), 0 12px 40px rgba(0,0,0,0.25)',
            },
        },
    },
    plugins: [],
}
