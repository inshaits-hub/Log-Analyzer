// Loaded from js/head.js right after the Tailwind Play CDN, which creates
// the `tailwind` global. The fallback keeps this file from throwing a
// ReferenceError (and taking the rest of the page's <head> with it) if the
// CDN is blocked or offline.
window.tailwind = window.tailwind || {};

// Material 3 token names are kept so existing markup keeps working, but the
// values are re-tuned to a neutral slate/blue ramp: the old export was
// warm-grey and read as "unfinished design tool output" next to real data.
tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      "colors": {
        // Neutrals (slate ramp)
        "surface": "#f1f5f9",
        "background": "#f1f5f9",
        "surface-bright": "#ffffff",
        "surface-dim": "#e2e8f0",
        "surface-variant": "#e2e8f0",
        "surface-container-lowest": "#ffffff",
        "surface-container-low": "#f8fafc",
        "surface-container": "#f1f5f9",
        "surface-container-high": "#e2e8f0",
        "surface-container-highest": "#cbd5e1",
        "on-surface": "#0f172a",
        "on-surface-variant": "#475569",
        "on-background": "#0f172a",
        "secondary": "#4b5768",
        "secondary-container": "#e2e8f0",
        "on-secondary": "#ffffff",
        "on-secondary-container": "#334155",
        "secondary-fixed": "#e2e8f0",
        "secondary-fixed-dim": "#cbd5e1",
        "on-secondary-fixed": "#1e293b",
        "on-secondary-fixed-variant": "#475569",

        // Brand (blue)
        "primary": "#2563eb",
        "on-primary": "#ffffff",
        "primary-container": "#dbeafe",
        "on-primary-container": "#1e3a8a",
        "primary-fixed": "#dbeafe",
        "primary-fixed-dim": "#bfdbfe",
        "on-primary-fixed": "#1e3a8a",
        "on-primary-fixed-variant": "#1d4ed8",
        "inverse-primary": "#93c5fd",
        "surface-tint": "#2563eb",

        // Accent (amber) - used for "high" attention states
        "tertiary": "#b45309",
        "on-tertiary": "#ffffff",
        "tertiary-container": "#fef3c7",
        "on-tertiary-container": "#78350f",
        "tertiary-fixed": "#fde68a",
        "tertiary-fixed-dim": "#fcd34d",
        "on-tertiary-fixed": "#78350f",
        "on-tertiary-fixed-variant": "#92400e",

        // Error / critical
        "error": "#dc2626",
        "on-error": "#ffffff",
        "error-container": "#fee2e2",
        "on-error-container": "#991b1b",

        "outline": "#94a3b8",
        "outline-variant": "#e2e8f0",

        // Sidebar (dark navy rail)
        "rail": "#0f172a",
        "rail-high": "#1e293b",
        "rail-hover": "#334155",
        "rail-on": "#f8fafc",
        "rail-on-muted": "#94a3b8",

        // Severity ramp, shared by badges, bars, table dots and charts so the
        // four places a severity appears can never drift apart. The
        // *-text shades are darkened just enough to clear 4.5:1 on white,
        // which the bar/dot colours do not.
        "sev-critical": "#dc2626",
        "sev-critical-text": "#b91c1c",
        "sev-critical-bg": "#fef2f2",
        "sev-critical-border": "#fecaca",
        "sev-high": "#ea580c",
        "sev-high-text": "#c2410c",
        "sev-high-bg": "#fff7ed",
        "sev-high-border": "#fed7aa",
        "sev-medium": "#ca8a04",
        "sev-medium-text": "#a16207",
        "sev-medium-bg": "#fefce8",
        "sev-medium-border": "#fde68a",
        "sev-low": "#64748b",
        "sev-low-text": "#475569",
        "sev-low-bg": "#f8fafc",
        "sev-low-border": "#e2e8f0",
        "sev-info": "#2563eb",
        "sev-info-bg": "#eff6ff",
        "sev-info-border": "#bfdbfe",

        // Positive
        "success": "#059669",
        "success-bg": "#ecfdf5",
        "success-border": "#a7f3d0"
      },

      // The old export zeroed every radius, which is what made the UI look
      // unfinished. Rounded surfaces are the single biggest visual upgrade.
      "borderRadius": {
        "none": "0px",
        "sm": "4px",
        "DEFAULT": "6px",
        "md": "8px",
        "lg": "12px",
        "xl": "16px",
        "2xl": "20px",
        "full": "9999px"
      },

      // Soft elevation instead of hard 1px borders everywhere.
      "boxShadow": {
        "card": "0 1px 2px 0 rgb(15 23 42 / 0.04), 0 1px 3px 0 rgb(15 23 42 / 0.06)",
        "card-hover": "0 4px 6px -1px rgb(15 23 42 / 0.07), 0 2px 4px -2px rgb(15 23 42 / 0.05)",
        "raised": "0 2px 4px -1px rgb(15 23 42 / 0.06), 0 4px 8px -2px rgb(15 23 42 / 0.08)",
        "popover": "0 10px 15px -3px rgb(15 23 42 / 0.10), 0 4px 6px -4px rgb(15 23 42 / 0.10)",
        "rail": "0 0 24px -4px rgb(15 23 42 / 0.25)"
      },

      "spacing": {
        "rail": "248px",
        "topbar": "56px"
      },

      "fontFamily": {
        "body-sm": ["IBM Plex Sans"],
        "label-md": ["IBM Plex Sans"],
        "headline-md": ["IBM Plex Sans"],
        "label-sm": ["IBM Plex Sans"],
        "headline-lg": ["IBM Plex Sans"],
        "headline-sm": ["IBM Plex Sans"],
        "code-sm": ["IBM Plex Mono", "IBM Plex Sans", "monospace"],
        "body-md": ["IBM Plex Sans"],
        "body-lg": ["IBM Plex Sans"],
        "code-md": ["IBM Plex Mono", "IBM Plex Sans", "monospace"],
        "headline-xl": ["IBM Plex Sans"]
      },

      "fontSize": {
        "body-sm": ["12px", { "lineHeight": "16px", "fontWeight": "400" }],
        "label-md": ["12px", { "lineHeight": "16px", "letterSpacing": "0.01em", "fontWeight": "500" }],
        "headline-md": ["18px", { "lineHeight": "24px", "fontWeight": "600" }],
        "label-sm": ["11px", { "lineHeight": "14px", "letterSpacing": "0.04em", "fontWeight": "600" }],
        "headline-lg": ["22px", { "lineHeight": "28px", "letterSpacing": "-0.01em", "fontWeight": "600" }],
        "headline-sm": ["16px", { "lineHeight": "22px", "letterSpacing": "-0.005em", "fontWeight": "600" }],
        "code-sm": ["11px", { "lineHeight": "16px", "fontWeight": "400" }],
        "body-md": ["14px", { "lineHeight": "20px", "fontWeight": "400" }],
        "body-lg": ["16px", { "lineHeight": "24px", "fontWeight": "400" }],
        "code-md": ["13px", { "lineHeight": "20px", "fontWeight": "400" }],
        "headline-xl": ["30px", { "lineHeight": "36px", "letterSpacing": "-0.02em", "fontWeight": "700" }]
      },

      "keyframes": {
        "fade-in": {
          "0%": { "opacity": "0" },
          "100%": { "opacity": "1" }
        },
        "rise": {
          "0%": { "opacity": "0", "transform": "translateY(6px)" },
          "100%": { "opacity": "1", "transform": "translateY(0)" }
        },
        "pulse-soft": {
          "0%, 100%": { "opacity": "1" },
          "50%": { "opacity": ".45" }
        }
      },

      "animation": {
        "fade-in": "fade-in .18s ease-out both",
        "rise": "rise .22s cubic-bezier(.2,.7,.3,1) both",
        "pulse-soft": "pulse-soft 1.8s ease-in-out infinite"
      }
    }
  }
}
