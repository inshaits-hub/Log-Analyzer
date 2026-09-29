# Frontend

Everything the user sees in the browser. There is no build step and no
package manager here: the pages are plain HTML, styled with the Tailwind
Play CDN from a config file, and driven by classic (non-module) scripts
loaded in dependency order at the bottom of each page.

## Running it

Serve this folder over HTTP (opening the files with `file://` will break
the CORS requests to the Flask backend):

```bash
python3 -m http.server 8000
# then open http://127.0.0.1:8000/
```

The Flask backend must also be running for live data; see `../backend/`.

## Folder structure

```text
frontend/
├── README.md
├── index.html            # Overview: metrics, severity split, threats-per-hour, critical table
├── upload.html           # Drag-and-drop log upload
├── threats.html          # Threat list: filters, sort, pagination, export modal
├── threat-detail.html    # One threat expanded, with its matching log lines
├── log-events.html       # Raw parsed events: search, filters, pagination
├── css/
│   └── style.css         # Component layer: app shell, cards, tables, badges
├── assets/
│   ├── images/           # Raster/vector imagery (empty for now)
│   └── icons/
│       └── favicon.svg
└── js/
    ├── head.js           # Shared <head> loader - must be first in every page
    ├── config.js         # App-wide config, incl. the risk-score thresholds
    ├── tailwind-config.js# Design tokens (colours, type scale, spacing)
    ├── core/
    │   ├── dom.js        # Small DOM helpers (clear, message rows, disabled state)
    │   ├── format.js     # Number, timestamp and file-size formatting
    │   └── pagination.js # Page slicing + range text
    ├── services/
    │   ├── http-client.js     # fetch() wrapper + query-string building
    │   ├── api.js             # The real backend API, documented field by field
    │   ├── mock-api.js        # Same contract, fake data
    │   ├── mock-data.js       # The fake dataset
    │   ├── report-builder.js  # Client-side report composition
    │   └── download.js        # Blob download helpers
    ├── ui/
    │   ├── layout.js     # Rail + topbar shell, injected into #app-shell
    │   └── severity.js   # Severity classes, labels and badge builders
    └── pages/
        ├── overview.js
        ├── upload.js
        ├── threats.js
        ├── threat-detail.js
        └── log-events.js
```

## How a page is wired

1. `<script src="js/head.js">` is the **first** thing in `<head>`. It
   pulls in the Tailwind Play CDN, `tailwind-config.js`, `css/style.css`
   and the webfonts. It uses `document.write()`, so it only works when
   loaded synchronously from `<head>` — do not move it.
2. `<div id="app-shell"></div>` is the mount point for the shared header
   and nav, rendered by `js/ui/layout.js`.
3. `js/ui/layout.js` runs next; it needs no other module, so the nav
   appears immediately.
4. The remaining scripts are listed at the bottom of `<body>` in
   dependency order. They are plain scripts sharing a single
   `window.LogAnalyzer` namespace, so **order matters**:

   ```text
   config.js
   core/*
   ui/severity.js
   services/*
   pages/<this-page>.js
   ```

   `pages/*.js` runs immediately on load, so it must come last.

## Mock vs. real data

`js/config.js` has a `USE_MOCK` flag. With `USE_MOCK: true` (the current
default) every call goes to `mock-api.js` and the Flask backend is never
contacted, so the UI can be developed and demoed with no server. Set it
to `false` to talk to the real API at `BASE_URL`.

`?mock=empty` and `?mock=error` are frontend-only switches for previewing
the empty and error states; they are not API features.

## Design system

There is no component library. The look is built from three layers, in this
order of precedence: Tailwind utilities beat the component classes, which beat
the design tokens in `tailwind-config.js`.

1. **Tokens** — `js/tailwind-config.js`. Material 3 names are kept
   (`primary`, `surface-container`, `on-surface`, …) but the values are a
   neutral slate/blue ramp, plus a `--sev-*` severity ramp used by badges,
   meters, table dots and the chart so those can never drift apart.
2. **Components** — `css/style.css`. `.card`, `.stat`, `.dtable`, `.btn`,
   `.input`, `.badge`, `.alert`, `.empty`, `.page-head`, and the
   `.app-rail` / `.app-topbar` / `.app-content` shell. Prefer these over
   re-deriving the same utility string on every page.
3. **Utilities** — for one-off tweaks only.

### The app shell

`js/ui/layout.js` renders a fixed 248px dark rail plus a fixed topbar. The
page `<main class="app-content">` needs no wrapper: it clears the topbar with
`padding-top` and insets from the rail with `padding-left`, both in CSS. That
is deliberate — `layout.js` runs before the browser has parsed `<main>`, so
the layout must not depend on JS moving it.

Below 1024px the rail becomes a drawer opened by the topbar hamburger
(scrim click or `Escape` closes it) and the topbar shows pill navigation
instead.

### Adding a page

1. `<script src="js/head.js">` first in `<head>`, then
   `<div id="app-shell">` + `<script src="js/ui/layout.js">` + `<main class="app-content">`.
2. `data-page="<key>"` on `<body>`, and add that key to `ACTIVE_TAB_BY_PAGE`
   and `PAGE_META` in `layout.js`.
3. One visible `<h1 class="page-title">`; the topbar uses a plain div so the
   page keeps a single top-level heading.

### Severity colours

Never hardcode a severity hex. Use `.badge.sev-critical` (etc.) or
`ui/severity.js`, which resolves the `.sev-*` classes. The `*-text` shades are
darkened so labels clear 4.5:1 on white; the plain `sev-*` shades are for
fills and dots only.

## Notes for members working here

- Keep server code out of this folder — the Flask app lives in
  `../backend/`.
- Element IDs are the contract between a page and its page script. If you
  rename an ID, update `getElementById` in the matching `pages/*.js`.
- The risk-score thresholds live only in `config.js`. The backend clamps
  scores to 0–100 and flags `CRITICAL` at `>= 80`; do not hardcode a
  threshold in markup or a page script.
- Icons are the Material Symbols font, not image files — use
  `<span class="material-symbols-outlined" data-icon="name">name</span>`
  and pick the name from the [Material Symbols](https://fonts.google.com/icons)
  list.
