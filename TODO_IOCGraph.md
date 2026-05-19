# IOC Graph Page Improvements

## Plan Approved ✅

### 1. Light Mode Visualization
- [x] Add `useTheme` hook import
- [x] Create dual SVG grid patterns (`grid-dark` / `grid-light`)
- [x] Theme-aware background rect (white in light, #0D1420 in dark)
- [x] Theme-aware grid stroke color

### 2. Fluid Node Dragging
- [x] Remove `cancelAnimationFrame` from `handleNodeMouseDown`
- [x] Keep physics `tick()` running during drag via `fx/fy` pinning
- [x] On `mouseup`, release `fx/fy` to `null` instead of restarting limited sim

### 3. Hardcoded Color Fixes for Light Mode
- [x] Scan list unselected filename: `#fff` → `var(--text)`
- [x] Scan counter badge: use `var(--sub)` / `var(--muted)`
- [x] Node detail panel: `#1F2937`/`#374151` → `var(--card)`/`var(--border)`
- [x] Graph header edge count & legend email line: `#374151` → `var(--sub)`
- [x] IOC cards secondary text: `#9CA3AF`/`#4B5563` → `var(--sub)`

### 4. Export PNG Theme-Aware Background
- [x] `exportPNG` background fill adapts to current theme

### Followup
- [ ] Test light/dark mode switching
- [ ] Test fluid drag behavior

