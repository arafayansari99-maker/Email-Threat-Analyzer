import { useState, useEffect, useRef, useCallback } from 'react'
import { getHistory, getReport } from '../services/api'
import { useTheme } from '../hooks/useTheme'
import { useIsMobile } from '../hooks/useIsMobile'

const TYPE_ICONS = {
  url: '🔗', email: '📧', ip: '🌐', domain: '🌍', file: '📄', hash: '🔢',
}

const TYPE_LABELS = {
  url: 'URL', email: 'Email', ip: 'IP Address', domain: 'Domain', file: 'File', hash: 'Hash',
}

const RISK_COLOR = {
  // New per-IOC verdict labels from backend (primary)
  safe: '#10B981', threat: '#EF4444', suspicious: '#F59E0B',
  // Legacy labels (backward compat with old scan verdicts)
  high: '#EF4444', medium: '#F59E0B', low: '#10B981',
}
const getColor = (r) => RISK_COLOR[r] || '#64748B'

// ─── Graph data builder ─────────────────────────────────────────────────────
function buildGraph(iocs, scan) {
  if (!iocs.length) return { nodes: [], edges: [] }
  const W = 700, H = 480, cx = W / 2, cy = H / 2
  const startAngle = -Math.PI / 2
  const riskMap = { safe: 'low', suspicious: 'medium', malicious: 'high' }
  const centerRisk = riskMap[scan?.verdict] || 'high'
  const nodes = [
    { id: 'center', label: scan?.subject || scan?.filename || 'Email', type: 'file', risk: centerRisk,
      x: cx, y: cy, isCenter: true, vx: 0, vy: 0, fx: cx, fy: cy },
  ]
  const edges = []

  // Concentric rings — spread nodes across rings so they never overlap
  // Ring capacities: 8 → 12 → 16 → … (each ring fits 4 more)
  const ringRadii = [150, 250, 340, 420]
  const ringCaps  = [8, 12, 16, 20]
  let ringIdx = 0, slotInRing = 0, ringCount = 0

  // Pre-compute ring assignment so we know how many nodes are in each ring
  const ringAssign = []
  for (let i = 0; i < iocs.length; i++) {
    if (ringIdx >= ringRadii.length) ringIdx = ringRadii.length - 1
    ringAssign.push(ringIdx)
    slotInRing++
    if (slotInRing >= ringCaps[ringIdx] && ringIdx < ringRadii.length - 1) {
      ringIdx++; slotInRing = 0
    }
  }

  // Count per ring
  const perRing = ringAssign.reduce((acc, r) => { acc[r] = (acc[r] || 0) + 1; return acc }, {})

  const ringSlotUsed = {}
  iocs.forEach((ioc, i) => {
    const ri   = ringAssign[i]
    const R    = ringRadii[ri]
    const total = perRing[ri]
    const slot  = ringSlotUsed[ri] = (ringSlotUsed[ri] ?? 0)
    ringSlotUsed[ri]++
    const angle = startAngle + (slot / total) * 2 * Math.PI
    nodes.push({
      id: `ioc-${i}`, label: ioc.value, type: ioc.type, risk: ioc.risk,
      x: cx + R * Math.cos(angle),
      y: cy + R * Math.sin(angle),
      vx: 0, vy: 0, fx: null, fy: null, isCenter: false,
    })
    // Only spoke edges — no ring edges (ring edges cause nodes to cluster)
    edges.push({ from: 'center', to: `ioc-${i}` })
  })

  return { nodes, edges }
}

// ─── Force tick — strong repulsion keeps nodes separated ──────────────────
function tick(nodes, edges) {
  const n = nodes.length
  for (let i = 0; i < n; i++) {
    const node = nodes[i]
    if (node.fx != null) { node.x = node.fx; node.y = node.fy; continue }
    let fx = 0, fy = 0

    // Strong repulsion so nodes never overlap
    for (let j = 0; j < n; j++) {
      if (i === j) continue
      const dx = node.x - nodes[j].x, dy = node.y - nodes[j].y
      const dist2 = dx * dx + dy * dy || 1
      const dist  = Math.sqrt(dist2)
      const rep   = 4500 / dist2
      fx += (dx / dist) * rep
      fy += (dy / dist) * rep
    }

    // Spoke spring: each node wants to stay ~180px from center
    for (const edge of edges) {
      if (edge.from !== node.id && edge.to !== node.id) continue
      const other = nodes.find(nd => nd.id === (edge.from === node.id ? edge.to : edge.from))
      if (!other) continue
      const dx2 = other.x - node.x, dy2 = other.y - node.y
      const d = Math.sqrt(dx2 * dx2 + dy2 * dy2) || 1
      const k = (d - 180) * 0.018
      fx += (dx2 / d) * k
      fy += (dy2 / d) * k
    }

    // Gentle gravity toward canvas center so nodes don't drift off-screen
    fx += (350 - node.x) * 0.006
    fy += (240 - node.y) * 0.006

    node.vx = (node.vx + fx) * 0.76
    node.vy = (node.vy + fy) * 0.76
    const speed = Math.sqrt(node.vx * node.vx + node.vy * node.vy)
    if (speed > 10) { node.vx = node.vx / speed * 10; node.vy = node.vy / speed * 10 }
    node.x += node.vx
    node.y += node.vy
    node.x = Math.max(36, Math.min(664, node.x))
    node.y = Math.max(36, Math.min(444, node.y))
  }
}

// ─── Zoom helpers ────────────────────────────────────────────────────────────
function applyZoom(viewBox, scaleFactor, svgRef) {
  const vb = viewBox
  const newW = vb.w / scaleFactor
  const newH = vb.h / scaleFactor
  return { x: vb.x, y: vb.y, w: newW, h: newH }
}

// ─── Export helpers ─────────────────────────────────────────────────────────

// Replace all CSS custom property references with their computed values so the
// exported file is self-contained and renders correctly without the page styles.
function resolveCSSVars(str, isDark) {
  const cs = getComputedStyle(document.documentElement)
  const fallback = {
    '--border':  isDark ? '#1E293B' : '#E2E8F0',
    '--sub':     isDark ? '#64748B' : '#94A3B8',
    '--text':    isDark ? '#E2E8F0' : '#0F172A',
    '--cyan':    '#06B6D4',
    '--card':    isDark ? '#111827' : '#FFFFFF',
    '--surface': isDark ? '#0A1628' : '#F8FAFC',
    '--bg':      isDark ? '#0A0F1E' : '#F1F5F9',
    '--red':     '#EF4444',
    '--muted':   isDark ? '#1E293B' : '#F1F5F9',
  }
  return str.replace(/var\((--[\w-]+)\)/g, (_, v) => {
    const val = cs.getPropertyValue(v).trim()
    return val || fallback[v] || '#888'
  })
}

// Build a standalone, export-ready SVG string with:
//  - CSS variables resolved to concrete colors
//  - Embedded font-family style
//  - Title metadata
//  - Legend strip appended below the graph
function buildExportSVG(svgEl, isDark, selectedScan) {
  if (!svgEl) return null

  const GW = 700, GH = 480, LH = 56  // graph width/height + legend height
  const ns = 'http://www.w3.org/2000/svg'

  const clone = svgEl.cloneNode(true)
  clone.setAttribute('xmlns', ns)
  clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink')
  clone.setAttribute('viewBox', `0 0 ${GW} ${GH + LH}`)
  clone.setAttribute('width',  String(GW))
  clone.setAttribute('height', String(GH + LH))

  // Extend background rects to cover legend area
  clone.querySelectorAll(`rect[width="700"]`).forEach(r => r.setAttribute('height', String(GH + LH)))

  // Strip interactive-only artifacts
  clone.querySelectorAll('[data-ring]').forEach(el => el.remove())

  // Inject font style into <defs>
  let defs = clone.querySelector('defs')
  if (!defs) { defs = document.createElementNS(ns, 'defs'); clone.insertBefore(defs, clone.firstChild) }
  const styleEl = document.createElementNS(ns, 'style')
  styleEl.textContent = `text{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}`
  defs.appendChild(styleEl)

  // Title metadata
  const title = document.createElementNS(ns, 'title')
  title.textContent = `IOC Graph — ${selectedScan?.subject || selectedScan?.filename || 'scan'}`
  clone.insertBefore(title, clone.firstChild)

  // ── Legend strip ──────────────────────────────────────────────────────────
  const mk = (tag, attrs) => {
    const el = document.createElementNS(ns, tag)
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v))
    return el
  }
  const mkText = (x, y, text, attrs = {}) => {
    const el = mk('text', { x, y, ...attrs })
    el.textContent = text
    return el
  }

  const legendG = mk('g', { transform: `translate(0,${GH})` })
  const subColor  = isDark ? '#94A3B8' : '#64748B'
  const textColor = isDark ? '#CBD5E1' : '#334155'
  const borderCol = isDark ? '#1E293B' : '#E2E8F0'
  const bgColor   = isDark ? '#111827' : '#F8FAFC'

  legendG.appendChild(mk('rect', { width: GW, height: LH, fill: bgColor }))
  legendG.appendChild(mk('line', { x1: 0, y1: 0, x2: GW, y2: 0, stroke: borderCol, 'stroke-width': 1 }))
  legendG.appendChild(mkText(16, 18, 'LEGEND', { 'font-size': 9, 'font-weight': 700, fill: subColor, 'letter-spacing': '0.06em' }))

  // Risk dots
  const risks = [
    { label: 'High Risk',   color: '#EF4444', x: 16  },
    { label: 'Medium Risk', color: '#F59E0B', x: 112 },
    { label: 'Low Risk',    color: '#10B981', x: 215 },
  ]
  risks.forEach(r => {
    legendG.appendChild(mk('circle', { cx: r.x, cy: 38, r: 5, fill: r.color }))
    legendG.appendChild(mkText(r.x + 12, 42, r.label, { 'font-size': 10, fill: textColor }))
  })

  // Edge type indicators
  const ex = 330
  legendG.appendChild(mk('line', { x1: ex, y1: 38, x2: ex + 22, y2: 38, stroke: subColor, 'stroke-width': 2.5 }))
  legendG.appendChild(mkText(ex + 28, 42, 'Email → IOC', { 'font-size': 10, fill: textColor }))
  legendG.appendChild(mk('line', { x1: ex + 114, y1: 38, x2: ex + 136, y2: 38, stroke: subColor, 'stroke-width': 1.5, 'stroke-dasharray': '5 4' }))
  legendG.appendChild(mkText(ex + 142, 42, 'IOC link', { 'font-size': 10, fill: textColor }))

  // Filename watermark
  legendG.appendChild(mkText(GW - 16, 42, selectedScan?.subject || selectedScan?.filename || 'IOC Graph', {
    'font-size': 9, fill: isDark ? '#475569' : '#94A3B8', 'text-anchor': 'end',
  }))

  clone.appendChild(legendG)

  let str = new XMLSerializer().serializeToString(clone)
  return resolveCSSVars(str, isDark)
}

function exportSVG(svgEl, isDark, selectedScan) {
  const str = buildExportSVG(svgEl, isDark, selectedScan)
  if (!str) return
  const blob = new Blob([str], { type: 'image/svg+xml;charset=utf-8' })
  const url  = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  const exportName = (selectedScan?.subject || selectedScan?.filename || 'scan').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60)
  a.download = `IOC_Graph_${exportName}.svg`
  a.click()
  URL.revokeObjectURL(url)
}

function exportPNG(svgEl, isDark, selectedScan, onStart, onDone) {
  const str = buildExportSVG(svgEl, isDark, selectedScan)
  if (!str) return

  const SCALE = 2
  const GW = 700, GH = 480 + 56
  const canvas = document.createElement('canvas')
  canvas.width  = GW * SCALE
  canvas.height = GH * SCALE
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = isDark ? '#0D1420' : '#FFFFFF'
  ctx.fillRect(0, 0, canvas.width, canvas.height)

  const svgBlob = new Blob([str], { type: 'image/svg+xml;charset=utf-8' })
  const svgUrl  = URL.createObjectURL(svgBlob)

  onStart?.()
  const img = new Image()
  img.onload = () => {
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
    URL.revokeObjectURL(svgUrl)
    canvas.toBlob(blob => {
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `IOC_Graph_${(selectedScan?.subject || selectedScan?.filename || 'scan').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60)}.png`
      a.click()
      URL.revokeObjectURL(url)
      onDone?.()
    }, 'image/png')
  }
  img.onerror = () => { URL.revokeObjectURL(svgUrl); onDone?.() }
  img.src = svgUrl
}

// ─── Component ─────────────────────────────────────────────────────────────
export default function IOCGraph() {
  const { theme, isDark } = useTheme()
  const isMobile = useIsMobile()
  const [loading, setLoading] = useState(true)
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [graph, setGraph] = useState({ nodes: [], edges: [] })
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 700, h: 480 })
  const [exporting, setExporting] = useState(false)
  const svgRef = useRef(null)
  const animRef = useRef(null)
  const viewBoxRef = useRef({ x: 0, y: 0, w: 700, h: 480 })
  const isZooming = useRef(false)
  const lastPinch = useRef(null)
  const draggedNodeRef = useRef(null)
  // Use refs so animation loop always sees the live graph, never a stale snapshot
  const graphRef = useRef({ nodes: [], edges: [] })

  useEffect(() => { loadScans(1) }, [])

  const loadScans = async (page = 1) => {
    if (page === 1) setLoading(true)
    try {
      const { data } = await getHistory(page, 100)
      const records = data?.records || []
      const total   = data?.total   ?? records.length
      const pages   = data?.pages   ?? 1
      setScans(prev => page === 1 ? records : [...prev, ...records])
      setTotalScans(total)
      setHasMore(page < pages)
      setScanPage(page)
      if (page === 1 && records.length > 0) setSelectedScan(records[0])
    } catch (err) { console.error(err) } finally { if (page === 1) setLoading(false) }
  }

  const [reportLoading, setReportLoading] = useState(false)
  const [totalScans, setTotalScans] = useState(0)
  const [scanPage, setScanPage] = useState(1)
  const [hasMore, setHasMore] = useState(false)

  // ── Risk helpers (used inside component) ──────────────────────────────────
const _KNOWN_SAFE = new Set([
  'google.com','accounts.google.com','github.com','microsoft.com',
  'live.com','outlook.com','apple.com','amazon.com','paypal.com',
  'stripe.com','shopify.com','slack.com','zoom.us','dropbox.com',
  'linkedin.com','twitter.com','x.com','facebook.com','instagram.com',
])
const _PRIVATE_IP_RE = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)/
const _MALICIOUS_EXT = new Set([
  '.exe','.bat','.cmd','.ps1','.vbs','.wsf','.hta','.scr',
  '.com','.pif','.lnk','.js','.jar','.msi','.dll','.sys',
])

function _domainIsSafe(domain) {
  if (!domain) return false
  return _KNOWN_SAFE.has(domain) || _KNOWN_SAFE.has(domain.split('.').slice(-2).join('.'))
}
function _ipIsThreat(ip)    { return _PRIVATE_IP_RE.test(ip) }
function _hashIsThreat(fn)  {
  if (!fn) return false
  const l = fn.toLowerCase()
  return [..._MALICIOUS_EXT].some(e => l.endsWith(e))
}
function _urlIsThreat(url, ua) {
  if ((ua?.high_risk || []).includes(url)) return true
  if ((ua?.suspicious_urls || []).includes(url)) return true
  if ((ua?.shortener_urls || []).includes(url)) return true
  // url_analysis.analyses is the primary URL data store — urls[] is often empty
  const analyses = ua?.analyses || []
  const f = analyses.find(u => typeof u === 'object' && u.url === url)
  if (f) return f.verdict === 'threat' || f.verdict === 'suspicious'
  // Fallback to top-level urls[] (may be empty)
  const fb = (ua?.urls || []).find(u => typeof u === 'object' && u.url === url)
  return fb?.verdict === 'threat'
}
function _urlIsSafe(url, ua) {
  if ((ua?.high_risk || []).includes(url)) return false
  if ((ua?.suspicious_urls || []).includes(url)) return false
  if ((ua?.shortener_urls || []).includes(url)) return false
  const analyses = ua?.analyses || []
  const f = analyses.find(u => typeof u === 'object' && u.url === url)
  if (f) return f.verdict === 'safe'
  const fb = (ua?.urls || []).find(u => typeof u === 'object' && u.url === url)
  if (fb?.verdict === 'safe') return true
  return !!(f || (ua?.all_urls || []).includes(url))
}
function _domainRisk(domain, auth) {
  if (!domain) return 'safe'
  if (_domainIsSafe(domain)) return 'safe'
  const spf   = auth?.spf_status   || auth?.spf
  const dkim  = auth?.dkim_status  || auth?.dkim_present
  const dmarc = auth?.dmarc_status || auth?.dmarc
  const authed = [spf, dkim, dmarc].some(v => v === true || v === 'pass')
  return authed ? 'safe' : 'threat'
}
function _ipRisk(ip)        { return _ipIsThreat(ip) ? 'threat' : 'safe' }
function _hashRisk(sha, attachments) {
  const fn = (attachments || []).find(a => a.sha256 === sha)?.filename || ''
  return _hashIsThreat(fn) ? 'threat' : 'safe'
}

// ── Extract IOCs from a loaded report ─────────────────────────────────────
function extractIOCs(report) {
  const seen = new Set()
  const iocs = []
  const ua = report.url_analysis || {}
  const auth = report.authentication || {}

  const push = (type, value, risk) => {
    if (!value || seen.has(value)) return
    seen.add(value)
    iocs.push({ type, value, risk })
  }

  push('email',  report.meta?.sender_email || '',  'safe')
  push('domain', report.meta?.sender_domain || '', _domainRisk(report.meta?.sender_domain || '', auth))

  const allUrls = new Set([
    ...(ua.high_risk || []),
    ...(ua.suspicious_urls || []),
    ...(ua.shortener_urls || []),
    ...(ua.all_urls || []),
    // url_analysis.urls is the per-URL result array (each entry has url + verdict fields)
    ...(ua.urls || []).map(u => typeof u === 'object' ? u.url : u),
  ])
  for (const url of [...allUrls].slice(0, 8)) {
    push('url', url, _urlIsThreat(url, ua) ? 'threat' : 'safe')
  }

  // Pull domain-type IOCs from report.iocs (backend already extracts these)
  for (const ioc of (report.iocs || []).filter(i => i.type === 'domain')) {
    push('domain', ioc.value, _domainRisk(ioc.value, auth))
  }

  for (const ip of (report.iocs || []).filter(i => i.type === 'ip').map(i => i.value)) {
    push('ip', ip, _ipRisk(ip))
  }

  for (const ioc of (report.iocs || []).filter(i => i.type === 'hash')) {
    push('hash', ioc.value, _hashRisk(ioc.value, report.attachment_analysis?.attachments))
  }

  // Also pull url-type IOCs from report.iocs (backend deduplicates these)
  for (const ioc of (report.iocs || []).filter(i => i.type === 'url')) {
    push('url', ioc.value, _urlIsThreat(ioc.value, ua) ? 'threat' : 'safe')
  }

  return iocs
}

  useEffect(() => {
    if (!selectedScan) {
      setGraph({ nodes: [], edges: [] })
      graphRef.current = { nodes: [], edges: [] }
      return
    }

    let cancelled = false
    setReportLoading(true)

    getReport(selectedScan.scan_id)
      .then(({ data: report }) => {
        if (cancelled) return
        const iocs = extractIOCs(report)
        const g = buildGraph(iocs, selectedScan)
        setGraph({ ...g })
        graphRef.current = g
        viewBoxRef.current = { x: 0, y: 0, w: 700, h: 480 }
        setViewBox({ x: 0, y: 0, w: 700, h: 480 })
      })
      .catch(() => {
        if (cancelled) return
        setGraph({ nodes: [], edges: [] })
        graphRef.current = { nodes: [], edges: [] }
      })
      .finally(() => { if (!cancelled) setReportLoading(false) })

    return () => { cancelled = true }
  }, [selectedScan])

  // ── Animation loop — reads from graphRef so no stale-closure bug on scan switch ─
  useEffect(() => {
    if (!svgRef.current) return
    const svg = svgRef.current
    let lastTime = 0
    const minDelta = 1000 / 60  // cap at 60 fps

    const animate = (time) => {
      if (time - lastTime >= minDelta) {
        lastTime = time
        const { nodes, edges } = graphRef.current
        if (!nodes.length) return
        tick(nodes, edges)
        // Update node group transforms — all children move as one unit
        nodes.forEach(node => {
          const g = svg.querySelector(`[data-node-id="${CSS.escape(node.id)}"]`)
          if (g) g.setAttribute('transform', `translate(${node.x},${node.y})`)
        })
        // Update edges — use live node positions from graphRef
        edges.forEach((edge, i) => {
          const { nodes: liveNodes } = graphRef.current
          const from = liveNodes.find(n => n.id === edge.from)
          const to = liveNodes.find(n => n.id === edge.to)
          if (!from || !to) return
          const line = svg.querySelector(`[data-edge-id="${i}"]`)
          if (line) {
            line.setAttribute('x1', from.x); line.setAttribute('y1', from.y)
            line.setAttribute('x2', to.x); line.setAttribute('y2', to.y)
          }
        })
      }
      animRef.current = requestAnimationFrame(animate)
    }
    animRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animRef.current)
  }, [selectedScan])

  // ── Drag handlers ────────────────────────────────────────────────────────
  const handleNodeMouseDown = useCallback((e, node) => {
    e.stopPropagation()
    e.preventDefault()
    draggedNodeRef.current = node
    const svg = svgRef.current
    if (!svg) return
    const pt = svg.createSVGPoint()
    pt.x = e.clientX; pt.y = e.clientY
    const svgP = pt.matrixTransform(svg.getScreenCTM().inverse())
    node.fx = svgP.x; node.fy = svgP.y
    node.x = svgP.x; node.y = svgP.y

    // Pre-compute which edges are connected to this node so we can drag those neighbours
    const { edges } = graphRef.current
    const connectedNodeIds = new Set(['center']) // always keep center pinned
    edges.forEach(edge => {
      if (edge.from === node.id || edge.to === node.id) {
        connectedNodeIds.add(edge.from === node.id ? edge.to : edge.from)
      }
    })

    const onMove = (ev) => {
      const pt2 = svg.createSVGPoint()
      pt2.x = ev.clientX; pt2.y = ev.clientY
      const svgP2 = pt2.matrixTransform(svg.getScreenCTM().inverse())
      const dx = svgP2.x - svgP.x
      const dy = svgP2.y - svgP.y
      svgP.x = svgP2.x; svgP.y = svgP2.y
      node.fx = svgP2.x; node.fy = svgP2.y
      node.x = svgP2.x; node.y = svgP2.y

      // Move all connected nodes along with the dragged node — group transform = single update
      connectedNodeIds.forEach(cid => {
        if (cid === node.id) return
        const { nodes } = graphRef.current
        const cn = nodes.find(n => n.id === cid)
        if (!cn) return
        cn.x += dx; cn.y += dy
        if (cn.fx != null) { cn.fx += dx; cn.fy += dy }
        // Update the group transform so icon + label + circles all move as one unit
        const el = svg.querySelector(`[data-node-id="${CSS.escape(cn.id)}"]`)
        if (el) el.setAttribute('transform', `translate(${cn.x},${cn.y})`)
      })

      // Update the dragged node group transform
      const el = svg.querySelector(`[data-node-id="${CSS.escape(node.id)}"]`)
      if (el) el.setAttribute('transform', `translate(${svgP2.x},${svgP2.y})`)

      // Update all edges
      const { nodes, edges: liveEdges } = graphRef.current
      liveEdges.forEach((edge, i) => {
        const from = nodes.find(n => n.id === edge.from)
        const to = nodes.find(n => n.id === edge.to)
        if (!from || !to) return
        const line = svg.querySelector(`[data-edge-id="${i}"]`)
        if (line) {
          line.setAttribute('x1', from.x); line.setAttribute('y1', from.y)
          line.setAttribute('x2', to.x); line.setAttribute('y2', to.y)
        }
      })
    }

    const onUp = () => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      node.fx = null; node.fy = null
      draggedNodeRef.current = null
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [])

  // ── Zoom handlers ────────────────────────────────────────────────────────
  // Must be attached imperatively with { passive: false } — React's onWheel
  // registers a passive listener since React 17, making preventDefault() a no-op.
  const handleWheel = useCallback((e) => {
    e.preventDefault()
    const svg = svgRef.current
    if (!svg) return
    const factor = e.deltaY < 0 ? 0.85 : 1.18
    const vb = viewBoxRef.current
    // Get cursor position in SVG coordinates before zoom
    const rect = svg.getBoundingClientRect()
    const cursorX = (e.clientX - rect.left) / rect.width * vb.w + vb.x
    const cursorY = (e.clientY - rect.top) / rect.height * vb.h + vb.y
    const newW = Math.max(200, Math.min(1400, vb.w * factor))
    const newH = Math.max(137, Math.min(960, vb.h * factor))
    // Re-centre zoom toward cursor
    const newX = cursorX - (cursorX - vb.x) * (newW / vb.w)
    const newY = cursorY - (cursorY - vb.y) * (newH / vb.h)
    viewBoxRef.current = { x: newX, y: newY, w: newW, h: newH }
    setViewBox({ x: newX, y: newY, w: newW, h: newH })
  }, [])

  // Attach wheel listener with passive:false so preventDefault() actually works
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    svg.addEventListener('wheel', handleWheel, { passive: false })
    return () => svg.removeEventListener('wheel', handleWheel)
  }, [handleWheel])

  const handleSVGMouseDown = (e) => {
    if (e.target === svgRef.current || e.target.tagName === 'svg') {
      setSelectedNode(null)
      isZooming.current = false
    }
  }

  const handleZoomIn = () => {
    const vb = viewBoxRef.current
    const newW = Math.max(200, vb.w * 0.7)
    const newH = Math.max(137, vb.h * 0.7)
    const cx = vb.x + vb.w / 2, cy = vb.y + vb.h / 2
    viewBoxRef.current = { x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH }
    setViewBox({ x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH })
  }

  const handleZoomOut = () => {
    const vb = viewBoxRef.current
    const newW = Math.min(1400, vb.w * 1.43)
    const newH = Math.min(960, vb.h * 1.43)
    const cx = vb.x + vb.w / 2, cy = vb.y + vb.h / 2
    viewBoxRef.current = { x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH }
    setViewBox({ x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH })
  }

  const handleReset = () => {
    viewBoxRef.current = { x: 0, y: 0, w: 700, h: 480 }
    setViewBox({ x: 0, y: 0, w: 700, h: 480 })
  }

  // ── Render ───────────────────────────────────────────────────────────────
  const vb = `0 0 700 480`

  return (
    <div style={{ padding: isMobile ? '1rem' : '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>IOC Graph</h1>
          <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Interactive force-directed threat indicator visualization</p>
        </div>
        {graph.nodes.length > 0 && (
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button onClick={handleZoomIn} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid var(--border)',
              background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Zoom In</button>
            <button onClick={handleZoomOut} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid var(--border)',
              background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Zoom Out</button>
            <button onClick={handleReset} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid var(--border)',
              background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Reset</button>
            <button onClick={() => exportSVG(svgRef.current, isDark, selectedScan)} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid #10B981',
              background: 'rgba(16,185,129,0.1)', color: '#10B981', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Export SVG</button>
            <button
              disabled={exporting}
              onClick={() => exportPNG(svgRef.current, isDark, selectedScan, () => setExporting(true), () => setExporting(false))}
              style={{
                padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid #06B6D4',
                background: 'rgba(6,182,212,0.1)', color: '#06B6D4', cursor: exporting ? 'not-allowed' : 'pointer',
                fontSize: '0.875rem', fontWeight: 600, opacity: exporting ? 0.6 : 1,
              }}
            >{exporting ? 'Exporting…' : 'Export PNG'}</button>
          </div>
        )}
      </div>

      {loading ? (
        <div style={{ display: 'flex', gap: '1.5rem', flexDirection: 'column' }}>
          <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', width: 280, flexShrink: 0, overflow: 'hidden' }}>
              {[1,2,3,4,5].map(i => (
                <div key={i} style={{ padding: '0.875rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <div className="skeleton" style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div className="skeleton skeleton-text" style={{ width: '70%', marginBottom: '0.25rem' }} />
                    <div className="skeleton skeleton-text" style={{ width: '40%', height: 10 }} />
                  </div>
                </div>
              ))}
            </div>
            <div className="skeleton" style={{ flex: 1, minHeight: 420, borderRadius: 12 }} />
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: isMobile ? 'column' : 'row', gap: '1.5rem' }}>
          {/* ── Scan List ── */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', height: 'fit-content', width: isMobile ? '100%' : 280, flexShrink: 0 }}>
            <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, margin: 0 }}>Scans</h2>
              <span style={{ fontSize: '0.6875rem', color: 'var(--sub)', background: 'var(--muted)', padding: '0.125rem 0.4rem', borderRadius: 4 }}>{totalScans || scans.length}</span>
            </div>
            <div style={{ maxHeight: 480, overflowY: 'auto' }}>
              {scans.length === 0 ? (
                <p style={{ color: '#64748B', padding: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>No scans available.</p>
              ) : (
                <>
                  {scans.map(scan => (
                    <button key={scan.scan_id} onClick={() => setSelectedScan(scan)} style={{
                      width: '100%', padding: '0.875rem 1rem', border: 'none', borderBottom: '1px solid var(--border)',
                      background: selectedScan?.scan_id === scan.scan_id ? '#06B6D418' : 'transparent',
                      cursor: 'pointer', textAlign: 'left', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      transition: 'background 0.15s',
                    }}>
                      <span style={{
                        color: selectedScan?.scan_id === scan.scan_id ? 'var(--cyan)' : 'var(--text)',
                        fontSize: '0.8125rem', flex: 1, marginRight: '0.5rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>{scan.subject || scan.filename}</span>
                      <span style={{
                        padding: '0.125rem 0.375rem', borderRadius: 4, fontSize: '0.625rem', textTransform: 'uppercase', flexShrink: 0,
                        background: scan.verdict === 'malicious' ? '#EF444420' : scan.verdict === 'suspicious' ? '#F59E0B20' : '#10B98120',
                        color: scan.verdict === 'malicious' ? '#EF4444' : scan.verdict === 'suspicious' ? '#F59E0B' : '#10B981',
                      }}>{scan.verdict}</span>
                    </button>
                  ))}
                  {hasMore && (
                    <button
                      onClick={() => loadScans(scanPage + 1)}
                      style={{ width: '100%', padding: '0.75rem', border: 'none', borderTop: '1px solid var(--border)', background: 'transparent', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600 }}
                    >
                      Load more ({totalScans - scans.length} remaining)
                    </button>
                  )}
                </>
              )}
            </div>
          </div>

          {/* ── Graph Panel ── */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Graph header */}
            {selectedScan && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                {selectedScan.source === 'imap' && (
                  <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, background: '#06B6D420', color: '#06B6D4', fontSize: '0.625rem', fontWeight: 700, textTransform: 'uppercase', flexShrink: 0 }}>IMAP</span>
                )}
                <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, margin: 0 }}>
                  {selectedScan.subject || selectedScan.filename}
                </h2>
                <span style={{
                  padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', textTransform: 'uppercase', fontWeight: 700,
                  background: selectedScan.verdict === 'malicious' ? '#EF444420' : selectedScan.verdict === 'suspicious' ? '#F59E0B20' : '#10B98120',
                  color: selectedScan.verdict === 'malicious' ? '#EF4444' : selectedScan.verdict === 'suspicious' ? '#F59E0B' : '#10B981',
                }}>{selectedScan.verdict}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--sub)', marginLeft: 'auto' }}>
                  {graph.nodes.length > 0 && `${graph.nodes.length - 1} nodes · ${graph.edges.length} edges`}
                </span>
              </div>
            )}

            {/* SVG Graph */}
            {reportLoading ? (
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '3rem' }}>
                <div style={{ width: 36, height: 36, border: '3px solid var(--border)', borderTopColor: 'var(--cyan)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', marginBottom: '0.75rem' }} />
                <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>Loading IOC data…</p>
              </div>
            ) : graph.nodes.length === 0 ? (
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: isMobile ? '1rem' : '1.5rem' }}>
                <p style={{ color: '#64748B', fontSize: '0.9rem' }}>{selectedScan ? 'No indicators of compromise found in this email.' : 'Select a scan to load the threat graph'}</p>
              </div>
            ) : (
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', position: 'relative' }}>
                <svg
                  id="ioc-svg"
                  ref={svgRef}
                  width="100%"
                  height={isMobile ? 300 : 480}
                  viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
                  onMouseDown={handleSVGMouseDown}
                  style={{ display: 'block', cursor: 'default', userSelect: 'none' }}
                >
                  <defs>
                    <filter id="glow">
                      <feGaussianBlur stdDeviation="4" result="coloredBlur" />
                      <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
                    </filter>
                    <filter id="shadow">
                      <feDropShadow dx="0" dy="2" stdDeviation="4" floodColor="rgba(0,0,0,0.5)" />
                    </filter>
                  </defs>

                  {/* Grid background — dual patterns so SVG export preserves theme */}
                  <pattern id="grid-dark" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="var(--border)" strokeWidth="0.5" opacity="0.6" />
                  </pattern>
                  <pattern id="grid-light" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#000000" strokeWidth="0.5" opacity="0.15" />
                  </pattern>
                  <rect width="700" height="480" fill={isDark ? '#0D1420' : '#FFFFFF'} />
                  <rect width="700" height="480" fill={isDark ? 'url(#grid-dark)' : 'url(#grid-light)'} />

                  {/* Edges */}
                  {graph.edges.map((edge, i) => {
                    const from = graph.nodes.find(n => n.id === edge.from)
                    const to = graph.nodes.find(n => n.id === edge.to)
                    if (!from || !to) return null
                    const isIOCEdge = !from.isCenter && !to.isCenter
                    return (
                      <line
                        key={i}
                        data-edge-id={i}
                        x1={from.x} y1={from.y}
                        x2={to.x} y2={to.y}
                        stroke={isIOCEdge ? 'var(--border)' : 'var(--sub)'}
                        strokeWidth={isIOCEdge ? 1.5 : 2.5}
                        strokeDasharray={isIOCEdge ? '5 4' : '0'}
                        opacity={0.9}
                      />
                    )
                  })}

                  {/* Nodes — each group uses transform so icon+label+circles always move as one unit */}
                  {graph.nodes.map(node => {
                    const color = getColor(node.risk)
                    const isHovered = hoveredNode === node.id
                    const isSelected = selectedNode?.id === node.id
                    const radius = node.isCenter ? 30 : 22
                    return (
                      <g key={node.id} data-node-id={node.id} transform={`translate(${node.x},${node.y})`}>
                        {/* Glow */}
                        <circle cx={0} cy={0} r={radius + 10}
                          fill="none" stroke={color} strokeWidth={2}
                          opacity={isHovered || isSelected ? 0.5 : 0.12}
                          filter={isHovered || isSelected ? 'url(#glow)' : undefined}
                          style={{ transition: 'opacity 0.2s' }}
                        />
                        {/* Node body */}
                        <circle
                          cx={0} cy={0} r={radius}
                          data-node-id={node.id}
                          fill={node.isCenter ? (isDark ? '#111827' : '#F3F4F6') : color + '22'}
                          stroke={color}
                          strokeWidth={node.isCenter ? 3 : 2.5}
                          filter="url(#shadow)"
                          style={{ cursor: 'grab' }}
                          onMouseEnter={() => setHoveredNode(node.id)}
                          onMouseLeave={() => setHoveredNode(null)}
                          onMouseDown={(e) => handleNodeMouseDown(e, node)}
                          onClick={(e) => { e.stopPropagation(); setSelectedNode(node) }}
                        />
                        {/* Icon */}
                        <text x={0} y={1} textAnchor="middle" dominantBaseline="middle"
                          style={{ fontSize: node.isCenter ? 20 : 14, pointerEvents: 'none' }}>
                          {TYPE_ICONS[node.type] || '📄'}
                        </text>
                        {/* Label */}
                        <text x={0} y={radius + 14} textAnchor="middle"
                          style={{
                            fontSize: node.isCenter ? 8 : 7.5, fill: node.isCenter ? (isDark ? '#06B6D4' : '#0891B2') : (isDark ? color : color),
                            fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', pointerEvents: 'none',
                          }}>
                          {node.isCenter ? 'EMAIL' : node.type}
                        </text>
                        {/* Selected ring */}
                        {isSelected && (
                          <circle cx={0} cy={0} r={radius + 4}
                            data-ring
                            fill="none" stroke={color} strokeWidth={1.5} strokeDasharray="4 2" opacity={0.7} />
                        )}
                      </g>
                    )
                  })}
                </svg>

                {/* Node detail panel */}
                {selectedNode && (
                  <div style={{
                    position: 'absolute', top: '1rem', right: '1rem',
                    background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10,
                    padding: '1rem', width: isMobile ? '100%' : 220, maxWidth: '90vw', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.4)' : '0 4px 12px rgba(0,0,0,0.1)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.625rem' }}>
                      <span style={{ fontSize: '1.25rem' }}>{TYPE_ICONS[selectedNode.type] || '📄'}</span>
                      <button onClick={() => setSelectedNode(null)} style={{
                        background: 'none', border: 'none', color: 'var(--sub)', cursor: 'pointer', fontSize: '1rem',
                      }}>✕</button>
                    </div>
                    <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem', textTransform: 'capitalize' }}>
                      {TYPE_LABELS[selectedNode.type] || selectedNode.type}
                    </p>
                    <p style={{ color: 'var(--sub)', fontSize: '0.7rem', fontFamily: 'monospace', wordBreak: 'break-all', marginBottom: '0.625rem', lineHeight: 1.4 }}>
                      {selectedNode.label}
                    </p>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                      <span style={{
                        padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase',
                        background: getColor(selectedNode.risk) + '22', color: getColor(selectedNode.risk),
                      }}>
                        {selectedNode.risk} risk
                      </span>
                    </div>
                    <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginTop: '0.5rem' }}>
                      Drag node to reposition · Scroll to zoom
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Legend */}
            {graph.nodes.length > 0 && (
              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', alignItems: 'center', padding: '0.75rem 1rem', background: 'var(--card)', borderRadius: 8, border: '1px solid var(--border)' }}>
                {[{ l: 'High Risk', c: '#EF4444' }, { l: 'Medium Risk', c: '#F59E0B' }, { l: 'Low Risk', c: '#10B981' }].map(x => (
                  <div key={x.l} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: x.c }} />
                    <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>{x.l}</span>
                  </div>
                ))}
                <div style={{ width: 20, height: 2, background: 'var(--border)' }} />
                <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>→ Email</span>
                <div style={{ width: 20, height: 1, borderTop: '1px dashed var(--border)' }} />
                <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>IOC link</span>
              </div>
            )}

            {/* IOC cards */}
            {graph.nodes.length > 0 && (
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fill, minmax(${isMobile ? '160px' : '210px'}, 1fr))`, gap: '0.625rem' }}>
                {graph.nodes.filter(n => !n.isCenter).map(node => (
                  <div key={node.id} onClick={() => setSelectedNode(node)} style={{
                    background: 'var(--card)', borderRadius: 10, border: '1px solid var(--border)',
                    padding: '0.75rem', cursor: 'pointer', borderLeft: `3px solid ${getColor(node.risk)}`,
                    transition: 'all 0.15s',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.3rem' }}>
                      <span style={{ fontSize: '0.9rem' }}>{TYPE_ICONS[node.type] || '📄'}</span>
                      <span style={{
                        fontSize: '0.625rem', fontWeight: 700, padding: '0.1rem 0.375rem', borderRadius: 4,
                        textTransform: 'uppercase', background: getColor(node.risk) + '22', color: getColor(node.risk),
                      }}>{node.risk}</span>
                    </div>
                    <p style={{ color: 'var(--text)', fontSize: '0.75rem', fontWeight: 500, marginBottom: '0.15rem', textTransform: 'capitalize' }}>
                      {TYPE_LABELS[node.type] || node.type}
                    </p>
                    <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', fontFamily: 'monospace', wordBreak: 'break-all', margin: 0 }}>
                      {node.label}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}