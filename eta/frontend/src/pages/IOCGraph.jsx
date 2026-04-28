import { useState, useEffect, useRef, useCallback } from 'react'
import { getHistory } from '../services/api'
import { useTheme } from '../hooks/useTheme'

const TYPE_ICONS = {
  url: '🔗', email: '📧', ip: '🌐', domain: '🌍', file: '📄', hash: '🔢',
}

const TYPE_LABELS = {
  url: 'URL', email: 'Email', ip: 'IP Address', domain: 'Domain', file: 'File', hash: 'Hash',
}

const RISK_COLOR = { high: '#EF4444', medium: '#F59E0B', low: '#10B981' }
const getColor = (r) => RISK_COLOR[r] || '#64748B'

// ─── Graph data builder ─────────────────────────────────────────────────────
function buildGraph(iocs, scan) {
  if (!iocs.length) return { nodes: [], edges: [] }
  const W = 700, H = 480, cx = W / 2, cy = H / 2, R = Math.min(W, H) * 0.30
  const startAngle = -Math.PI / 2
  // Derive center risk from scan verdict — safe → low, suspicious → medium, malicious → high
  const riskMap = { safe: 'low', suspicious: 'medium', malicious: 'high' }
  const centerRisk = riskMap[scan?.verdict] || 'high'
  const nodes = [
    { id: 'center', label: scan?.filename || 'Email File', type: 'file', risk: centerRisk, x: cx, y: cy, isCenter: true, vx: 0, vy: 0, fx: cx, fy: cy },
  ]
  const edges = []
  iocs.forEach((ioc, i) => {
    const angle = startAngle + (i / iocs.length) * 2 * Math.PI
    nodes.push({
      id: `${ioc.type}-${i}`, label: ioc.value, type: ioc.type, risk: ioc.risk,
      x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle),
      vx: 0, vy: 0, fx: null, fy: null, isCenter: false,
    })
    edges.push({ from: 'center', to: `${ioc.type}-${i}` })
  })
  if (iocs.length > 1) {
    for (let i = 0; i < iocs.length; i++) {
      edges.push({ from: `${iocs[i].type}-${i}`, to: `${iocs[(i + 1) % iocs.length].type}-${(i + 1) % iocs.length}` })
    }
  }
  return { nodes, edges }
}

// ─── Simple force tick ─────────────────────────────────────────────────────
function tick(nodes, edges) {
  const n = nodes.length
  for (let i = 0; i < n; i++) {
    const node = nodes[i]
    if (node.fx != null) { node.x = node.fx; node.y = node.fy; continue }
    let fx = 0, fy = 0
    // Repulsion between all nodes
    for (let j = 0; j < n; j++) {
      if (i === j) continue
      const other = nodes[j]
      const dx = node.x - other.x, dy = node.y - other.y
      const dist = Math.sqrt(dx * dx + dy * dy) || 1
      const repulse = 1200 / (dist * dist)
      fx += (dx / dist) * repulse
      fy += (dy / dist) * repulse
    }
    // Attraction to center
    const dx = 350 - node.x, dy = 240 - node.y
    fx += dx * 0.01
    fy += dy * 0.01
    // Edge spring
    edges.forEach(edge => {
      const from = nodes.find(n => n.id === edge.from)
      const to = nodes.find(n => n.id === edge.to)
      if (!from || !to) return
      const isIOCEdge = !from.isCenter && !to.isCenter
      const dist2 = isIOCEdge ? 150 : 200
      const dx2 = to.x - from.x, dy2 = to.y - from.y
      const distC = Math.sqrt(dx2 * dx2 + dy2 * dy2) || 1
      if (nodes[i].id === from.id) {
        fx += (dx2 / distC) * (distC - dist2) * 0.04
        fy += (dy2 / distC) * (distC - dist2) * 0.04
      } else if (nodes[i].id === to.id) {
        fx -= (dx2 / distC) * (distC - dist2) * 0.04
        fy -= (dy2 / distC) * (distC - dist2) * 0.04
      }
    })
    // Dampen
    node.vx = (node.vx + fx) * 0.8
    node.vy = (node.vy + fy) * 0.8
    // Apply velocity with cap
    const speed = Math.sqrt(node.vx * node.vx + node.vy * node.vy)
    if (speed > 8) { node.vx = (node.vx / speed) * 8; node.vy = (node.vy / speed) * 8 }
    node.x += node.vx
    node.y += node.vy
    // Bounds
    node.x = Math.max(40, Math.min(660, node.x))
    node.y = Math.max(40, Math.min(440, node.y))
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
function exportSVG(graph, selectedScan) {
  const svgEl = document.getElementById('ioc-svg')
  if (!svgEl) return
  const clone = svgEl.cloneNode(true)
  const styles = `<style>text{font-family:sans-serif} circle{cursor:pointer}</style>`
  clone.innerHTML = styles + clone.innerHTML
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
  const blob = new Blob([clone.outerHTML], { type: 'image/svg+xml' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `IOC_Graph_${selectedScan?.filename?.replace(/\.[^/.]+$/, '') || 'scan'}.svg`
  a.click()
  URL.revokeObjectURL(url)
}

function exportPNG(viewBoxRef) {
  const svgEl = document.getElementById('ioc-svg')
  if (!svgEl) return
  const vb = viewBoxRef.current
  const canvas = document.createElement('canvas')
  canvas.width = 1400
  canvas.height = 960
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = '#0D1420'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  const svgData = new XMLSerializer().serializeToString(svgEl)
  const img = new Image()
  img.onload = () => {
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
    canvas.toBlob(blob => {
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `IOC_Graph.png`
      a.click()
      URL.revokeObjectURL(url)
    })
  }
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svgData)
}

// ─── Component ─────────────────────────────────────────────────────────────
export default function IOCGraph() {
  const { theme, isDark } = useTheme()
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

  useEffect(() => { loadScans() }, [])

  const loadScans = async () => {
    try {
      const { data } = await getHistory(1, 20)
      const records = data?.records || data?.data?.records || []
      setScans(records)
      if (records.length > 0) setSelectedScan(records[0])
    } catch (err) { console.error(err) } finally { setLoading(false) }
  }

  const getIOCsForScan = (scan) => {
    if (!scan) return []
    if (scan.verdict === 'malicious') {
      return [
        { type: 'url', value: 'hxxp://phishing-login.com/auth', risk: 'high' },
        { type: 'email', value: 'attacker@darkmail.ru', risk: 'high' },
        { type: 'ip', value: '185.220.101.42', risk: 'high' },
        { type: 'domain', value: 'malicious-cdn.io', risk: 'high' },
        { type: 'hash', value: 'a3f5c8...e91d2', risk: 'medium' },
        { type: 'url', value: 'http://redirect.bit.ly/pay', risk: 'medium' },
        { type: 'ip', value: '91.108.56.180', risk: 'high' },
        { type: 'domain', value: 'evil-tracker.net', risk: 'high' },
      ]
    } else if (scan.verdict === 'suspicious') {
      return [
        { type: 'domain', value: 'verify-account.net', risk: 'medium' },
        { type: 'url', value: 'https://login-secure.com', risk: 'medium' },
        { type: 'email', value: 'noreply@updates.com', risk: 'low' },
        { type: 'ip', value: '104.21.45.88', risk: 'medium' },
      ]
    }
    return [
      { type: 'domain', value: 'google.com', risk: 'low' },
      { type: 'email', value: 'newsletter@company.com', risk: 'low' },
    ]
  }

  useEffect(() => {
    if (selectedScan) {
      const iocs = getIOCsForScan(selectedScan)
      const g = buildGraph(iocs, selectedScan)
      setGraph({ ...g })
      graphRef.current = g
      viewBoxRef.current = { x: 0, y: 0, w: 700, h: 480 }
      setViewBox({ x: 0, y: 0, w: 700, h: 480 })
    } else {
      setGraph({ nodes: [], edges: [] })
      graphRef.current = { nodes: [], edges: [] }
    }
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
  const handleWheel = (e) => {
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
  }

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
    <div style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>IOC Graph</h1>
          <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Interactive force-directed threat indicator visualization</p>
        </div>
        {graph.nodes.length > 0 && (
          <div style={{ display: 'flex', gap: '0.5rem' }}>
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
            <button onClick={() => exportSVG(graph, selectedScan)} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid #10B981',
              background: 'rgba(16,185,129,0.1)', color: '#10B981', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Export SVG</button>
            <button onClick={() => exportPNG(viewBoxRef)} style={{
              padding: '0.4rem 0.75rem', borderRadius: 8, border: '1px solid #06B6D4',
              background: 'rgba(6,182,212,0.1)', color: '#06B6D4', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}>Export PNG</button>
          </div>
        )}
      </div>

      {loading ? (
        <div style={{ color: '#64748B', textAlign: 'center', padding: '3rem' }}>Loading...</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '1.5rem' }}>
          {/* ── Scan List ── */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', height: 'fit-content' }}>
            <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, margin: 0 }}>Scans</h2>
              <span style={{ fontSize: '0.6875rem', color: isDark ? '#374151' : '#6B7280', background: isDark ? '#1F2937' : '#F3F4F6', padding: '0.125rem 0.4rem', borderRadius: 4 }}>{scans.length}</span>
            </div>
            <div style={{ maxHeight: 480, overflowY: 'auto' }}>
              {scans.length === 0 ? (
                <p style={{ color: '#64748B', padding: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>No scans available.</p>
              ) : (
                scans.map(scan => (
                  <button key={scan.scan_id} onClick={() => setSelectedScan(scan)} style={{
                    width: '100%', padding: '0.875rem 1rem', border: 'none', borderBottom: '1px solid var(--border)',
                    background: selectedScan?.scan_id === scan.scan_id ? '#06B6D418' : 'transparent',
                    cursor: 'pointer', textAlign: 'left', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    transition: 'background 0.15s',
                  }}>
                    <span style={{
                      color: selectedScan?.scan_id === scan.scan_id ? '#06B6D4' : (isDark ? '#fff' : '#1F2937'),
                      fontSize: '0.8125rem', flex: 1, marginRight: '0.5rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>{scan.filename}</span>
                    <span style={{
                      padding: '0.125rem 0.375rem', borderRadius: 4, fontSize: '0.625rem', textTransform: 'uppercase', flexShrink: 0,
                      background: scan.verdict === 'malicious' ? '#EF444420' : scan.verdict === 'suspicious' ? '#F59E0B20' : '#10B98120',
                      color: scan.verdict === 'malicious' ? '#EF4444' : scan.verdict === 'suspicious' ? '#F59E0B' : '#10B981',
                    }}>{scan.verdict}</span>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* ── Graph Panel ── */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Graph header */}
            {selectedScan && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, margin: 0 }}>{selectedScan.filename}</h2>
                <span style={{
                  padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', textTransform: 'uppercase', fontWeight: 700,
                  background: selectedScan.verdict === 'malicious' ? '#EF444420' : selectedScan.verdict === 'suspicious' ? '#F59E0B20' : '#10B98120',
                  color: selectedScan.verdict === 'malicious' ? '#EF4444' : selectedScan.verdict === 'suspicious' ? '#F59E0B' : '#10B981',
                }}>{selectedScan.verdict}</span>
                <span style={{ fontSize: '0.75rem', color: isDark ? '#374151' : '#6B7280', marginLeft: 'auto' }}>
                  {graph.nodes.length > 0 && `${graph.nodes.length - 1} nodes · ${graph.edges.length} edges`}
                </span>
              </div>
            )}

            {/* SVG Graph */}
            {graph.nodes.length === 0 ? (
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '3rem' }}>
                <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem' }}>🔍</div>
                <p style={{ color: '#64748B', fontSize: '0.9rem' }}>Select a scan to load the threat graph</p>
              </div>
            ) : (
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', position: 'relative' }}>
                <svg
                  id="ioc-svg"
                  ref={svgRef}
                  width="100%"
                  height={480}
                  viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
                  onWheel={handleWheel}
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

                  {/* Grid background */}
                  <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke={isDark ? 'var(--border)' : '#000000'} strokeWidth="0.5" opacity={isDark ? 0.6 : 0.3} />
                  </pattern>
                  <rect width="700" height="480" fill={isDark ? '#0D1420' : '#FFFFFF'} />
                  <rect width="700" height="480" fill="url(#grid)" />

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
                        stroke={isIOCEdge ? (isDark ? 'var(--border)' : '#9CA3AF') : (isDark ? '#374151' : '#4B5563')}
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
                    background: isDark ? '#1F2937' : '#FFFFFF', border: isDark ? '1px solid #374151' : '1px solid #D1D5DB', borderRadius: 10,
                    padding: '1rem', width: 220, boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.4)' : '0 4px 12px rgba(0,0,0,0.1)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.625rem' }}>
                      <span style={{ fontSize: '1.25rem' }}>{TYPE_ICONS[selectedNode.type] || '📄'}</span>
                      <button onClick={() => setSelectedNode(null)} style={{
                        background: 'none', border: 'none', color: isDark ? '#64748B' : '#9CA3AF', cursor: 'pointer', fontSize: '1rem',
                      }}>✕</button>
                    </div>
                    <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem', textTransform: 'capitalize' }}>
                      {TYPE_LABELS[selectedNode.type] || selectedNode.type}
                    </p>
                    <p style={{ color: isDark ? '#9CA3AF' : '#4B5563', fontSize: '0.7rem', fontFamily: 'monospace', wordBreak: 'break-all', marginBottom: '0.625rem', lineHeight: 1.4 }}>
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
                    <p style={{ color: isDark ? '#4B5563' : '#9CA3AF', fontSize: '0.6875rem', marginTop: '0.5rem' }}>
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
                    <span style={{ fontSize: '0.75rem', color: isDark ? '#64748B' : '#6B7280' }}>{x.l}</span>
                  </div>
                ))}
                <div style={{ width: 20, height: 2, background: isDark ? '#374151' : '#D1D5DB' }} />
                <span style={{ fontSize: '0.75rem', color: isDark ? '#64748B' : '#6B7280' }}>→ Email</span>
                <div style={{ width: 20, height: 1, borderTop: '1px dashed var(--border)' }} />
                <span style={{ fontSize: '0.75rem', color: isDark ? '#64748B' : '#6B7280' }}>IOC link</span>
              </div>
            )}

            {/* IOC cards */}
            {graph.nodes.length > 0 && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))', gap: '0.625rem' }}>
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
                    <p style={{ color: isDark ? '#9CA3AF' : '#4B5563', fontSize: '0.75rem', fontWeight: 500, marginBottom: '0.15rem', textTransform: 'capitalize' }}>
                      {TYPE_LABELS[node.type] || node.type}
                    </p>
                    <p style={{ color: isDark ? '#4B5563' : '#9CA3AF', fontSize: '0.6875rem', fontFamily: 'monospace', wordBreak: 'break-all', margin: 0 }}>
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