import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../../services/api'

export default function SearchBar({ onClose }) {
  const [query, setQuery]   = useState('')
  const [results, setResults] = useState({ scans: [], reports: [], users: [] })
  const [loading, setLoading] = useState(false)
  const [activeIdx, setActiveIdx] = useState(-1)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    inputRef.current?.focus()
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  useEffect(() => {
    if (!query.trim()) { setResults({ scans: [], reports: [], users: [] }); return }
    const ctrl = new AbortController()
    setLoading(true)
    const timer = setTimeout(async () => {
      try {
        const q = query.trim()
        const [scanRes, userRes] = await Promise.all([
          api.get('/api/history/scan-history', { params: { page: 1, limit: 6, ...(q ? { search: q } : {}) }, signal: ctrl.signal }),
          (await api.get('/api/users/', { params: { search: q, limit: 4 }, signal: ctrl.signal }).catch(() => ({ data: [] }))),
        ])
        const scans = (scanRes.data?.records || []).filter(r =>
          r.filename?.toLowerCase().includes(q.toLowerCase()) ||
          r.sender?.toLowerCase().includes(q.toLowerCase()) ||
          String(r.scan_id).includes(q)
        ) || []
        const users = (userRes.data?.users || userRes.data || []).filter(u =>
          u.username?.toLowerCase().includes(q.toLowerCase()) ||
          u.email?.toLowerCase().includes(q.toLowerCase())
        )
        setResults({ scans, reports: [], users })
      } catch { /* ignore abort */ }
      setLoading(false)
    }, 250)
    return () => { ctrl.abort(); clearTimeout(timer) }
  }, [query])

  const allItems = [
    ...results.scans.map(s => ({ ...s, _type: 'scan' })),
    ...results.users.map(u => ({ ...u, _type: 'user' })),
  ]

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, allItems.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, -1)) }
    if (e.key === 'Enter' && activeIdx >= 0) { handleSelect(allItems[activeIdx]) }
    if (e.key === 'Escape')    onClose()
  }

  const handleSelect = (item) => {
    onClose()
    if (item._type === 'scan') navigate(`/reports/${item.scan_id}`)
    if (item._type === 'user') navigate('/users')
  }

  const hasResults = allItems.length > 0
  let itemCounter = -1

  const renderItem = (item, label, icon, color) => {
    itemCounter++
    const idx = itemCounter
    const isActive = activeIdx === idx
    return (
      <div key={item.scan_id || item.id} className={`search-result-item${isActive ? ' active' : ''}`} onClick={() => handleSelect(item)} onMouseEnter={() => setActiveIdx(idx)}>
        <div className="search-result-icon" style={{ background: color + '20', color }}>
          {icon}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.filename || item.username}</p>
          <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{label}</p>
        </div>
        {item.verdict && (
          <span style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: { malicious: 'var(--red)', suspicious: 'var(--amber)', safe: 'var(--green)' }[item.verdict] || 'var(--sub)' }}>
            {item.verdict}
          </span>
        )}
      </div>
    )
  }

  return (
    <div className="search-overlay" onClick={onClose}>
      <div className="search-modal" onClick={e => e.stopPropagation()}>
        <div className="search-input-wrap">
          <span style={{ color: 'var(--sub)', fontSize: '1rem' }}>🔍</span>
          <input
            ref={inputRef}
            className="search-input"
            placeholder="Search scans, reports, users..."
            value={query}
            onChange={e => { setQuery(e.target.value); setActiveIdx(-1) }}
            onKeyDown={handleKeyDown}
          />
          {loading && <span style={{ color: 'var(--cyan)', fontSize: '0.875rem' }}>…</span>}
          <kbd style={{ display: 'inline-flex', alignItems: 'center', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '0.1rem 0.4rem', fontFamily: 'monospace', fontSize: '0.6875rem', color: 'var(--sub)', minWidth: 'auto', minHeight: 'auto' }}>ESC</kbd>
        </div>

        <div className="search-results">
          {!query.trim() && (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--sub)', fontSize: '0.875rem' }}>
              Start typing to search across all your scans, reports and users
            </div>
          )}
          {query.trim() && !loading && !hasResults && (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--sub)', fontSize: '0.875rem' }}>
              No results found for "{query}"
            </div>
          )}
          {results.scans.length > 0 && (
            <>
              <div className="search-section-label">Scans ({results.scans.length})</div>
              {results.scans.map(s => renderItem(s, `Scan #${s.scan_id} · ${new Date(s.created_at).toLocaleDateString()}`, '📧', 'var(--cyan)'))}
            </>
          )}
          {results.users.length > 0 && (
            <>
              <div className="search-section-label">Users ({results.users.length})</div>
              {results.users.map(u => renderItem(u, u.email, '👤', 'var(--amber)'))}
            </>
          )}
        </div>

        <div className="search-shortcuts">
          <span><kbd>↑↓</kbd> Navigate</span>
          <span><kbd>Enter</kbd> Open</span>
          <span><kbd>Esc</kbd> Close</span>
        </div>
      </div>
    </div>
  )
}