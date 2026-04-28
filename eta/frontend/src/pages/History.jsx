import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { getHistory, deleteScan, getFavourites, addFavourite, removeFavourite, getReport } from '../services/api'

export default function History() {
  const [records, setRecords] = useState([])
  const [favourites, setFavourites] = useState([])
  const [favSet, setFavSet] = useState(new Set())
  const [tab, setTab] = useState('all')   // 'all' | 'favourites'
  const [loading, setLoading] = useState(true)
  const [toggling, setToggling] = useState(null)
  // Comparison state
  const [compareMode, setCompareMode] = useState(false)
  const [selectedForCompare, setSelectedForCompare] = useState([])
  const [compareData, setCompareData] = useState([])
  const [compareLoading, setCompareLoading] = useState(false)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [verdictFilter, setVerdictFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [fileTypeFilter, setFileTypeFilter] = useState('')
  const location = useLocation()

  // Reload scans when returning to this page
  useEffect(() => {
    loadAll(false)
  }, [location.key])

  // Load more on page change (for infinite scroll)
  useEffect(() => {
    if (page > 1) {
      loadAll(true)
    }
  }, [page])

  // Load scan history data - handles both initial and pagination loads
  const loadAll = async (append = false) => {
    try {
      // Parallel fetch faster
      const [histRes, favRes] = await Promise.all([
        getHistory(page, 50, verdictFilter || undefined).catch(() => ({ data: { records: [], pages: 1 } })),
        getFavourites().catch(() => ({ data: { favourites: [] } })),
      ])
      if (append) {
        setRecords(prev => [...prev, ...(histRes.data?.records || histRes?.records || [])])
      } else {
        setRecords(histRes.data?.records || histRes?.records || [])
        setLoading(false)
      }
      setTotalPages(histRes.data?.pages || 1)
      setFavourites(favRes.data?.favourites || [])
      const ids = new Set((favRes.data?.favourites || []).map(f => f.scan_id))
      setFavSet(ids)
    } catch (err) {
      console.error(err)
      setLoading(false)
    }
  }

  const getColor = (v) => ({ malicious: 'var(--red)', suspicious: 'var(--amber)', safe: 'var(--green)' }[v] || 'var(--sub)')
  const getBg = (v) => ({ malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }[v] || 'rgba(100,116,139,0.15)')

  const handleFav = async (scanId) => {
    setToggling(scanId)
    try {
      if (favSet.has(scanId)) {
        await removeFavourite(scanId)
        setFavSet(prev => { const n = new Set(prev); n.delete(scanId); return n })
        setFavourites(prev => prev.filter(f => f.scan_id !== scanId))
      } else {
        await addFavourite(scanId)
        setFavSet(prev => new Set([...prev, scanId]))
        const rec = records.find(r => r.scan_id === scanId)
        if (rec) setFavourites(prev => [{ ...rec, favourite_id: null }, ...prev])
      }
    } catch { /* ignore */ }
    setToggling(null)
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this scan?')) return
    try {
      await deleteScan(id)
      setRecords(prev => prev.filter(r => r.scan_id !== id))
      setFavourites(prev => prev.filter(r => r.scan_id !== id))
      setFavSet(prev => { const n = new Set(prev); n.delete(id); return n })
    } catch { alert('Failed to delete scan') }
  }

  const toggleCompare = (scan) => {
    if (selectedForCompare.includes(scan.scan_id)) {
      setSelectedForCompare(prev => prev.filter(id => id !== scan.scan_id))
    } else {
      if (selectedForCompare.length < 2) {
        setSelectedForCompare(prev => [...prev, scan.scan_id])
      }
    }
  }

  const runCompare = async () => {
    if (selectedForCompare.length !== 2) return
    setCompareLoading(true)
    try {
      const [r1, r2] = await Promise.all([
        getReport(selectedForCompare[0]),
        getReport(selectedForCompare[1]),
      ])
      // Handle both direct data and wrapped response
      let data1 = r1.data || r1
      let data2 = r2.data || r2
      // Parse string responses if needed
      if (typeof data1 === 'string') data1 = JSON.parse(data1)
      if (typeof data2 === 'string') data2 = JSON.parse(data2)
      setCompareData([data1, data2])
    } catch (err) {
      console.error('Compare error:', err)
      alert('Failed to load reports for comparison')
    }
    setCompareLoading(false)
  }

  const closeCompare = () => {
    setCompareMode(false)
    setSelectedForCompare([])
    setCompareData([])
  }

  const displayRecords = tab === 'favourites' ? favourites : records

  // Filter records by search query and file type
  const filteredRecords = displayRecords.filter(r => {
    const matchesSearch = !searchQuery ||
      (r.filename && r.filename.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (r.sender && r.sender.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesFileType = !fileTypeFilter ||
      (r.filename && r.filename.toLowerCase().endsWith(fileTypeFilter.toLowerCase()))
    return matchesSearch && matchesFileType
  })

  // Infinite scroll observer
  const loadMoreRef = useCallback((node) => {
    if (loading) return
    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting && page < totalPages) {
        setPage(p => p + 1)
      }
    })
    if (node) observer.observe(node)
    return () => observer.disconnect()
  }, [loading, page, totalPages])

  return (
    <div style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.25rem' }}>Scan History</h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>View and manage all your scanned emails</p>
        </div>
        {/* Compare button */}
        <button onClick={() => {
            if (selectedForCompare.length === 2) {
              setCompareMode(true)
              runCompare()
            }
          }} disabled={selectedForCompare.length !== 2}
          style={{ padding: '0.5rem 1rem', borderRadius: 8, border: '1px solid var(--cyan)', background: compareMode ? 'var(--cyan)' : 'transparent', color: compareMode ? '#fff' : 'var(--cyan)', cursor: selectedForCompare.length === 2 ? 'pointer' : 'not-allowed', fontSize: '0.8125rem', fontWeight: 600, opacity: selectedForCompare.length === 2 ? 1 : 0.5 }}>
          {compareMode ? 'Comparing...' : `Compare (${selectedForCompare.length}/2)`}
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0', marginBottom: '1rem', borderBottom: '1px solid var(--border)' }}>
        {[['all', 'All Scans', filteredRecords.length], ['favourites', 'Favourites', favourites.length]].map(([t, label, count]) => (
          <button key={t} onClick={() => setTab(t)}
            style={{
              padding: '0.625rem 1.25rem', border: 'none', borderBottom: `2px solid ${tab === t ? 'var(--cyan)' : 'transparent'}`,
              background: 'transparent', color: tab === t ? 'var(--cyan)' : 'var(--sub)',
              cursor: 'pointer', fontSize: '0.875rem', fontWeight: tab === t ? 600 : 400,
              transition: 'all 0.15s', marginBottom: -1,
            }}>
            {label} <span style={{ color: 'var(--sub)', fontWeight: 400 }}>({count})</span>
          </button>
        ))}
      </div>

      {/* Search and Filter Bar */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        {/* Search Input */}
        <div style={{ flex: 1, minWidth: 200, position: 'relative' }}>
          <input
            type="text"
            placeholder="Search by filename or sender..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%', padding: '0.625rem 0.75rem 0.625rem 2.5rem',
              borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)',
              color: 'var(--text)', fontSize: '0.875rem',
            }}
          />
          <span style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--sub)', fontSize: '0.875rem' }}>🔍</span>
        </div>

        {/* File Type Filter */}
        <select
          value={fileTypeFilter}
          onChange={(e) => setFileTypeFilter(e.target.value)}
          style={{
            padding: '0.625rem 0.75rem', borderRadius: 8, border: '1px solid var(--border)',
            background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem', minWidth: 120,
          }}
        >
          <option value="">All Types</option>
          <option value=".eml">.eml</option>
          <option value=".txt">.txt</option>
          <option value=".csv">.csv</option>
          <option value=".msg">.msg</option>
        </select>
      </div>

      {loading ? (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
          <div className="skeleton skeleton-table-row" />
          <div className="skeleton skeleton-table-row" />
          <div className="skeleton skeleton-table-row" />
          <div className="skeleton skeleton-table-row" />
          <div className="skeleton skeleton-table-row" />
        </div>
      ) : filteredRecords.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">{tab === 'favourites' ? '⭐' : '📧'}</div>
          <h3 className="empty-state-title">
            {searchQuery || fileTypeFilter ? 'No matching scans' : tab === 'favourites' ? 'No favorite scans yet' : 'No scans yet'}
          </h3>
          <p className="empty-state-text">
            {searchQuery || fileTypeFilter ? 'Try adjusting your search or filter' : tab === 'favourites' ? 'Star a report to bookmark it here' : 'Analyze your first email to get started'}
          </p>
          {tab === 'all' && !searchQuery && !fileTypeFilter && (
            <Link to="/analyze" style={{ padding: '0.75rem 1.5rem', background: 'var(--cyan)', color: 'var(--text)', borderRadius: 8, textDecoration: 'none', fontWeight: 600 }}>
              Start Analyzing
            </Link>
          )}
        </div>
      ) : (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, width: 40 }}>Compare</th>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, width: 52 }}>Fav</th>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>File Name</th>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Verdict</th>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Risk Score</th>
                  <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Date</th>
                  <th style={{ padding: '0.875rem', textAlign: 'right', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map(r => (
                  <tr key={r.scan_id} style={{ borderBottom: '1px solid var(--border)' }}>
                    {/* Compare checkbox */}
                    <td style={{ padding: '0.875rem', width: 40 }}>
                      <input type="checkbox"
                        checked={selectedForCompare.includes(r.scan_id)}
                        onChange={() => toggleCompare(r)}
                        disabled={!selectedForCompare.includes(r.scan_id) && selectedForCompare.length >= 2}
                        title="Select for comparison"
                        style={{ width: 16, height: 16, accentColor: 'var(--cyan)', cursor: 'pointer' }}
                      />
                    </td>
                    {/* Favourite star */}
                    <td style={{ padding: '0.875rem', width: 52 }}>
                      <button
                        onClick={() => handleFav(r.scan_id)}
                        disabled={toggling === r.scan_id}
                        title={favSet.has(r.scan_id) ? 'Remove from favourites' : 'Add to favourites'}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer', fontSize: '1rem',
                          color: favSet.has(r.scan_id) ? 'var(--amber)' : 'var(--sub)',
                          opacity: toggling === r.scan_id ? 0.5 : 1, padding: '0.25rem',
                          minWidth: 0, minHeight: 0, display: 'flex', alignItems: 'center',
                        }}
                      >
                        {favSet.has(r.scan_id) ? '⭐' : '☆'}
                      </button>
                    </td>
                    <td style={{ padding: '0.875rem', color: 'var(--text)', fontSize: '0.875rem' }}>{r.filename}</td>
                    <td style={{ padding: '0.875rem' }}>
                      <span style={{ padding: '0.25rem 0.5rem', borderRadius: 6, fontSize: '0.6875rem', textTransform: 'uppercase', fontWeight: 600, background: getBg(r.verdict), color: getColor(r.verdict) }}>
                        {r.verdict}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem', color: getColor(r.verdict), fontSize: '0.875rem', fontWeight: 600 }}>{r.risk_score}</td>
                    <td style={{ padding: '0.875rem', color: 'var(--sub)', fontSize: '0.8125rem' }}>{new Date(r.created_at).toLocaleDateString()}</td>
                    <td style={{ padding: '0.875rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                        <Link to={`/reports/${r.scan_id}`} style={{ color: 'var(--cyan)', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.75rem', textDecoration: 'none' }}>View</Link>
                        <button onClick={() => handleDelete(r.scan_id)} style={{ color: 'var(--red)', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.75rem' }}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Comparison Modal */}
      {compareMode && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', zIndex: 9999,
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem',
        }} onClick={closeCompare}>
          <div style={{
            background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 16,
            width: '100%', maxWidth: 1200, maxHeight: '90vh', overflow: 'auto', padding: '1.5rem',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 600 }}>Scan Comparison</h2>
              <button onClick={closeCompare} style={{ background: 'none', border: 'none', color: 'var(--sub)', cursor: 'pointer', fontSize: '1.25rem' }}>X</button>
            </div>

            {compareLoading ? (
              <p style={{ color: 'var(--sub)', textAlign: 'center', padding: '2rem' }}>Loading reports...</p>
            ) : compareData.length === 2 ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                {[0, 1].map(idx => {
                  const d = compareData[idx]
                  // More flexible matching - try both number and string
                  const scanId = selectedForCompare[idx]
                  const rec = filteredRecords.find(r =>
                    Number(r.scan_id) === Number(scanId) ||
                    String(r.scan_id) === String(scanId)
                  )
                  const getColor = v => ({ malicious: 'var(--red)', suspicious: 'var(--amber)', safe: 'var(--green)' }[v] || 'var(--sub)')
                  return (
                    <div key={idx} style={{ background: 'var(--surface)', borderRadius: 12, padding: '1.25rem', border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <div>
                          <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>
                            {rec?.filename || d?.filename || `Scan ${selectedForCompare[idx]}`}
                          </h3>
                          <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>
                            {rec?.created_at ? new Date(rec.created_at).toLocaleString() : d?.created_at || 'Unknown date'}
                          </p>
                        </div>
                        {/* Use record verdict as fallback */}
                        <span style={{ padding: '0.25rem 0.625rem', borderRadius: 6, fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', background: getColor(d?.verdict || rec?.verdict) + '20', color: getColor(d?.verdict || rec?.verdict) }}>
                          {d?.verdict || rec?.verdict || 'unknown'}
                        </span>
                      </div>

                      {/* Stats comparison - use record as fallback */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.625rem', marginBottom: '1rem' }}>
                        <div style={{ background: 'var(--card)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.625rem', textTransform: 'uppercase' }}>Risk Score</p>
                          <p style={{ color: getColor(d?.verdict || rec?.verdict), fontSize: '1.25rem', fontWeight: 700 }}>
                            {d?.risk_score ?? rec?.risk_score ?? 0}
                          </p>
                        </div>
                        <div style={{ background: 'var(--card)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.625rem', textTransform: 'uppercase' }}>URLs</p>
                          <p style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 700 }}>{d?.url_count ?? 0}</p>
                        </div>
                        <div style={{ background: 'var(--card)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.625rem', textTransform: 'uppercase' }}>Attachments</p>
                          <p style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 700 }}>{d?.attach_count ?? 0}</p>
                        </div>
                      </div>

                      {/* Threats */}
                      <div style={{ marginBottom: '0.75rem' }}>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.375rem' }}>Detected Threats</p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                          {(d?.threats || []).length > 0 ? d.threats.map((t, i) => (
                            <span key={i} style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: 'var(--red)20', color: 'var(--red)', fontSize: '0.6875rem' }}>{t}</span>
                          )) : <span style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>None</span>}
                        </div>
                      </div>

                      {/* IOCs */}
                      <div>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.375rem' }}>IOCs ({d?.iocs?.length || 0})</p>
                        <div style={{ background: 'var(--card)', borderRadius: 6, padding: '0.5rem', maxHeight: 120, overflowY: 'auto' }}>
                          {(d?.iocs || []).slice(0, 10).map((ioc, i) => (
                            <div key={i} style={{ fontSize: '0.6875rem', fontFamily: 'monospace', color: 'var(--text)', padding: '0.125rem 0' }}>
                              <span style={{ color: 'var(--cyan)', textTransform: 'uppercase' }}>{ioc.type}: </span>{ioc.value}
                            </div>
                          ))}
                          {(d?.iocs?.length || 0) > 10 && <p style={{ color: 'var(--sub)', fontSize: '0.625rem' }}>+{(d.iocs.length - 10)} more</p>}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p style={{ color: 'var(--sub)', textAlign: 'center', padding: '2rem' }}>Select exactly 2 scans to compare</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}