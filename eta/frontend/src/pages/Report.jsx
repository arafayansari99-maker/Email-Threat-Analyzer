import { useState, useEffect, useCallback } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import api, { getHistory, getReport, downloadJSON, generatePDF, addFavourite, removeFavourite } from '../services/api'
import { useToast } from '../hooks/useToast'
import { useIsMobile } from '../hooks/useIsMobile'

export default function Report() {
  const isMobile = useIsMobile()
  const { id } = useParams()
  const navigate = useNavigate()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)
  const [comments, setComments] = useState([])
  const [newComment, setNewComment] = useState('')
  const [isFlag, setIsFlag] = useState(false)
  const [addingComment, setAddingComment] = useState(false)
  const [isFav, setIsFav] = useState(false)
  const [favLoading, setFavLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [fileTypeFilter, setFileTypeFilter] = useState('')
  const { warn, success, error: showError } = useToast()

  const toggleFav = useCallback(async () => {
    if (!selectedScan) return
    setFavLoading(true)
    try {
      if (isFav) {
        await removeFavourite(selectedScan.scan_id)
        setIsFav(false)
        success('Removed from favourites')
      } else {
        await addFavourite(selectedScan.scan_id)
        setIsFav(true)
        success('Added to favourites')
      }
    } catch { warn('Failed to update favourite') }
    setFavLoading(false)
  }, [selectedScan, isFav, success, warn])

  // Keyboard: E to export
  useEffect(() => {
    const h = (e) => {
      if (e.key.toLowerCase() === 'e' && !['INPUT','TEXTAREA'].includes(e.target.tagName)) {
        e.preventDefault()
        handleExportJSON()
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  // Load scan list + optionally load report by ID from URL
  useEffect(() => {
    loadAll()
  }, [])

  const loadAll = async () => {
    setLoading(true)
    try {
      // Load scans list, report, and favourites in parallel
      const [historyRes, reportRes, favRes] = await Promise.all([
        getHistory(1, 50),
        id ? getReport(id) : Promise.resolve({ data: null }),
        api.get('/api/history/favourites').catch(() => ({ data: { favourites: [] } })),
      ])

      const records = historyRes.data?.records || historyRes.data?.data?.records || []
      setScans(records)

      // Parse and set report — handle both JSON object and raw JSON string
      if (reportRes.data) {
        const raw = reportRes.data
        let parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
        setReport(parsed)

        // Find matching scan from history - handle both string and number
        const matched = records.find(s => String(s.scan_id) === String(id) || s.scan_id === parseInt(id))
        setSelectedScan(matched || null)
        if (matched) {
          const favIds = (favRes.data?.favourites || []).map(f => f.scan_id)
          setIsFav(favIds.includes(String(matched.scan_id)))
        }
      }
    } catch (err) {
      console.error('Report load error:', err)
      // Try loading just the history if report fails
      try {
        const { data: hData } = await getHistory(1, 50)
        const records = hData?.records || hData?.data?.records || []
        setScans(records)
        const matched = records.find(s => s.scan_id === parseInt(id))
        setSelectedScan(matched || null)
      } catch (e2) {
        console.error(e2)
      }
    } finally {
      setLoading(false)
    }
  }

  const handleSelectScan = (scan) => {
    setSelectedScan(scan)
    navigate(`/reports/${scan.scan_id}`)
    loadReportForScan(scan.scan_id)
    loadComments(scan.scan_id)
  }

  const loadReportForScan = async (scanId) => {
    try {
      const { data } = await getReport(scanId)
      const parsed = typeof data === 'string' ? JSON.parse(data) : data
      setReport(parsed)
    } catch (err) {
      console.error(err)
      setReport(null)
    }
  }

  const loadComments = async (scanId) => {
    try {
      const { data } = await api.get(`/api/collaboration/comments/${scanId}`)
      setComments(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Failed to load comments:', err)
      setComments([])
    }
  }

  const handleAddComment = async () => {
    if (!newComment.trim() || !selectedScan) return
    setAddingComment(true)
    try {
      const { data } = await api.post('/api/collaboration/comments', {
        scan_id: selectedScan.scan_id,
        content: newComment,
        is_flag: isFlag,
      })
      setComments(prev => [data, ...prev])
      setNewComment('')
      setIsFlag(false)
      success('Comment added')
    } catch (err) {
      console.error('Failed to add comment:', err)
      showError('Failed to add comment')
    } finally {
      setAddingComment(false)
    }
  }

  const getSafeFilename = (name) => {
    // Sanitize filename: remove extension if present, replace special chars with underscore
    const base = name.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9-_]/g, '_')
    return base || 'email_analysis'
  }

  const handleExportJSON = async () => {
    if (!selectedScan) return
    setExporting(true)
    try {
      const response = await downloadJSON(selectedScan.scan_id)
      const blob = response.data || response
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const filename = `Report analysis - ${getSafeFilename(selectedScan.filename)}.json`
      a.download = filename
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      console.error('JSON export error:', err)
      showError('Failed to export JSON')
    } finally {
      setExporting(false)
    }
  }

  const handleExportPDF = async () => {
    if (!selectedScan) return
    setExporting(true)
    try {
      const response = await generatePDF(selectedScan.scan_id)
      const blob = response.data || response
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const filename = `Report analysis - ${getSafeFilename(selectedScan.filename)}.pdf`
      a.download = filename
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      console.error('PDF export error:', err)
      // Try to extract error message from backend response
      let errorMessage = 'Failed to export PDF'
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail
        // Extract the actual error message from the detail string
        if (typeof detail === 'string' && detail.includes('PDF error:')) {
          errorMessage = `PDF export failed: ${detail.replace('PDF error: ', '')}`
        } else {
          errorMessage = detail
        }
      } else if (err.message) {
        errorMessage = `PDF export failed: ${err.message}`
      }
      showError(errorMessage)
    } finally {
      setExporting(false)
    }
  }

  // Filter scans by search query and file type
  const filteredScans = scans.filter(scan => {
    const q = searchQuery.toLowerCase()
    const matchesSearch = !searchQuery ||
      (scan.filename && scan.filename.toLowerCase().includes(q)) ||
      (scan.subject && scan.subject.toLowerCase().includes(q)) ||
      (scan.sender && scan.sender.toLowerCase().includes(q))
    const matchesFileType = !fileTypeFilter ||
      (scan.filename && scan.filename.toLowerCase().endsWith(fileTypeFilter.toLowerCase()))
    return matchesSearch && matchesFileType
  })

  const getColor = (v) => ({ malicious: '#EF4444', suspicious: '#F59E0B', safe: '#10B981', unknown: '#64748B' }[v] || '#64748B')

  const getIOCStatus = (iocObj) => {
    const safeString = (value) => (value || '').toString().trim()
    const normalizeUrl = (url) => safeString(url).replace(/\/+$|\s+/g, '').toLowerCase()
    const statusFromVerdict = (verdict, score) => {
      const v = safeString(verdict).toLowerCase()
      if (v === 'malicious' || v === 'high' || v === 'danger') return 'malicious'
      if (v === 'suspicious' || v === 'medium' || v === 'warning') return 'suspicious'
      if (v === 'safe' || v === 'benign' || v === 'low') return 'safe'
      if (typeof score === 'number') {
        if (score >= 70) return 'malicious'
        if (score >= 40) return 'suspicious'
        return 'safe'
      }
      return 'unknown'
    }

    if (!iocObj) return 'unknown'
    const value = safeString(iocObj.value || iocObj)
    const type = safeString(iocObj.type).toLowerCase()
    if (iocObj.risk) {
      return safeString(iocObj.risk).toLowerCase()
    }

    const urls = report?.url_analysis?.urls || []
    const attachments = report?.attachment_analysis?.attachments || []

    if (type === 'url') {
      const match = urls.find((u) => normalizeUrl(u.url) === normalizeUrl(value) || normalizeUrl(u.url).endsWith(normalizeUrl(value)))
      if (match) return statusFromVerdict(match.verdict, match.score)
    }

    if (type === 'domain') {
      const domain = value.toLowerCase()
      const matches = urls.filter((u) => {
        try {
          const hostname = new URL(safeString(u.url)).hostname.toLowerCase()
          return hostname === domain || hostname.endsWith(`.${domain}`)
        } catch {
          return safeString(u.url).toLowerCase().includes(domain)
        }
      })
      if (matches.length > 0) {
        const statuses = matches.map((u) => statusFromVerdict(u.verdict, u.score))
        return statuses.includes('malicious') ? 'malicious' : statuses.includes('suspicious') ? 'suspicious' : 'safe'
      }
    }

    if (type === 'hash') {
      const match = attachments.find((a) => safeString(a.sha256).toLowerCase() === value.toLowerCase() || safeString(a.md5).toLowerCase() === value.toLowerCase())
      if (match) {
        return statusFromVerdict(match.risk, match.score)
      }
      if (attachments.some((a) => a.is_malicious_extension || a.is_risky_extension)) {
        return 'suspicious'
      }
    }

    if (type === 'ip') {
      const ipReputation = report?.threat_intel?.ip_reputation || []
      const match = Array.isArray(ipReputation)
        ? ipReputation.find((entry) => safeString(entry.ip).toLowerCase() === value.toLowerCase())
        : ipReputation
      if (match) return statusFromVerdict(match.verdict || match.risk, match.score || match.risk_score)
    }

    return 'unknown'
  }

  if (loading) {
    return (
      <div style={{ padding: '1.5rem', display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 300 }}>
        <div style={{ color: '#64748B', fontSize: '0.9375rem' }}>Loading report...</div>
      </div>
    )
  }

  return (
    <div style={{ padding: isMobile ? '1rem' : '1.5rem' }}>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Reports</h1>
      <p style={{ color: '#64748B', fontSize: '0.9375rem', marginBottom: '2rem' }}>View and export detailed threat reports</p>

      {/* Search and Filter Bar */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        {/* Search Input */}
        <div style={{ flex: 1, minWidth: 200, position: 'relative' }}>
          <input
            type="text"
            placeholder="Search by subject, sender, or filename..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%', padding: '0.625rem 0.75rem 0.625rem 2.5rem',
              borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)',
              color: 'var(--text)', fontSize: '0.875rem',
            }}
          />
          <span style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: '#64748B', lineHeight: 0 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </span>
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

      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '320px 1fr', gap: '1.5rem' }}>
        {/* Scan List Sidebar */}
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', height: 'fit-content' }}>
          <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, margin: 0 }}>Scan History</h2>
          </div>
          <div style={{ maxHeight: 500, overflowY: 'auto' }}>
            {filteredScans.length === 0 ? (
              <div style={{ padding: '1.5rem', textAlign: 'center' }}>
                <p style={{ color: '#64748B', fontSize: '0.875rem', marginBottom: '0.75rem' }}>
                  {searchQuery || fileTypeFilter ? 'No matching scans' : 'No scans available'}
                </p>
                {(searchQuery || fileTypeFilter) ? (
                  <button
                    onClick={() => { setSearchQuery(''); setFileTypeFilter('') }}
                    style={{ color: '#06B6D4', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.8125rem' }}
                  >
                    Clear filters
                  </button>
                ) : (
                  <Link to="/analyze" style={{ color: '#06B6D4', textDecoration: 'none', fontSize: '0.8125rem' }}>
                    Run an analysis first
                  </Link>
                )}
              </div>
            ) : (
              filteredScans.map(scan => (
                <button
                  key={scan.scan_id}
                  onClick={() => handleSelectScan(scan)}
                  style={{
                    width: '100%', padding: '0.875rem 1rem', border: 'none',
                    borderBottom: '1px solid var(--border)',
                    background: selectedScan?.scan_id === scan.scan_id ? '#06B6D415' : 'transparent',
                    cursor: 'pointer', textAlign: 'left',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    transition: 'background 0.15s',
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.125rem' }}>
                      {scan.source === 'imap' && (
                        <span style={{ flexShrink: 0, padding: '0.05rem 0.3rem', borderRadius: 3, background: '#06B6D420', color: '#06B6D4', fontSize: '0.5625rem', fontWeight: 700, textTransform: 'uppercase' }}>IMAP</span>
                      )}
                      <p style={{ color: 'var(--text)', fontSize: '0.8125rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', margin: 0 }}>
                        {scan.subject || scan.filename}
                      </p>
                    </div>
                    {scan.sender && (
                      <p style={{ color: '#6B7280', fontSize: '0.6875rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: '0.1rem' }}>{scan.sender}</p>
                    )}
                    <p style={{ color: '#4B5563', fontSize: '0.6rem' }}>{new Date(scan.created_at).toLocaleDateString()}</p>
                  </div>
                  <span style={{
                    padding: '0.125rem 0.375rem', borderRadius: 4, fontSize: '0.625rem',
                    textTransform: 'uppercase', flexShrink: 0, marginLeft: '0.5rem',
                    background: getColor(scan.verdict) + '20', color: getColor(scan.verdict),
                  }}>
                    {scan.verdict}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Report Content */}
        <div>
          {!selectedScan ? (
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '3rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', marginBottom: '0.75rem', fontSize: '0.9375rem' }}>Select a scan from the left to view its detailed report</p>
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                <Link to="/analyze" style={{ color: '#06B6D4', textDecoration: 'none', fontSize: '0.875rem' }}>Run Analysis</Link>
                <Link to="/history" style={{ color: '#64748B', textDecoration: 'none', fontSize: '0.875rem' }}>View History</Link>
              </div>
            </div>
          ) : (
            <>
              {/* Report Header Card */}
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <button
                      onClick={toggleFav}
                      disabled={favLoading}
                      title={isFav ? 'Remove from favourites' : 'Add to favourites'}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '1.5rem', color: isFav ? '#F59E0B' : '#4B5563', padding: 0, minWidth: 0, minHeight: 0, lineHeight: 1 }}>
                      {isFav ? '⭐' : '☆'}
                    </button>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.25rem' }}>
                        {selectedScan.source === 'imap' && (
                          <span style={{ padding: '0.15rem 0.4rem', borderRadius: 4, background: '#06B6D420', color: '#06B6D4', fontSize: '0.625rem', fontWeight: 700, textTransform: 'uppercase' }}>IMAP</span>
                        )}
                        <h2 style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 600, margin: 0 }}>
                          {selectedScan.subject || selectedScan.filename}
                        </h2>
                      </div>
                      {selectedScan.sender && (
                        <p style={{ color: '#6B7280', fontSize: '0.8125rem', marginBottom: '0.2rem' }}>From: {selectedScan.sender}</p>
                      )}
                      <p style={{ color: '#4B5563', fontSize: '0.75rem' }}>Scan #{selectedScan.scan_id} · {new Date(selectedScan.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                  <span style={{
                    padding: '0.375rem 0.875rem', borderRadius: 8, fontSize: '0.8125rem',
                    fontWeight: 600, textTransform: 'uppercase', whiteSpace: 'nowrap',
                    background: getColor(selectedScan.verdict) + '20', color: getColor(selectedScan.verdict),
                  }}>
                    {selectedScan.verdict}
                  </span>
                </div>

                {/* Sender Domain Intelligence */}
                {report?.meta?.sender_domain && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem', padding: '0.875rem 1rem', background: 'var(--surface)', borderRadius: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: 200 }}>
                      <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Domain:</span>
                      <code style={{ color: '#06B6D4', fontSize: '0.8125rem', background: 'var(--muted)', padding: '0.1rem 0.4rem', borderRadius: 3, wordBreak: 'break-all' }}>
                        {report.meta.sender_domain}
                      </code>
                    </div>
                    {report.header_analysis?.domain_reputation?.suspicious_tld && (
                      <span style={{ padding: '0.15rem 0.5rem', borderRadius: 4, background: 'rgba(239,68,68,0.15)', color: '#EF4444', fontSize: '0.6875rem', fontWeight: 600 }}>Suspicious TLD</span>
                    )}
                    {report.ml_analysis?.domain_entropy != null && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                        <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Domain Entropy:</span>
                        <span style={{
                          padding: '0.1rem 0.5rem', borderRadius: 4,
                          fontSize: '0.75rem', fontWeight: 700,
                          background: report.ml_analysis.domain_entropy > 3.5 ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                          color: report.ml_analysis.domain_entropy > 3.5 ? '#EF4444' : '#10B981',
                        }}>
                          {report.ml_analysis.domain_entropy.toFixed(2)}
                          {report.ml_analysis.domain_entropy > 3.5 ? ' (high — likely random/throwaway)' : ' (normal)'}
                        </span>
                      </div>
                    )}
                    {report.authentication && (
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        {[['SPF', report.authentication?.spf_status], ['DKIM', report.authentication?.dkim_status], ['DMARC', report.authentication?.dmarc_status]].filter(([, v]) => v).map(([k, v]) => (
                          <span key={k} style={{
                            padding: '0.1rem 0.4rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                            background: v === 'pass' ? 'rgba(16,185,129,0.15)' : v === 'fail' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)',
                            color: v === 'pass' ? '#10B981' : v === 'fail' ? '#EF4444' : '#F59E0B',
                          }}>
                            {k}: {v}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Stats Row */}
                <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fit, minmax(${isMobile ? '90px' : '120px'}, 1fr))`, gap: '0.75rem', marginBottom: '1.25rem' }}>
                  <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
                    <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem', letterSpacing: '0.05em' }}>Risk Score</p>
                    <p style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getColor(selectedScan.verdict) }}>{selectedScan.risk_score ?? 0}</p>
                  </div>
                  <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
                    <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem', letterSpacing: '0.05em' }}>Verdict</p>
                    <p style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getColor(selectedScan.verdict), textTransform: 'capitalize' }}>{selectedScan.verdict}</p>
                  </div>
                  <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
                    <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem', letterSpacing: '0.05em' }}>Phishing Prob</p>
                    <p style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text)' }}>{(selectedScan.phishing_prob * 100 || 0).toFixed(1)}%</p>
                  </div>
                </div>

                {/* Export Buttons */}
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button onClick={handleExportJSON} disabled={exporting} style={{
                    flex: 1, padding: '0.75rem', borderRadius: 8,
                    background: '#06B6D4', color: 'var(--text)', border: 'none',
                    cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
                    opacity: exporting ? 0.7 : 1, transition: 'opacity 0.15s',
                  }}>
                    Export JSON
                  </button>
                  <button onClick={handleExportPDF} disabled={exporting} style={{
                    flex: 1, padding: '0.75rem', borderRadius: 8,
                    background: '#8B5CF6', color: 'var(--text)', border: 'none',
                    cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
                    opacity: exporting ? 0.7 : 1, transition: 'opacity 0.15s',
                  }}>
                    Export PDF
                  </button>
                </div>
              </div>

              {/* Analysis Summary */}
              {report && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Analysis Summary</h3>
                  <p style={{ color: '#6B7280', fontSize: '0.875rem', lineHeight: 1.6 }}>
                    {report.analysis_summary || report.summary || (
                      // Generate fallback summary from available data
                      `Verdict: ${report.verdict?.toUpperCase() || 'UNKNOWN'}` +
                      ` | Risk Score: ${report.risk_score || 0}/100` +
                      (report.risk_score != null
                        ? ` | Phishing Probability: ${report.risk_score.toFixed(0)}%`
                        : '') +
                      ` | URLs: ${report.url_count || 0} | Attachments: ${report.attach_count || 0}`
                    )}
                  </p>
                </div>
              )}

              {/* ── AI Threat Assessment ── */}
              {report?.narrative && report.narrative.enabled && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                    <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>AI Threat Assessment</h3>
                    <span style={{ marginLeft: 'auto', padding: '0.15rem 0.5rem', borderRadius: 4, background: 'rgba(139,92,246,0.15)', color: '#A78BFA', fontSize: '0.625rem', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                      {report.narrative.model || 'gpt-4o-mini'}
                    </span>
                  </div>

                  {report.narrative.threat_assessment && (
                    <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', marginBottom: '1rem', borderLeft: '3px solid #A78BFA' }}>
                      <p style={{ color: 'var(--text)', fontSize: '0.875rem', lineHeight: 1.7, margin: 0 }}>
                        {report.narrative.threat_assessment}
                      </p>
                    </div>
                  )}

                  {report.narrative.social_engineering_tactics?.length > 0 && (
                    <div style={{ marginBottom: '1rem' }}>
                      <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Social Engineering Tactics</p>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {report.narrative.social_engineering_tactics.map((tactic, i) => (
                          <span key={i} style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: 'rgba(239,68,68,0.12)', color: '#EF4444', fontSize: '0.75rem', fontWeight: 500 }}>
                            {tactic}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {(report.narrative.spf_assessment || report.narrative.dkim_assessment || report.narrative.dmarc_assessment) && (
                    <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr 1fr', gap: '0.75rem' }}>
                      {[
                        ['SPF', report.narrative.spf_assessment],
                        ['DKIM', report.narrative.dkim_assessment],
                        ['DMARC', report.narrative.dmarc_assessment],
                      ].filter(([, v]) => v).map(([auth, text]) => (
                        <div key={auth} style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.875rem' }}>
                          <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem', fontWeight: 700 }}>{auth}</p>
                          <p style={{ color: '#9CA3AF', fontSize: '0.8125rem', lineHeight: 1.5, margin: 0 }}>{text}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {report.narrative.additional_iocs?.length > 0 && (
                    <div style={{ marginTop: '1rem' }}>
                      <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Additional IOCs</p>
                      <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.875rem', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                        {report.narrative.additional_iocs.map((ioc, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ color: '#F59E0B', fontSize: '0.75rem', fontWeight: 700 }}>+ </span>
                            <span style={{ color: '#9CA3AF', fontSize: '0.8125rem' }}>{ioc}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {report?.narrative && !report.narrative.enabled && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>AI Threat Assessment</h3>
                  </div>
                  <p style={{ color: '#64748B', fontSize: '0.8125rem', lineHeight: 1.5 }}>
                    Set <code style={{ background: 'var(--surface)', padding: '0.1rem 0.35rem', borderRadius: 3, fontSize: '0.75rem', color: '#06B6D4' }}>OPENAI_API_KEY</code> in your backend <code style={{ background: 'var(--surface)', padding: '0.1rem 0.35rem', borderRadius: 3, fontSize: '0.75rem', color: '#06B6D4' }}>.env</code> to enable AI-powered narrative threat analysis with social engineering insight.
                  </p>
                </div>
              )}

              {/* ML Signal Breakdown */}
              {report && (report.ml_analysis || report.semantic_analysis) && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Detection Signals</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>

                    {/* XGBoost structural */}
                    {report.ml_analysis && (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                          <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>
                            XGBoost (structural features)
                            <span style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginLeft: '0.5rem' }}>
                              {report.semantic_analysis?.method === 'distilbert' ? '25% weight' : '35% weight'}
                            </span>
                          </span>
                          <span style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600 }}>
                            {((report.ml_analysis.phishing_probability ?? 0) * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div style={{ height: 6, borderRadius: 3, background: 'var(--surface)', overflow: 'hidden' }}>
                          <div style={{ height: '100%', borderRadius: 3, width: `${(report.ml_analysis.phishing_probability ?? 0) * 100}%`, background: 'var(--cyan)', transition: 'width 0.4s' }} />
                        </div>
                      </div>
                    )}

                    {/* Semantic NLP */}
                    {report.semantic_analysis && (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                          <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>
                            {report.semantic_analysis.method === 'distilbert'
                              ? 'DistilBERT (semantic NLP)'
                              : 'Semantic NLP'}
                            <span style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginLeft: '0.5rem' }}>
                              {report.semantic_analysis.method === 'distilbert' ? '15% weight' : 'unavailable'}
                            </span>
                          </span>
                          <span style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600 }}>
                            {report.semantic_analysis.method === 'distilbert'
                              ? `${((report.semantic_analysis.semantic_prob ?? 0) * 100).toFixed(1)}%`
                              : '—'}
                          </span>
                        </div>
                        <div style={{ height: 6, borderRadius: 3, background: 'var(--surface)', overflow: 'hidden' }}>
                          <div style={{
                            height: '100%', borderRadius: 3,
                            width: report.semantic_analysis.method === 'distilbert' ? `${(report.semantic_analysis.semantic_prob ?? 0) * 100}%` : '0%',
                            background: 'var(--purple)', transition: 'width 0.4s',
                          }} />
                        </div>
                        {report.semantic_analysis.method === 'unavailable' && (
                          <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginTop: '0.25rem' }}>
                            Run ml/fine_tune.py to enable semantic detection
                          </p>
                        )}
                        {report.semantic_analysis.top_tokens?.length > 0 && (
                          <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                            {report.semantic_analysis.top_tokens.map((t, i) => (
                              <span key={i} style={{ padding: '0.125rem 0.5rem', borderRadius: 4, background: 'rgba(139,92,246,0.15)', color: 'var(--purple)', fontSize: '0.6875rem', fontWeight: 500 }}>
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                </div>
              )}

              {/* Threats */}
              {report?.threats?.length > 0 && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                    Detected Threats ({report.threats.length})
                  </h3>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {report.threats.map((t, i) => (
                      <span key={i} style={{
                        padding: '0.25rem 0.625rem', borderRadius: 6,
                        background: 'rgba(239,68,68,0.15)', color: '#EF4444',
                        fontSize: '0.75rem', fontWeight: 500,
                      }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* IOCs */}
              {report?.iocs?.length > 0 && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                    Indicators of Compromise ({report.iocs.length})
                  </h3>
                  <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {report.iocs.map((ioc, i) => {
                      const iocObj = typeof ioc === 'string' ? { value: ioc, type: 'ioc' } : ioc
                      const status = getIOCStatus(iocObj)
                      return (
                        <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', minWidth: 84 }}>
                            <span style={{ fontSize: '0.6875rem', color: '#06B6D4', fontWeight: 600, textTransform: 'uppercase' }}>
                              {iocObj.type || 'ioc'}
                            </span>
                            <span style={{ padding: '0.18rem 0.5rem', borderRadius: 9999, background: getColor(status) + '22', color: getColor(status), fontSize: '0.6875rem', fontWeight: 700, textTransform: 'capitalize', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', minWidth: 72 }}>
                              {status}
                            </span>
                          </div>
                          <span style={{ color: '#9CA3AF', fontSize: '0.8125rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                            {iocObj.value || ioc}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* ── Threat Intelligence ── */}
              {report?.threat_intel && Object.keys(report.threat_intel).length > 0 && (
                <>
                  {/* Header Deep-Dive */}
                  {report.threat_intel.header_deep_dive && (
                    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Email Header Deep-Dive</h3>
                        {report.threat_intel.header_deep_dive.severity && (
                          <span style={{
                            marginLeft: 'auto', padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 700,
                            background: { critical: '#EF444420', high: '#F9731620', medium: '#F59E0B20', low: '#06B6D420', none: 'var(--muted)20' }[report.threat_intel.header_deep_dive.severity] || 'var(--muted)20',
                            color: { critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#06B6D4', none: '#64748B' }[report.threat_intel.header_deep_dive.severity] || '#64748B',
                          }}>
                            {report.threat_intel.header_deep_dive.severity.toUpperCase()} RISK
                          </span>
                        )}
                      </div>

                      {/* Auth Results */}
                      {report.threat_intel.header_deep_dive.summary && (
                        <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', marginBottom: '1rem' }}>
                          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Sender Authenticity</p>
                          <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fit, minmax(${isMobile ? '90px' : '120px'}, 1fr))`, gap: '0.75rem' }}>
                            {[['SPF', report.threat_intel.header_deep_dive.summary.spf], ['DKIM', report.threat_intel.header_deep_dive.summary.dkim], ['DMARC', report.threat_intel.header_deep_dive.summary.dmarc]].map(([auth, val]) => (
                              <div key={auth} style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--card)', borderRadius: 6 }}>
                                <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>{auth}</p>
                                <p style={{ fontSize: '0.9375rem', fontWeight: 700, color: val === 'pass' ? '#10B981' : val === 'fail' ? '#EF4444' : '#64748B', textTransform: 'capitalize' }}>{val}</p>
                              </div>
                            ))}
                          </div>
                          <div style={{ marginTop: '0.75rem', display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '0.5rem', fontSize: '0.8125rem' }}>
                            <div><span style={{ color: '#64748B' }}>From: </span><span style={{ color: '#9CA3AF', fontFamily: 'monospace' }}>{report.threat_intel.header_deep_dive.summary.from || '—'}</span></div>
                            <div><span style={{ color: '#64748B' }}>Reply-To: </span><span style={{ color: '#9CA3AF', fontFamily: 'monospace' }}>{report.threat_intel.header_deep_dive.summary.reply_to || '—'}</span></div>
                            <div><span style={{ color: '#64748B' }}>Return-Path: </span><span style={{ color: '#9CA3AF', fontFamily: 'monospace' }}>{report.threat_intel.header_deep_dive.summary.return_path || '—'}</span></div>
                            <div><span style={{ color: '#64748B' }}>Orig. IP: </span><span style={{ color: '#9CA3AF', fontFamily: 'monospace' }}>{report.threat_intel.header_deep_dive.summary.originating_ip || '—'}</span></div>
                          </div>
                        </div>
                      )}

                      {/* Header Risk Flags */}
                      {report.threat_intel.header_deep_dive.flags?.length > 0 && (
                        <div>
                          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Risk Flags ({report.threat_intel.header_deep_dive.flags.length})</p>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                            {report.threat_intel.header_deep_dive.flags.map((flag, i) => (
                              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', borderRadius: 6, background: 'var(--surface)', borderLeft: `3px solid ${{ critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#06B6D4' }[flag.severity] || '#64748B'}` }}>
                                <span style={{ fontSize: '0.6875rem', color: { critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#06B6D4' }[flag.severity] || '#64748B', fontWeight: 700, textTransform: 'uppercase', minWidth: 55 }}>{flag.severity}</span>
                                <span style={{ color: '#9CA3AF', fontSize: '0.8125rem' }}>{flag.label}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Sender Reputation */}
                  {report.threat_intel.enrichment?.ip_reputation && (
                    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Sender Reputation</h3>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '1rem' }}>
                        {/* AbuseIPDB */}
                        {report.threat_intel.enrichment.ip_reputation.abuseipdb && report.threat_intel.enrichment.ip_reputation.abuseipdb.available && (
                          <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem' }}>
                            <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>AbuseIPDB</p>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
                              <div style={{ width: 60, height: 60, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 50 ? 'rgba(239,68,68,0.2)' : report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 25 ? 'rgba(249,115,22,0.2)' : 'rgba(16,185,129,0.2)' }}>
                                <span style={{ fontSize: '1.25rem', fontWeight: 'bold', color: report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 50 ? '#EF4444' : report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 25 ? '#F97316' : '#10B981' }}>
                                  {report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score}
                                </span>
                              </div>
                              <div>
                                <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, margin: 0 }}>
                                  {report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 50 ? 'Malicious' : report.threat_intel.enrichment.ip_reputation.abuseipdb.abuse_score >= 25 ? 'Suspicious' : 'Clean'}
                                </p>
                                <p style={{ color: '#64748B', fontSize: '0.6875rem', margin: 0 }}>{report.threat_intel.enrichment.ip_reputation.abuseipdb.total_reports || 0} reports · {report.threat_intel.enrichment.ip_reputation.abuseipdb.country_code || '—'}</p>
                              </div>
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                              {[
                                ['Whitelisted', report.threat_intel.enrichment.ip_reputation.abuseipdb.is_whitelisted],
                                ['Tor', report.threat_intel.enrichment.ip_reputation.abuseipdb.is_tor],
                                ['Proxy', report.threat_intel.enrichment.ip_reputation.abuseipdb.is_proxy],
                                ['VPN', report.threat_intel.enrichment.ip_reputation.abuseipdb.is_vpn],
                                ['Hosting', report.threat_intel.enrichment.ip_reputation.abuseipdb.is_hosting],
                              ].filter(([,v]) => v).map(([label]) => (
                                <span key={label} style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: '#F9731620', color: '#F97316', fontSize: '0.6875rem', fontWeight: 600 }}>{label}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {!report.threat_intel.enrichment.ip_reputation.abuseipdb?.available && (
                          <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
                            <p style={{ color: '#64748B', fontSize: '0.8125rem' }}>AbuseIPDB not configured</p>
                            <p style={{ color: '#4B5563', fontSize: '0.75rem' }}>Set ABUSEIPDB_API_KEY to enable</p>
                          </div>
                        )}

                        {/* Shodan */}
                        {report.threat_intel.enrichment.ip_reputation.shodan && report.threat_intel.enrichment.ip_reputation.shodan.available && (
                          <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem' }}>
                            <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Shodan</p>
                            <div style={{ fontSize: '0.8125rem', color: '#9CA3AF', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                              <div><span style={{ color: '#64748B' }}>Org: </span>{report.threat_intel.enrichment.ip_reputation.shodan.org || '—'}</div>
                              <div><span style={{ color: '#64748B' }}>ISP: </span>{report.threat_intel.enrichment.ip_reputation.shodan.isp || '—'}</div>
                              <div><span style={{ color: '#64748B' }}>OS: </span>{report.threat_intel.enrichment.ip_reputation.shodan.os || '—'}</div>
                              <div><span style={{ color: '#64748B' }}>Country: </span>{report.threat_intel.enrichment.ip_reputation.shodan.country || '—'}</div>
                              {report.threat_intel.enrichment.ip_reputation.shodan.ports?.length > 0 && (
                                <div><span style={{ color: '#64748B' }}>Open Ports: </span>
                                  <span style={{ fontFamily: 'monospace', color: '#F59E0B' }}>{report.threat_intel.enrichment.ip_reputation.shodan.ports.slice(0, 8).join(', ')}</span>
                                </div>
                              )}
                              {report.threat_intel.enrichment.ip_reputation.shodan.vulnerabilities?.length > 0 && (
                                <div>
                                  <span style={{ color: '#64748B' }}>Vulns: </span>
                                  {report.threat_intel.enrichment.ip_reputation.shodan.vulnerabilities.map(v => (
                                    <span key={v} style={{ padding: '0.1rem 0.35rem', borderRadius: 3, background: '#EF444420', color: '#EF4444', fontSize: '0.6875rem', marginLeft: '0.25rem' }}>{v}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Threat Feed — URL Checks */}
                  {report.threat_intel.enrichment?.urls?.length > 0 && (
                    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>URL Threat Feed Check</h3>
                        {report.threat_intel.enrichment.available?.length > 0 && (
                          <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: '#64748B' }}>
                            Powered by: {report.threat_intel.enrichment.available.join(', ')}
                          </span>
                        )}
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                        {report.threat_intel.enrichment.urls.map((u, i) => (
                          <div key={i} style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.875rem', borderLeft: `3px solid ${{ malicious: '#EF4444', suspicious: '#F59E0B', trusted: '#10B981', unknown: '#64748B' }[u.verdict] || '#64748B'}` }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: { malicious: '#EF4444', suspicious: '#F59E0B', trusted: '#10B981', unknown: '#64748B' }[u.verdict] || '#64748B' }}>{u.verdict}</span>
                              <span style={{ fontSize: '0.6875rem', color: '#64748B' }}>{u.severity}</span>
                              <span style={{ color: '#4B5563', fontSize: '0.6875rem', marginLeft: 'auto', fontFamily: 'monospace', wordBreak: 'break-all' }}>{u.url}</span>
                            </div>
                            {/* VT stats */}
                            {u.virustotal?.available && (
                              <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem', flexWrap: 'wrap' }}>
                                {u.virustotal.malicious > 0 && <span style={{ padding: '0.15rem 0.4rem', borderRadius: 3, background: '#EF444420', color: '#EF4444' }}>{u.virustotal.malicious} malicious</span>}
                                {u.virustotal.suspicious > 0 && <span style={{ padding: '0.15rem 0.4rem', borderRadius: 3, background: '#F59E0B20', color: '#F59E0B' }}>{u.virustotal.suspicious} suspicious</span>}
                                <span style={{ color: '#64748B' }}>{u.virustotal.total} total engines · VT</span>
                              </div>
                            )}
                            {/* Flags */}
                            {u.flags?.length > 0 && (
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.375rem' }}>
                                {u.flags.map((f, j) => (
                                  <span key={j} style={{ padding: '0.1rem 0.35rem', borderRadius: 3, background: 'var(--muted)20', color: '#94A3B8', fontSize: '0.6875rem' }}>{f.label}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* API Services Status */}
                  {report.threat_intel.enrichment?.available?.length > 0 && (
                    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                      <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                        Live Threat Intelligence Services
                      </h3>
                      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, 1fr)', gap: '0.75rem' }}>
                        {[
                          ['VirusTotal', report.threat_intel.enrichment.available.includes('VirusTotal')],
                          ['AbuseIPDB', report.threat_intel.enrichment.available.includes('AbuseIPDB')],
                          ['Shodan', report.threat_intel.enrichment.available.includes('Shodan')],
                          ['Hybrid Analysis', report.threat_intel.enrichment.available.includes('Hybrid Analysis')],
                        ].map(([name, active]) => (
                          <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.625rem 0.875rem', background: 'var(--surface)', borderRadius: 6 }}>
                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: active ? '#10B981' : '#4B5563' }} />
                            <span style={{ color: active ? '#9CA3AF' : '#4B5563', fontSize: '0.8125rem' }}>{name}</span>
                            <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: active ? '#10B981' : '#4B5563' }}>{active ? 'Active' : 'Not configured'}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* ── Attachment Sandbox Preview ── */}
              {(report?.attachment_analysis?.attachments?.length > 0 || report?.attachments?.length > 0) && (
                <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                    <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Attachment Sandbox Preview</h3>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {(() => {
                      const attachments = report?.attachment_analysis?.attachments || report?.attachments || []
                      return attachments.map((att, i) => {
                        const info = att.threat_intel || {}
                        return (
                          <div key={i} style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', borderLeft: `3px solid ${info.type_mismatch ? '#EF4444' : '#64748B'}` }}>
                            {/* File info */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                              <span style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>{att.filename || 'attachment'}</span>
                              {att.size && <span style={{ color: '#64748B', fontSize: '0.75rem' }}>{(att.size / 1024).toFixed(1)} KB</span>}
                              {info.detected_type && <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: 'var(--muted)20', color: '#94A3B8', fontSize: '0.6875rem' }}>{info.detected_type}</span>}
                              {info.type_mismatch && <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: '#EF444420', color: '#EF4444', fontSize: '0.6875rem', fontWeight: 700 }}>TYPE MISMATCH</span>}
                            </div>

                            {/* Hashes */}
                            {(info.sha256 || info.md5) && (
                              <div style={{ marginBottom: '0.75rem' }}>
                                <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>File Hashes</p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem', fontFamily: 'monospace', color: '#9CA3AF' }}>
                                  {info.sha256 && <div><span style={{ color: '#64748B', minWidth: 45, display: 'inline-block' }}>SHA256</span>{info.sha256}</div>}
                                  {info.md5 && <div><span style={{ color: '#64748B', minWidth: 45, display: 'inline-block' }}>MD5</span>{info.md5}</div>}
                                  {info.sha1 && <div><span style={{ color: '#64748B', minWidth: 45, display: 'inline-block' }}>SHA1</span>{info.sha1}</div>}
                                </div>
                              </div>
                            )}

                            {/* Magic bytes */}
                            {info.magic_signatures?.length > 0 && (
                              <div style={{ marginBottom: '0.75rem' }}>
                                <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>Magic Bytes / File Signature</p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                  {info.magic_signatures.map((sig, j) => (
                                    <div key={j} style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#9CA3AF' }}>
                                      <span style={{ color: '#64748B' }}>{sig.type}</span>
                                      <span style={{ color: '#4B5563', marginLeft: '0.5rem' }}>{sig.magic}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* VirusTotal + Hybrid Analysis results */}
                            {(info.virustotal?.available || info.hybrid_analysis?.available) && (
                              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '0.75rem' }}>
                                {info.virustotal?.available && (
                                  <div style={{ background: 'var(--card)', borderRadius: 6, padding: '0.75rem' }}>
                                    <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>VirusTotal</p>
                                    <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap', fontSize: '0.75rem', marginBottom: '0.375rem' }}>
                                      <span style={{ padding: '0.15rem 0.4rem', borderRadius: 3, background: '#EF444420', color: '#EF4444' }}>{info.virustotal.malicious} malicious</span>
                                      <span style={{ padding: '0.15rem 0.4rem', borderRadius: 3, background: '#F59E0B20', color: '#F59E0B' }}>{info.virustotal.suspicious} suspicious</span>
                                      <span style={{ padding: '0.15rem 0.4rem', borderRadius: 3, background: '#10B98120', color: '#10B981' }}>{info.virustotal.harmless} harmless</span>
                                    </div>
                                    <p style={{ color: '#64748B', fontSize: '0.6875rem' }}>
                                      {info.virustotal.type_description ? `Type: ${info.virustotal.type_description}` : `${info.virustotal.total} engines`}
                                    </p>
                                  </div>
                                )}
                                {info.hybrid_analysis?.available && (
                                  <div style={{ background: 'var(--card)', borderRadius: 6, padding: '0.75rem' }}>
                                    <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Hybrid Analysis</p>
                                    <p style={{ color: info.hybrid_analysis.verdict === 'malicious' ? '#EF4444' : info.hybrid_analysis.verdict === 'suspicious' ? '#F59E0B' : '#9CA3AF', fontSize: '0.875rem', fontWeight: 600, textTransform: 'capitalize', margin: 0 }}>
                                      {info.hybrid_analysis.verdict}
                                    </p>
                                    {info.hybrid_analysis.vx_family?.length > 0 && (
                                      <p style={{ color: '#EF4444', fontSize: '0.75rem', margin: 0 }}>Family: {info.hybrid_analysis.vx_family.join(', ')}</p>
                                    )}
                                    {info.hybrid_analysis.av_malicious && info.hybrid_analysis.av_malicious !== 'N/A' && (
                                      <p style={{ color: '#64748B', fontSize: '0.6875rem' }}>AV: {info.hybrid_analysis.av_malicious}</p>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* PE flags / suspicious strings */}
                            {(info.pe_flags?.length > 0 || info.suspicious_strings?.length > 0) && (
                              <div>
                                <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>Behavioral Indicators</p>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                                  {(info.pe_flags || []).map((flag, j) => (
                                    <span key={j} style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: '#F9731620', color: '#F97316', fontSize: '0.6875rem' }}>{flag}</span>
                                  ))}
                                  {(info.suspicious_strings || []).slice(0, 8).map((s, j) => (
                                    <span key={j} style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: 'var(--muted)20', color: '#94A3B8', fontSize: '0.6875rem' }}>{s.kind}: {s.match}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )
                      })
                    })()}
                  </div>
                </div>
              )}

              {/* ── Comments & Flags ── */}
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>
                    Comments & Flags {comments.length > 0 && <span style={{ color: '#64748B', fontWeight: 400, fontSize: '0.875rem' }}>({comments.length})</span>}
                  </h3>
                  {comments.some(c => c.is_flag) && (
                    <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, background: '#EF444420', color: '#EF4444', fontSize: '0.6875rem', fontWeight: 700 }}>
                      {comments.filter(c => c.is_flag).length} FLAGGED
                    </span>
                  )}
                </div>

                {/* Add Comment */}
                <div style={{ marginBottom: '1.25rem' }}>
                  <textarea
                    placeholder="Add a note or flag this report for review..."
                    value={newComment}
                    onChange={e => setNewComment(e.target.value)}
                    rows={2}
                    style={{
                      width: '100%', padding: '0.75rem', borderRadius: 8,
                      border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)',
                      fontSize: '0.875rem', fontFamily: 'inherit', resize: 'vertical', marginBottom: '0.5rem',
                    }}
                  />
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={isFlag}
                        onChange={e => setIsFlag(e.target.checked)}
                        style={{ width: 14, height: 14, accentColor: '#EF4444' }}
                      />
                      <span style={{ color: isFlag ? '#EF4444' : '#64748B', fontSize: '0.8125rem', fontWeight: 500 }}>
                        Flag for review
                      </span>
                    </label>
                    <button
                      onClick={handleAddComment}
                      disabled={addingComment || !newComment.trim()}
                      style={{
                        padding: '0.5rem 1rem', borderRadius: 8, border: 'none',
                        background: addingComment || !newComment.trim() ? 'var(--muted)' : '#06B6D4',
                        color: newComment.trim() ? 'var(--text)' : '#64748B',
                        cursor: newComment.trim() ? 'pointer' : 'not-allowed',
                        fontSize: '0.8125rem', fontWeight: 600,
                      }}
                    >
                      {addingComment ? 'Posting...' : 'Post Comment'}
                    </button>
                  </div>
                </div>

                {/* Comments List */}
                {comments.length === 0 ? (
                  <p style={{ color: '#4B5563', fontSize: '0.875rem', textAlign: 'center', padding: '1rem 0' }}>No comments yet. Be the first to add one.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {comments.map(comment => (
                      <div key={comment.id} style={{
                        padding: '0.875rem', borderRadius: 8, background: 'var(--surface)',
                        borderLeft: `3px solid ${comment.is_flag ? '#EF4444' : 'var(--muted)'}`,
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
                          <div style={{ width: 24, height: 24, borderRadius: '50%', background: 'var(--muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text)', fontSize: '0.75rem', fontWeight: 600 }}>
                            {comment.username?.[0]?.toUpperCase() || '?'}
                          </div>
                          <span style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 500 }}>{comment.username}</span>
                          {comment.is_flag && (
                            <span style={{ padding: '0.1rem 0.375rem', borderRadius: 3, background: '#EF444420', color: '#EF4444', fontSize: '0.625rem', fontWeight: 700 }}>FLAGGED</span>
                          )}
                          <span style={{ color: '#4B5563', fontSize: '0.6875rem', marginLeft: 'auto' }}>{new Date(comment.created_at).toLocaleString()}</span>
                        </div>
                        <p style={{ color: '#9CA3AF', fontSize: '0.875rem', lineHeight: 1.5, margin: 0 }}>{comment.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}