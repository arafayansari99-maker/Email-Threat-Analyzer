import { useState, useEffect } from 'react'
import { analyzeEmail, getHistory } from '../services/api'
import { Link, useNavigate, useLocation } from 'react-router-dom'

export default function BatchResults() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState(null)
  const [recentBatches, setRecentBatches] = useState([])
  const navigate = useNavigate()
  const location = useLocation()

  // Reload recent batches when returning to this page
  useEffect(() => {
    loadRecentBatches()
  }, [location.key])

  const loadRecentBatches = async () => {
    try {
      const { data } = await getHistory(1, 5)
      setRecentBatches(data.records || [])
    } catch (err) {
      console.error(err)
    }
  }

  const handleFileChange = (e) => {
    const selected = Array.from(e.target.files || [])
    setFiles(selected)
    setResults(null)
  }

  const handleAnalyze = async () => {
    if (files.length === 0) return
    setLoading(true)
    setProgress(0)
    setResults(null)
    try {
      const { data } = await analyzeEmail(files, (p) => setProgress(p), true)
      setResults(data)
      // Reload recent batches after analysis
      loadRecentBatches()
    } catch (err) {
      console.error(err)
      alert('Batch analysis failed')
    } finally {
      setLoading(false)
      setProgress(0)
    }
  }

  const getColor = (v) => ({ malicious: '#EF4444', suspicious: '#F59E0B', safe: '#10B981' }[v] || '#64748B')
  const getBgColor = (v) => ({ malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }[v] || 'rgba(100,116,139,0.15)')

  return (
    <div style={{ padding: '1.5rem' }}>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Batch Analysis</h1>
      <p style={{ color: '#64748B', fontSize: '0.9375rem', marginBottom: '2rem' }}>Analyze multiple email files at once</p>

      {/* Upload Section */}
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid #1E2D40', padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Upload Emails</h2>
        <input
          type="file"
          multiple
          accept=".eml,.msg,.txt"
          onChange={handleFileChange}
          disabled={loading}
          style={{
            width: '100%',
            padding: '1rem',
            borderRadius: 8,
            border: '1px dashed #1E2D40',
            background: 'var(--surface)',
            color: '#94a3b8',
            marginBottom: '1rem'
          }}
        />

        {/* Selected Files */}
        {files.length > 0 && (
          <div style={{ marginBottom: '1rem' }}>
            <p style={{ color: '#64748B', fontSize: '0.8125rem', marginBottom: '0.5rem' }}>
              {files.length} file(s) selected
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {files.slice(0, 5).map((f, i) => (
                <span key={i} style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: '#1E2D40', color: 'var(--text)', fontSize: '0.75rem' }}>
                  {f.name}
                </span>
              ))}
              {files.length > 5 && (
                <span style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: '#1E2D40', color: '#64748B', fontSize: '0.75rem' }}>
                  +{files.length - 5} more
                </span>
              )}
            </div>
          </div>
        )}

        {/* Progress Bar */}
        {loading && (
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <span style={{ color: '#64748B', fontSize: '0.8125rem' }}>Analyzing...</span>
              <span style={{ color: '#06B6D4', fontSize: '0.8125rem' }}>{progress}%</span>
            </div>
            <div style={{ height: 6, background: '#1E2D40', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: progress + '%', background: '#06B6D4', transition: 'width 0.3s ease' }} />
            </div>
          </div>
        )}

        {/* Analyze Button */}
        <button
          onClick={handleAnalyze}
          disabled={loading || files.length === 0}
          style={{
            width: '100%',
            padding: '0.75rem',
            borderRadius: 8,
            background: loading || files.length === 0 ? '#1E2D40' : '#06B6D4',
            color: files.length === 0 ? '#64748B' : '#fff',
            border: 'none',
            cursor: files.length === 0 ? 'not-allowed' : 'pointer',
            fontSize: '0.9375rem',
            fontWeight: 600,
            opacity: loading ? 0.7 : 1
          }}
        >
          {loading ? 'Analyzing...' : 'Analyze Files'}
        </button>
      </div>

      {/* Results */}
      {results && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid #1E2D40', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Results</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
            {[
              { label: 'Total', value: results.total || files.length, color: '#06B6D4' },
              { label: 'Malicious', value: results.malicious || 0, color: '#EF4444' },
              { label: 'Suspicious', value: results.suspicious || 0, color: '#F59E0B' },
              { label: 'Safe', value: results.safe || 0, color: '#10B981' },
            ].map(stat => (
              <div key={stat.label} style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
                <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>{stat.label}</p>
                <p style={{ fontSize: '1.5rem', fontWeight: 'bold', color: stat.color }}>{stat.value}</p>
              </div>
            ))}
          </div>
          {results.results && results.results.length > 0 && (
            <div style={{ background: 'var(--surface)', borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1E2D40' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>File</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Verdict</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Score</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.slice(0, 10).map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #1E2D40' }}>
                      <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.8125rem' }}>{r.filename}</td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{ padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', textTransform: 'uppercase', background: getBgColor(r.verdict), color: getColor(r.verdict) }}>
                          {r.verdict}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', color: getColor(r.verdict), fontSize: '0.8125rem', fontWeight: 600 }}>{r.risk_score}</td>
                      <td style={{ padding: '0.75rem' }}>
                        {r.scan_id ? (
                          <Link to={`/report/${r.scan_id}`} style={{ color: '#06B6D4', fontSize: '0.8125rem', textDecoration: 'none' }}>
                            View Report →
                          </Link>
                        ) : (
                          <span style={{ color: '#64748B', fontSize: '0.8125rem' }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Recent Batches */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Recent Scans</h2>
          <Link to="/history" style={{ color: '#06B6D4', fontSize: '0.8125rem', textDecoration: 'none' }}>View All →</Link>
        </div>
        {recentBatches.length === 0 ? (
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid #1E2D40', padding: '2rem', textAlign: 'center' }}>
            <p style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>📭</p>
            <p style={{ color: '#64748B' }}>No scans yet</p>
          </div>
        ) : (
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid #1E2D40', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1E2D40' }}>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>File</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Verdict</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Date</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentBatches.map(r => (
                  <tr key={r.scan_id} style={{ borderBottom: '1px solid #1E2D40' }}>
                    <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.8125rem' }}>{r.filename}</td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{ padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', textTransform: 'uppercase', background: getBgColor(r.verdict), color: getColor(r.verdict) }}>
                        {r.verdict}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', color: '#64748B', fontSize: '0.8125rem' }}>{new Date(r.created_at).toLocaleDateString()}</td>
                    <td style={{ padding: '0.75rem' }}>
                      <Link to={`/report/${r.scan_id}`} style={{ color: '#06B6D4', fontSize: '0.8125rem', textDecoration: 'none' }}>
                        View Report →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}