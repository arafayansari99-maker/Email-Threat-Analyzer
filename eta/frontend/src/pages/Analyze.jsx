import { useState, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useToast } from '../hooks/useToast'
import { useAnalysisQueue } from '../hooks/useAnalysisQueue'
import { useIsMobile } from '../hooks/useIsMobile'

const MAX_FILE_SIZE = 300 * 1024 * 1024 // 300 MB

const VERDICT_COLOR  = { malicious: 'var(--red)', suspicious: 'var(--amber)', safe: '#10B981' }
const VERDICT_BG     = { malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }
const getColor  = v => VERDICT_COLOR[v]  || '#64748B'
const getBgColor = v => VERDICT_BG[v]    || 'rgba(100,116,139,0.15)'

// ── Shared sub-components ─────────────────────────────────────────────────────

function TabButton({ id, active, onClick, children }) {
  return (
    <button
      id={`tab-${id}`}
      role="tab"
      aria-selected={active}
      aria-controls={`tabpanel-${id}`}
      onClick={onClick}
      style={{
        padding: '0.75rem 1.25rem',
        borderRadius: 8,
        border: 'none',
        background: active ? 'var(--cyan)' : 'transparent',
        color: active ? '#fff' : '#64748B',
        fontSize: '0.9375rem',
        fontWeight: 600,
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        flexShrink: 0,
      }}
    >
      {children}
    </button>
  )
}

function ProgressBar({ progress, label }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
        <span style={{ color: '#64748B', fontSize: '0.8125rem' }}>{label}</span>
        <span style={{ color: 'var(--cyan)', fontSize: '0.8125rem' }}>{progress}%</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
        style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}
      >
        <div style={{ height: '100%', width: `${progress}%`, background: 'var(--cyan)', transition: 'width 0.3s ease' }} />
      </div>
    </div>
  )
}

function SubmitButton({ disabled, loading, children }) {
  return (
    <button
      type="submit"
      disabled={disabled}
      style={{
        width: '100%',
        padding: '0.875rem',
        borderRadius: 8,
        background: disabled ? 'var(--border)' : 'var(--cyan)',
        color: disabled ? '#64748B' : '#fff',
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
        fontSize: '0.9375rem',
        fontWeight: 600,
        opacity: loading ? 0.7 : 1,
        transition: 'background 0.2s',
      }}
    >
      {children}
    </button>
  )
}

function ErrorBanner({ message }) {
  if (!message) return null
  return (
    <div
      role="alert"
      style={{ color: 'var(--red)', fontSize: '0.8125rem', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}
    >
      {message}
    </div>
  )
}

function DropZone({ inputRef, label, hint, icon, summary, disabled, onDrop, onClick }) {
  const isMobile = useIsMobile()
  const [dragOver, setDragOver] = useState(false)

  const handleDragOver = (e) => { e.preventDefault(); setDragOver(true) }
  const handleDragLeave = () => setDragOver(false)
  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    onDrop(e.dataTransfer.files)
  }
  const handleKey = (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() }
  }

  return (
    <div style={{ marginBottom: '1rem' }}>
      <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {label}
      </label>
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label={`${label} — click or press Enter to browse`}
        aria-disabled={disabled}
        onClick={onClick}
        onKeyDown={handleKey}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          width: '100%',
          padding: isMobile ? '1.5rem 1rem' : '2.5rem 1rem',
          minHeight: isMobile ? '160px' : undefined,
          borderRadius: 8,
          border: `2px dashed ${dragOver ? 'var(--cyan)' : 'var(--border)'}`,
          background: dragOver ? 'rgba(6,182,212,0.05)' : 'var(--surface)',
          color: 'var(--sub)',
          fontSize: '0.9375rem',
          cursor: disabled ? 'not-allowed' : 'pointer',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.5rem',
          transition: 'border-color 0.2s, background 0.2s',
          outline: 'none',
          boxSizing: 'border-box',
        }}
        onFocus={e => { e.currentTarget.style.borderColor = 'var(--cyan)' }}
        onBlur={e => { if (!dragOver) e.currentTarget.style.borderColor = 'var(--border)' }}
      >
        {icon && <span aria-hidden="true" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', opacity: 0.5 }}>{icon}</span>}
        <span>{summary}</span>
        <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>{hint}</span>
      </div>
      {inputRef && <input ref={inputRef} type="file" style={{ display: 'none' }} aria-hidden="true" />}
    </div>
  )
}

function ResultCard({ result }) {
  const isMobile = useIsMobile()
  const phishingProb = (result.risk_score ?? 0) / 100

  const threats = result.header_analysis
    ? [
        ...(result.url_analysis?.indicators || []).filter(i => i.severity === 'critical' || i.severity === 'high').map(i => i.desc),
        ...(result.header_analysis?.indicators || []).filter(i => i.severity === 'critical' || i.severity === 'high').map(i => i.desc),
        ...(result.attachment_analysis?.indicators || []).filter(i => i.severity === 'critical').map(i => i.desc),
      ].filter(Boolean).slice(0, 5)
    : (result.indicators || []).map(i => (typeof i === 'string' ? i : i.desc)).filter(Boolean).slice(0, 5)

  return (
    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem', marginTop: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'var(--text)', margin: 0 }}>Analysis Result</h3>
        <span style={{
          padding: '0.375rem 0.875rem',
          borderRadius: 8,
          fontSize: '0.8125rem',
          fontWeight: 600,
          textTransform: 'uppercase',
          background: getBgColor(result.verdict),
          color: getColor(result.verdict),
        }}>
          {result.verdict}
        </span>
      </div>

      {/* Responsive 2-col → 1-col on small screens */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fit, minmax(${isMobile ? '120px' : '160px'}, 1fr))`, gap: '1rem', marginBottom: '1rem' }}>
        <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Risk Score</p>
          <p style={{ fontSize: '2rem', fontWeight: 'bold', color: getColor(result.verdict) }}>{result.risk_score}</p>
        </div>
        <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Phishing Prob.</p>
          <p style={{ fontSize: '2rem', fontWeight: 'bold', color: 'var(--text)' }}>{(phishingProb * 100).toFixed(1)}%</p>
        </div>
      </div>

      {threats.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Detected Threats</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {threats.map((t, i) => (
              <span key={i} style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: 'rgba(239,68,68,0.15)', color: 'var(--red)', fontSize: '0.75rem', fontWeight: 500 }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      <Link
        to={`/reports/${result.scan_id}`}
        style={{
          display: 'block',
          padding: '0.75rem',
          borderRadius: 8,
          background: 'var(--cyan)',
          color: '#fff',
          fontSize: '0.875rem',
          fontWeight: 600,
          textAlign: 'center',
          textDecoration: 'none',
        }}
      >
        View Full Report
      </Link>
    </div>
  )
}

// ── FileAnalyzer ──────────────────────────────────────────────────────────────

function FileAnalyzer() {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [retryCount, setRetryCount] = useState(0)
  const inputRef = useRef(null)

  const pickFile = () => inputRef.current?.click()

  const applyFile = (f) => {
    if (!f) return
    if (f.size > MAX_FILE_SIZE) { setError('File too large. Maximum size is 300 MB.'); return }
    setFile(f); setResult(null); setError(''); setRetryCount(0)
  }

  const handleChange = (e) => applyFile(e.target.files?.[0])

  const runAnalysis = async (fileToAnalyze) => {
    setLoading(true); setProgress(0); setError('')
    try {
      const fd = new FormData()
      fd.append('file', fileToAnalyze)
      const { data } = await api.post('/api/analyze-email', fd, {
        timeout: 180000,
        onUploadProgress: (e) => setProgress(Math.round((e.loaded * 100) / e.total)),
      })
      setResult(data)
      setRetryCount(0)
    } catch (err) {
      const isNetwork = !err.response
      const msg = err.response?.data?.detail || (isNetwork ? 'Network error — check your connection.' : 'Analysis failed.')
      setError(msg)
      if (isNetwork) setRetryCount(c => c + 1)
    } finally {
      setLoading(false); setProgress(0)
    }
  }

  const handleSubmit = (e) => { e.preventDefault(); if (file) runAnalysis(file) }
  const handleRetry  = ()  => { if (file) runAnalysis(file) }

  return (
    <form onSubmit={handleSubmit}>
      <DropZone
        inputRef={inputRef}
        label="Upload Email File (EML, MSG, TXT, PDF, CSV)"
        hint="EML · MSG · TXT · PDF · CSV — max 300 MB"
        icon={<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>}
        summary={file ? `${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)` : 'Click or drag-and-drop to select email file'}
        disabled={loading}
        onClick={pickFile}
        onDrop={(files) => applyFile(files[0])}
      />
      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg,.txt,.pdf,.csv"
        onChange={handleChange}
        disabled={loading}
        style={{ display: 'none' }}
        aria-hidden="true"
      />

      {error && (
        <div role="alert" style={{ marginBottom: '1rem', padding: '0.75rem 1rem', background: 'rgba(239,68,68,0.1)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
          <span style={{ color: 'var(--red)', fontSize: '0.8125rem' }}>{error}</span>
          {retryCount > 0 && retryCount <= 3 && (
            <button
              type="button"
              onClick={handleRetry}
              disabled={loading}
              style={{ padding: '0.375rem 0.875rem', borderRadius: 6, border: '1px solid rgba(239,68,68,0.4)', background: 'rgba(239,68,68,0.12)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, whiteSpace: 'nowrap' }}
            >
              Retry ({retryCount}/3)
            </button>
          )}
        </div>
      )}

      {loading && <ProgressBar progress={progress} label="Analyzing…" />}

      <SubmitButton disabled={loading || !file} loading={loading}>
        {loading ? 'Analyzing…' : 'Analyze File'}
      </SubmitButton>

      {result && <ResultCard result={result} />}
    </form>
  )
}

// ── BatchAnalyzer ─────────────────────────────────────────────────────────────

function BatchAnalyzer() {
  const isMobile = useIsMobile()
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState(null)
  const [error, setError] = useState('')
  const inputRef = useRef(null)
  const { success } = useToast()
  const navigate = useNavigate()
  const { clearDone } = useAnalysisQueue()

  const pickFiles = () => inputRef.current?.click()

  const applyFiles = (fileList) => {
    const valid = Array.from(fileList).filter(f => {
      if (f.size > MAX_FILE_SIZE) { setError(`${f.name} exceeds 300 MB`); return false }
      return true
    })
    setFiles(valid); setResults(null); setError('')
  }

  const handleChange = (e) => applyFiles(e.target.files || [])

  const handleAnalyze = async (e) => {
    e.preventDefault()
    if (!files.length) return
    setLoading(true); setProgress(0)
    try {
      const fd = new FormData()
      files.forEach(f => fd.append('files', f))
      const { data } = await api.post('/api/analyze-batch', fd, {
        timeout: 180000,
        onUploadProgress: (e) => setProgress(Math.round((e.loaded * 100) / e.total)),
      })
      setResults(data)
      success(`Batch complete: ${data.total ?? files.length} files — ${data.malicious ?? 0} malicious, ${data.suspicious ?? 0} suspicious, ${data.safe ?? 0} safe`)
      setTimeout(() => clearDone(), 10000)
    } catch (err) {
      setError(err.response?.data?.detail || 'Batch analysis failed')
    } finally {
      setLoading(false); setProgress(0)
    }
  }

  return (
    <form onSubmit={handleAnalyze}>
      <DropZone
        label="Upload Multiple Files (EML, MSG, TXT, PDF, CSV) — max 300 MB each"
        hint="EML · MSG · TXT · PDF · CSV"
        icon={<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>}
        summary={files.length > 0 ? `${files.length} file(s) selected` : 'Click or drag-and-drop to select multiple files'}
        disabled={loading}
        onClick={pickFiles}
        onDrop={applyFiles}
      />
      <input
        ref={inputRef}
        type="file"
        multiple
        accept=".eml,.msg,.txt,.pdf,.csv"
        onChange={handleChange}
        disabled={loading}
        style={{ display: 'none' }}
        aria-hidden="true"
      />

      {files.length > 0 && (
        <div style={{ marginBottom: '0.75rem' }}>
          <p style={{ color: '#64748B', fontSize: '0.8125rem', marginBottom: '0.5rem' }}>{files.length} file(s) selected</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', maxHeight: 100, overflowY: 'auto' }}>
            {files.slice(0, 5).map((f, i) => (
              <span key={i} style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: 'var(--border)', color: 'var(--text)', fontSize: '0.75rem' }}>
                {f.name}
              </span>
            ))}
            {files.length > 5 && (
              <span style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: 'var(--border)', color: '#64748B', fontSize: '0.75rem' }}>
                +{files.length - 5} more
              </span>
            )}
          </div>
        </div>
      )}

      <ErrorBanner message={error} />
      {loading && <ProgressBar progress={progress} label={`Analyzing ${files.length} files…`} />}

      <SubmitButton disabled={loading || files.length === 0} loading={loading}>
        {loading ? 'Analyzing…' : `Analyze ${files.length} File${files.length !== 1 ? 's' : ''}`}
      </SubmitButton>

      {results && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem', marginTop: '1.5rem' }}>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '1rem' }}>Batch Results</h3>

          {/* Responsive 4-col → 2-col → 1-col */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
            {[
              { label: 'Total',      value: results.total ?? files.length, color: 'var(--cyan)' },
              { label: 'Malicious',  value: results.malicious ?? 0,        color: 'var(--red)' },
              { label: 'Suspicious', value: results.suspicious ?? 0,       color: 'var(--amber)' },
              { label: 'Safe',       value: results.safe ?? 0,             color: '#10B981' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
                <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>{label}</p>
                <p style={{ color, fontSize: '1.5rem', fontWeight: 'bold' }}>{value}</p>
              </div>
            ))}
          </div>

          {results.results?.length > 0 && (
            <div style={{ overflowX: 'auto', maxHeight: 300, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 360 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['File', 'Verdict', 'Score'].map(h => (
                      <th key={h} style={{ padding: '0.5rem', textAlign: 'left', color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {results.results.slice(0, 20).map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.5rem', color: 'var(--text)', fontSize: '0.75rem', wordBreak: 'break-all' }}>{r.filename}</td>
                      <td style={{ padding: '0.5rem' }}>
                        <span style={{ padding: '0.125rem 0.375rem', borderRadius: 4, fontSize: '0.625rem', textTransform: 'uppercase', background: getBgColor(r.verdict), color: getColor(r.verdict) }}>
                          {r.verdict}
                        </span>
                      </td>
                      <td style={{ padding: '0.5rem', color: getColor(r.verdict), fontSize: '0.75rem', fontWeight: 600 }}>{r.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: isMobile ? '0.5rem' : '0.75rem', marginTop: '1rem' }}>
            <button
              type="button"
              onClick={() => navigate('/reports')}
              style={{ flex: '1 1 120px', padding: '0.75rem', borderRadius: 8, background: 'var(--cyan)', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}
            >
              View All Reports
            </button>
            <button
              type="button"
              onClick={() => { setFiles([]); setResults(null) }}
              style={{ flex: '1 1 120px', padding: '0.75rem', borderRadius: 8, background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}
            >
              Analyze More
            </button>
          </div>
        </div>
      )}
    </form>
  )
}

// ── TextAnalyzer ──────────────────────────────────────────────────────────────

function TextAnalyzer() {
  const [emailText, setEmailText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const inputStyle = {
    width: '100%',
    padding: '0.75rem',
    borderRadius: 8,
    border: '1px solid var(--border)',
    background: 'var(--surface)',
    color: 'var(--text)',
    fontSize: '0.9375rem',
    boxSizing: 'border-box',
  }

  const handleAnalyze = async (e) => {
    e.preventDefault()
    if (!emailText.trim()) { setError('Please paste email content to analyze'); return }
    setLoading(true); setError('')
    try {
      const { data } = await api.post('/api/extension-scan', { email_content: emailText }, { timeout: 180000 })
      setResult(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleAnalyze}>
      <div style={{ marginBottom: '1rem' }}>
        <label htmlFor="text-body" style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Paste full email content (recommended: include From:/Subject: headers)
        </label>
        <textarea
          id="text-body"
          placeholder="Paste email content here to analyze for malicious or suspicious content…"
          value={emailText}
          onChange={e => setEmailText(e.target.value)}
          disabled={loading}
          rows={10}
          style={{ ...inputStyle, fontFamily: 'inherit', resize: 'vertical' }}
        />
      </div>

      <ErrorBanner message={error} />

      <SubmitButton disabled={loading || !emailText.trim()} loading={loading}>
        {loading ? 'Analyzing…' : 'Analyze Text'}
      </SubmitButton>

      {result && <ResultCard result={result} />}
    </form>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export default function Analyze() {
  const isMobile = useIsMobile()
  const [activeTab, setActiveTab] = useState('file')
  const [clearing, setClearing] = useState(false)

  const handleRefresh = () => {
    setClearing(true)
    // Reload the page to reset all analysis state
    window.location.reload()
    setTimeout(() => setClearing(false), 1000)
  }

  const tabs = [
    { id: 'file',  label: 'Single File' },
    { id: 'batch', label: 'Batch Upload' },
    { id: 'text',  label: 'Text Analysis' },
  ]

  return (
    <div style={{ padding: isMobile ? '1rem' : '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Email Analyzer</h1>
          <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Analyze emails for threats using file upload or text input</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={clearing}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.375rem',
            padding: '0.5rem 1rem', borderRadius: 8,
            border: '1px solid var(--border)', background: 'var(--surface)',
            color: clearing ? 'var(--sub)' : 'var(--text)',
            fontSize: '0.8125rem', fontWeight: 600, cursor: clearing ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
          }}
        >
          <span style={{ display: 'inline-block', transition: 'transform 0.4s', transform: clearing ? 'rotate(360deg)' : 'none' }}>↻</span>
          {clearing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div
        role="tablist"
        aria-label="Analysis modes"
        style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}
      >
        {tabs.map(tab => (
          <TabButton key={tab.id} id={tab.id} active={activeTab === tab.id} onClick={() => setActiveTab(tab.id)}>
            {tab.label}
          </TabButton>
        ))}
      </div>

      <div
        id={`tabpanel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`tab-${activeTab}`}
        style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem' }}
      >
        {activeTab === 'file'  && <FileAnalyzer />}
        {activeTab === 'batch' && <BatchAnalyzer />}
        {activeTab === 'text'  && <TextAnalyzer />}
      </div>
    </div>
  )
}
