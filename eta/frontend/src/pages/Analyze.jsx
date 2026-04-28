import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useToast } from '../hooks/useToast'
import { useAnalysisQueue } from '../hooks/useAnalysisQueue'

const MAX_FILE_SIZE = 300 * 1024 * 1024 // 300 MB

function TabButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '0.75rem 1.5rem',
        borderRadius: 8,
        border: 'none',
        background: active ? 'var(--cyan)' : 'transparent',
        color: active ? '#fff' : '#64748B',
        fontSize: '0.9375rem',
        fontWeight: 600,
        cursor: 'pointer',
        transition: 'all 0.2s ease'
      }}
    >
      {children}
    </button>
  )
}

function ResultCard({ result }) {
  const getColor = (v) => ({ malicious: 'var(--red)', suspicious: 'var(--amber)', safe: '#10B981' }[v] || '#64748B')
  const getBgColor = (v) => ({ malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }[v] || 'rgba(100,116,139,0.15)')

  return (
    <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginTop: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'var(--text)', margin: 0 }}>Analysis Result</h3>
        <span style={{
          padding: '0.375rem 0.875rem',
          borderRadius: 8,
          fontSize: '0.8125rem',
          fontWeight: 600,
          textTransform: 'uppercase',
          background: getBgColor(result.verdict),
          color: getColor(result.verdict)
        }}>
          {result.verdict}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', marginBottom: '1rem' }}>
        <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Risk Score</p>
          <p style={{ fontSize: '2rem', fontWeight: 'bold', color: getColor(result.verdict) }}>{result.risk_score}</p>
        </div>
        <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.6875rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Phishing</p>
          <p style={{ fontSize: '2rem', fontWeight: 'bold', color: 'var(--text)' }}>{(result.phishing_prob * 100).toFixed(1)}%</p>
        </div>
      </div>

      {result.threats && result.threats.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Detected Threats</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {result.threats.map((t, i) => (
              <span key={i} style={{ padding: '0.25rem 0.625rem', borderRadius: 6, background: 'var(--red)20', color: 'var(--red)', fontSize: '0.75rem', fontWeight: 500 }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        <Link
          to={`/reports/${result.scan_id}`}
          style={{
            flex: 1,
            padding: '0.75rem',
            borderRadius: 8,
            background: 'var(--cyan)',
            color: 'var(--text)',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 600,
            textAlign: 'center',
            textDecoration: 'none',
            display: 'inline-block'
          }}
        >
          View Full Report
        </Link>
      </div>
    </div>
  )
}

function FileAnalyzer() {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleFileChange = (e) => {
    const f = e.target.files?.[0]
    if (f) {
      if (f.size > MAX_FILE_SIZE) {
        setError('File too large. Maximum size is 300MB.')
        return
      }
      setFile(f)
      setResult(null)
      setError('')
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setProgress(0)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const { data } = await api.post('/api/analyze-email', formData, {
        onUploadProgress: (e) => setProgress(Math.round((e.loaded * 100) / e.total))
      })
      console.log('API response:', data)
      setResult(data)
    } catch (err) {
      console.log('API error:', err)
      setError(err.response?.data?.detail || 'Analysis failed')
    } finally {
      setLoading(false)
      setProgress(0)
    }
  }

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Upload Email File (PDF, EML, MSG, TXT, CSV)
          </label>
          <div
            onClick={() => document.getElementById('single-file-input').click()}
            style={{
              width: '100%',
              padding: '2.5rem 1rem',
              borderRadius: 8,
              border: '2px dashed var(--border)',
              background: 'var(--surface)',
              color: 'var(--sub)',
              fontSize: '0.9375rem',
              cursor: 'pointer',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'border-color 0.2s, background 0.2s'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.borderColor = 'var(--cyan)'
              e.currentTarget.style.background = 'rgba(6,182,212,0.05)'
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.borderColor = 'var(--border)'
              e.currentTarget.style.background = 'var(--surface)'
            }}
          >
            <span style={{ fontSize: '1.5rem' }}>📧</span>
            <span>{file ? file.name : 'Click to select email file'}</span>
            <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>PDF, EML, MSG, TXT, CSV</span>
          </div>
          <input
            id="single-file-input"
            type="file"
            accept=".eml,.msg,.txt,.pdf,.csv"
            onChange={handleFileChange}
            disabled={loading}
            style={{ display: 'none' }}
          />
          {file && (
            <p style={{ color: 'var(--cyan)', fontSize: '0.8125rem', marginTop: '0.5rem', textAlign: 'center' }}>
              Selected: {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
            </p>
          )}
        </div>

        {error && (
          <div style={{ color: 'var(--red)', fontSize: '0.8125rem', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}>
            {error}
          </div>
        )}

        {loading && (
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <span style={{ color: '#64748B', fontSize: '0.8125rem' }}>Analyzing...</span>
              <span style={{ color: 'var(--cyan)', fontSize: '0.8125rem' }}>{progress}%</span>
            </div>
            <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: progress + '%', background: 'var(--cyan)', transition: 'width 0.3s ease' }} />
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !file}
          style={{
            width: '100%',
            padding: '0.875rem',
            borderRadius: 8,
            background: loading || !file ? 'var(--border)' : 'var(--cyan)',
            color: file ? '#fff' : '#64748B',
            border: 'none',
            cursor: file ? 'pointer' : 'not-allowed',
            fontSize: '0.9375rem',
            fontWeight: 600,
            opacity: loading ? 0.7 : 1
          }}
        >
          {loading ? 'Analyzing...' : 'Analyze File'}
        </button>
      </form>

      {result && <ResultCard result={result} />}
    </div>
  )
}

function BatchAnalyzer() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState(null)
  const [error, setError] = useState('')
  const { success, error: showError } = useToast()
  const navigate = useNavigate()
  const { jobs, addJob, clearDone } = useAnalysisQueue()

  useEffect(() => {
    const h = () => {
      if (jobs.some(j => j.status === 'processing')) {
        const active = jobs.find(j => j.status === 'processing')
        setProgress(active?.progress || 0)
      }
    }
    const int = setInterval(h, 500)
    return () => clearInterval(int)
  }, [jobs])

  const handleQueueComplete = useCallback((r) => {
    const total = results?.total || files.length
    const mal = results?.malicious || 0
    const sus = results?.suspicious || 0
    const safe = results?.safe || 0
    const msg = `Batch complete: ${total} files — ${mal} malicious, ${sus} suspicious, ${safe} safe`
    success(msg)
    // Auto-clear done jobs after 10s
    setTimeout(() => clearDone(), 10000)
  }, [results, files.length, success, clearDone])

  const handleFileChange = (e) => {
    const selected = Array.from(e.target.files || [])
    const validFiles = selected.filter(f => {
      if (f.size > MAX_FILE_SIZE) {
        setError(`File ${f.name} is too large (max 300MB)`)
        return false
      }
      return true
    })
    setFiles(validFiles)
    setResults(null)
    setError('')
  }

  const handleAnalyze = async () => {
    if (files.length === 0) return
    setLoading(true)
    setProgress(0)
    try {
      const formData = new FormData()
      files.forEach(f => formData.append('files', f))
      const { data } = await api.post('/api/analyze-batch', formData, {
        onUploadProgress: (e) => setProgress(Math.round((e.loaded * 100) / e.total))
      })
      setResults(data)
      // Show toast on batch completion
      const total = data.total || files.length
      const mal = data.malicious || 0
      const sus = data.suspicious || 0
      const safe = data.safe || 0
      success(`Batch complete: ${total} files — ${mal} malicious, ${sus} suspicious, ${safe} safe`)
    } catch (err) {
      setError(err.response?.data?.detail || 'Batch analysis failed')
    } finally {
      setLoading(false)
      setProgress(0)
    }
  }

  const getColor = (v) => ({ malicious: 'var(--red)', suspicious: 'var(--amber)', safe: '#10B981' }[v] || '#64748B')
  const getBgColor = (v) => ({ malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }[v] || 'rgba(100,116,139,0.15)')

  return (
    <div>
      <div style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Upload Multiple Files (PDF, EML, MSG, TXT, CSV) - Max 300MB each
        </label>
        <div
          onClick={() => document.getElementById('batch-file-input').click()}
          style={{
            width: '100%',
            padding: '2.5rem 1rem',
            borderRadius: 8,
            border: '2px dashed var(--border)',
            background: 'var(--surface)',
            color: 'var(--sub)',
            fontSize: '0.9375rem',
            cursor: 'pointer',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            transition: 'border-color 0.2s, background 0.2s'
          }}
          onMouseOver={(e) => {
            e.currentTarget.style.borderColor = 'var(--cyan)'
            e.currentTarget.style.background = 'rgba(6,182,212,0.05)'
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.borderColor = 'var(--border)'
            e.currentTarget.style.background = 'var(--surface)'
          }}
        >
          <span style={{ fontSize: '1.5rem' }}>📁</span>
          <span>{files.length > 0 ? `${files.length} file(s) selected` : 'Click to select multiple files'}</span>
          <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>PDF, EML, MSG, TXT, CSV - Max 300MB each</span>
        </div>
        <input
          id="batch-file-input"
          type="file"
          multiple
          accept=".eml,.msg,.txt,.pdf,.csv"
          onChange={handleFileChange}
          disabled={loading}
          style={{ display: 'none' }}
        />
        {files.length > 0 && (
          <div style={{ marginTop: '0.75rem' }}>
            <p style={{ color: '#64748B', fontSize: '0.8125rem', marginBottom: '0.5rem' }}>
              {files.length} file(s) selected
            </p>
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
      </div>

      {error && (
        <div style={{ color: 'var(--red)', fontSize: '0.8125rem', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}>
          {error}
        </div>
      )}

      {loading && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
            <span style={{ color: '#64748B', fontSize: '0.8125rem' }}>Analyzing {files.length} files...</span>
            <span style={{ color: 'var(--cyan)', fontSize: '0.8125rem' }}>{progress}%</span>
          </div>
          <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: progress + '%', background: 'var(--cyan)', transition: 'width 0.3s ease' }} />
          </div>
        </div>
      )}

      <button
        onClick={handleAnalyze}
        disabled={loading || files.length === 0}
        style={{
          width: '100%',
          padding: '0.875rem',
          borderRadius: 8,
          background: loading || files.length === 0 ? 'var(--border)' : 'var(--cyan)',
          color: files.length === 0 ? '#64748B' : '#fff',
          border: 'none',
          cursor: files.length === 0 ? 'not-allowed' : 'pointer',
          fontSize: '0.9375rem',
          fontWeight: 600,
          opacity: loading ? 0.7 : 1
        }}
      >
        {loading ? 'Analyzing...' : `Analyze ${files.length} File${files.length !== 1 ? 's' : ''}`}
      </button>

      {results && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginTop: '1.5rem' }}>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '1rem' }}>Batch Results</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1rem' }}>
            <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Total</p>
              <p style={{ color: 'var(--cyan)', fontSize: '1.5rem', fontWeight: 'bold' }}>{results.total || files.length}</p>
            </div>
            <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Malicious</p>
              <p style={{ color: 'var(--red)', fontSize: '1.5rem', fontWeight: 'bold' }}>{results.malicious || 0}</p>
            </div>
            <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Suspicious</p>
              <p style={{ color: 'var(--amber)', fontSize: '1.5rem', fontWeight: 'bold' }}>{results.suspicious || 0}</p>
            </div>
            <div style={{ background: 'var(--surface)', borderRadius: 8, padding: '0.75rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Safe</p>
              <p style={{ color: '#10B981', fontSize: '1.5rem', fontWeight: 'bold' }}>{results.safe || 0}</p>
            </div>
          </div>
          {results.results && results.results.length > 0 && (
            <div style={{ maxHeight: 300, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ padding: '0.5rem', textAlign: 'left', color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>File</th>
                    <th style={{ padding: '0.5rem', textAlign: 'left', color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Verdict</th>
                    <th style={{ padding: '0.5rem', textAlign: 'left', color: '#64748B', fontSize: '0.625rem', textTransform: 'uppercase' }}>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.slice(0, 20).map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.5rem', color: 'var(--text)', fontSize: '0.75rem' }}>{r.filename}</td>
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
          {results && results.results && results.results.length > 0 && (
            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem' }}>
              <button
                onClick={() => navigate('/reports')}
                style={{
                  flex: 1, padding: '0.75rem', borderRadius: 8,
                  background: 'var(--cyan)', color: '#fff', border: 'none',
                  cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
                }}
              >
                View All Reports
              </button>
              <button
                onClick={() => { setFiles([]); setResults(null) }}
                style={{
                  flex: 1, padding: '0.75rem', borderRadius: 8,
                  background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
                }}
              >
                Analyze More
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function TextAnalyzer() {
  const [emailText, setEmailText] = useState('')
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!emailText.trim()) {
      setError('Please paste email content to analyze')
      return
    }
    setLoading(true)
    setError('')
    try {
      const { data } = await api.post('/api/extension-scan', {
        email_content: emailText,
        sender: sender,
        subject: subject
      })
      console.log('Text analysis response:', data)
      setResult(data)
    } catch (err) {
      console.log('Text analysis error:', err)
      setError(err.response?.data?.detail || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Sender (optional)
        </label>
        <input
          type="text"
          placeholder="sender@example.com"
          value={sender}
          onChange={(e) => setSender(e.target.value)}
          disabled={loading}
          style={{
            width: '100%',
            padding: '0.75rem',
            borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--surface)',
            color: 'var(--text)',
            fontSize: '0.9375rem'
          }}
        />
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Subject (optional)
        </label>
        <input
          type="text"
          placeholder="Email subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          disabled={loading}
          style={{
            width: '100%',
            padding: '0.75rem',
            borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--surface)',
            color: 'var(--text)',
            fontSize: '0.9375rem'
          }}
        />
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Email Content *
        </label>
        <textarea
          placeholder="Paste email content here to analyze for malicious or suspicious content..."
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          disabled={loading}
          rows={10}
          style={{
            width: '100%',
            padding: '0.75rem',
            borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--surface)',
            color: 'var(--text)',
            fontSize: '0.9375rem',
            fontFamily: 'inherit',
            resize: 'vertical'
          }}
        />
      </div>

      {error && (
        <div style={{ color: 'var(--red)', fontSize: '0.8125rem', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: 8 }}>
          {error}
        </div>
      )}

      <button
        onClick={handleAnalyze}
        disabled={loading || !emailText.trim()}
        style={{
          width: '100%',
          padding: '0.875rem',
          borderRadius: 8,
          background: loading || !emailText.trim() ? 'var(--border)' : 'var(--cyan)',
          color: emailText.trim() ? '#fff' : '#64748B',
          border: 'none',
          cursor: emailText.trim() ? 'pointer' : 'not-allowed',
          fontSize: '0.9375rem',
          fontWeight: 600,
          opacity: loading ? 0.7 : 1
        }}
      >
        {loading ? 'Analyzing...' : 'Analyze Text'}
      </button>

      {result && <ResultCard result={result} />}
    </div>
  )
}

export default function Analyze() {
  const [activeTab, setActiveTab] = useState('file')

  const tabs = [
    { id: 'file', label: 'Single File' },
    { id: 'batch', label: 'Batch Upload' },
    { id: 'text', label: 'Text Analysis' }
  ]

  return (
    <div style={{ padding: '1.5rem' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Email Analyzer</h1>
        <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Analyze emails for threats using file upload or text input</p>
      </div>

      {/* Tab Buttons */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
        {tabs.map(tab => (
          <TabButton
            key={tab.id}
            active={activeTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </TabButton>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
        {activeTab === 'file' && <FileAnalyzer />}
        {activeTab === 'batch' && <BatchAnalyzer />}
        {activeTab === 'text' && <TextAnalyzer />}
      </div>
    </div>
  )
}