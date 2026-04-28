import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import { updateProfile, getStats, getApiKeys, saveApiKeys, getBranding, saveBranding, getScheduledReports, createScheduledReport, deleteScheduledReport, exportHistoryCSV, exportHistoryXLSX, exportAnalytics } from '../services/api'

const DEFAULT_SERVICES = [
  { id: 'virustotal', label: 'VirusTotal', placeholder: 'Enter your VirusTotal API key', color: 'var(--cyan)' },
  { id: 'ipdb', label: 'IPDB (IPInfoDB)', placeholder: 'Enter your IPDB API key', color: 'var(--purple)' },
  { id: 'abuseipdb', label: 'AbuseIPDB', placeholder: 'Enter your AbuseIPDB API key', color: 'var(--red)' },
  { id: 'alienvault', label: 'AlienVault OTX', placeholder: 'Enter your AlienVault OTX API key', color: 'var(--amber)' },
  { id: 'hybrid', label: 'Hybrid Analysis', placeholder: 'Enter your Hybrid Analysis API key', color: 'var(--green)' },
  { id: 'urlscan', label: 'URLScan.io', placeholder: 'Enter your URLScan.io API key', color: 'var(--pink)' },
  { id: 'shodan', label: 'Shodan', placeholder: 'Enter your Shodan API key', color: 'var(--purple)' },
  { id: 'google', label: 'Google Safe Browsing', placeholder: 'Enter your Google Safe Browsing API key', color: 'var(--sub)' },
]

export default function Settings() {
  const { user, refreshUser } = useAuth()
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [loading, setLoading] = useState(false)
  const [msg, setMsg] = useState('')
  const [stats, setStats] = useState(null)

  // API Keys state
  const [keys, setKeys] = useState({}) // { [serviceId]: 'key_value' }
  const [visibleKeys, setVisibleKeys] = useState({}) // { [serviceId]: false }
  const [keysLoading, setKeysLoading] = useState(true)
  const [keysMsg, setKeysMsg] = useState('')
  const [customServiceLabel, setCustomServiceLabel] = useState('')
  const [customServiceKey, setCustomServiceKey] = useState('')
  const { success, error: showError } = useToast()

  // Branding state
  const [brand, setBrand] = useState({ company_name: '', logo_url: '', footer_text: '', primary_color: 'var(--cyan)' })
  const [brandMsg, setBrandMsg] = useState('')
  const [brandLoading, setBrandLoading] = useState(true)

  // Scheduled reports state
  const [scheduled, setScheduled] = useState([])
  const [schedLoading, setSchedLoading] = useState(true)
  const [newSchedEmail, setNewSchedEmail] = useState('')
  const [newSchedFreq, setNewSchedFreq] = useState('daily')
  const [newSchedFilter, setNewSchedFilter] = useState('')

  // Export state
  const [exportLoading, setExportLoading] = useState(false)

  useEffect(() => {
    loadStats()
    loadApiKeys()
    loadBranding()
    loadScheduled()
  }, [])

  const loadStats = async () => {
    try {
      const { data } = await getStats()
      setStats(data)
    } catch (err) {
      console.error(err)
    }
  }

  const loadApiKeys = async () => {
    setKeysLoading(true)
    try {
      const { data } = await getApiKeys()
      setKeys(data?.keys || {})
    } catch (err) {
      console.error(err)
    } finally {
      setKeysLoading(false)
    }
  }

  const loadBranding = async () => {
    setBrandLoading(true)
    try {
      const { data } = await getBranding()
      setBrand(data || { company_name: '', logo_url: '', footer_text: '', primary_color: 'var(--cyan)' })
    } catch { /* ignore */ }
    setBrandLoading(false)
  }

  const loadScheduled = async () => {
    setSchedLoading(true)
    try {
      const { data } = await getScheduledReports()
      setScheduled(data?.reports || [])
    } catch { /* ignore */ }
    setSchedLoading(false)
  }

  const saveBrandSettings = async () => {
    setBrandMsg('')
    try {
      await saveBranding(brand)
      setBrandMsg('Branding saved!')
      success('Branding updated')
    } catch { setBrandMsg('Failed to save branding') }
  }

  const addScheduledReport = async () => {
    if (!newSchedEmail) { showError('Enter an email address'); return }
    try {
      await createScheduledReport({ email: newSchedEmail, frequency: newSchedFreq, scan_filter: newSchedFilter })
      await loadScheduled()
      setNewSchedEmail('')
      success('Scheduled report created')
    } catch { showError('Failed to create scheduled report') }
  }

  const removeScheduledReport = async (id) => {
    try {
      await deleteScheduledReport(id)
      setScheduled(prev => prev.filter(s => s.id !== id))
      success('Scheduled report removed')
    } catch { showError('Failed to remove') }
  }

  const handleExport = async (type) => {
    setExportLoading(true)
    try {
      let res, filename
      if (type === 'csv')      { res = await exportHistoryCSV();      filename = 'scan_history.csv' }
      else if (type === 'xlsx') { res = await exportHistoryXLSX();     filename = 'scan_history.xlsx' }
      else                     { res = await exportAnalytics();       filename = 'analytics.xlsx' }
      const blob = new Blob([res.data], { type: res.headers['content-type'] })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
      URL.revokeObjectURL(url)
      success(`${type.toUpperCase()} exported successfully`)
    } catch { showError(`Export ${type} failed`) }
    setExportLoading(false)
  }

  const handleSave = async (e) => {
    e.preventDefault()
    setLoading(true)
    setMsg('')
    try {
      await updateProfile({ username, email })
      await refreshUser()
      setMsg('Profile updated successfully')
    } catch (err) {
      setMsg('Error updating profile')
    } finally {
      setLoading(false)
    }
  }

  const handleSaveKeys = async () => {
    setKeysMsg('')
    setKeysLoading(true)
    try {
      await saveApiKeys(keys)
      setKeysMsg({ text: 'API keys saved successfully', type: 'success' })
    } catch (err) {
      setKeysMsg({ text: 'Error saving API keys', type: 'error' })
    } finally {
      setKeysLoading(false)
    }
  }

  const handleKeyChange = (id, value) => {
    setKeys(prev => ({ ...prev, [id]: value }))
  }

  const handleAddCustomKey = () => {
    const label = customServiceLabel.trim().toLowerCase().replace(/\s+/g, '_')
    const key = customServiceKey.trim()
    if (!label || !key) return
    setKeys(prev => ({ ...prev, [label]: key }))
    setCustomServiceLabel('')
    setCustomServiceKey('')
  }

  const handleRemoveKey = (id) => {
    setKeys(prev => {
      const updated = { ...prev }
      delete updated[id]
      return updated
    })
  }

  const toggleVisible = (id) => {
    setVisibleKeys(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const getRoleColor = (role) => ({
    superadmin: 'var(--red)',
    admin: 'var(--amber)',
    user: 'var(--cyan)',
  }[role] || 'var(--sub)')

  const inputStyle = {
    width: '100%', padding: '0.75rem', borderRadius: 8,
    border: '1px solid var(--border)', background: 'var(--surface)',
    color: 'var(--text)', fontSize: '0.9375rem', outline: 'none',
  }

  const allServiceIds = [
    ...DEFAULT_SERVICES.map(s => s.id),
    ...Object.keys(keys).filter(id => !DEFAULT_SERVICES.find(s => s.id === id)),
  ]

  return (
    <div style={{ padding: '1.5rem' }}>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Settings</h1>
      <p style={{ color: 'var(--sub)', fontSize: '0.9375rem', marginBottom: '2rem' }}>Manage your profile and preferences</p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '1.5rem' }}>
        <div>
          {/* Profile Form */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Profile Information</h2>

            <form onSubmit={handleSave}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Username</label>
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} disabled={loading} style={inputStyle} />
              </div>

              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Email</label>
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={loading} style={inputStyle} />
              </div>

              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Role</label>
                <div style={{ padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{
                    padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem',
                    textTransform: 'uppercase', background: getRoleColor(user?.role) + '20',
                    color: getRoleColor(user?.role), fontWeight: 600,
                  }}>
                    {user?.role}
                  </span>
                  <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>Account type</span>
                </div>
              </div>

              {msg && (
                <div style={{
                  padding: '0.75rem', borderRadius: 8, marginBottom: '1rem',
                  background: msg.includes('Error') ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                  color: msg.includes('Error') ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem',
                }}>
                  {msg}
                </div>
              )}

              <button type="submit" disabled={loading} style={{
                width: '100%', padding: '0.75rem', borderRadius: 8,
                background: 'var(--cyan)', color: 'var(--text)', border: 'none',
                cursor: 'pointer', fontSize: '0.9375rem', fontWeight: 600,
                opacity: loading ? 0.7 : 1,
              }}>
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </form>
          </div>

          {/* API Keys Section */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>API Keys</h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>
                {Object.keys(keys).length} key{Object.keys(keys).length !== 1 ? 's' : ''} configured
              </span>
            </div>

            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1.25rem', lineHeight: 1.5 }}>
              Add API keys for external threat intelligence services. Keys are stored securely and used during email analysis.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
              {DEFAULT_SERVICES.map(service => (
                <div key={service.id} style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--sub)', fontSize: '0.8125rem', fontWeight: 500 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: service.color, display: 'inline-block', flexShrink: 0 }} />
                    {service.label}
                    {keys[service.id] && (
                      <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: 'var(--green)', fontWeight: 600, background: 'rgba(16,185,129,0.15)', padding: '0.1rem 0.4rem', borderRadius: 4 }}>
                        Active
                      </span>
                    )}
                  </label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <div style={{ flex: 1, position: 'relative' }}>
                      <input
                        type={visibleKeys[service.id] ? 'text' : 'password'}
                        value={keys[service.id] || ''}
                        onChange={e => handleKeyChange(service.id, e.target.value)}
                        placeholder={service.placeholder}
                        style={{ ...inputStyle, paddingRight: '2.5rem' }}
                      />
                      <button
                        type="button"
                        onClick={() => toggleVisible(service.id)}
                        style={{
                          position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)',
                          background: 'none', border: 'none', cursor: 'pointer', color: 'var(--sub)',
                          fontSize: '0.875rem', padding: 0,
                        }}
                      >
                        {visibleKeys[service.id] ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    {keys[service.id] && (
                      <button
                        type="button"
                        onClick={() => handleRemoveKey(service.id)}
                        style={{
                          padding: '0 0.875rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.3)',
                          background: 'rgba(239,68,68,0.1)', color: 'var(--red)', cursor: 'pointer',
                          fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap',
                        }}
                      >
                        Remove
                      </button>
                    )}
                  </div>
                </div>
              ))}

              {/* Custom API Keys */}
              {Object.entries(keys)
                .filter(([id]) => !DEFAULT_SERVICES.find(s => s.id === id))
                .map(([id, value]) => (
                  <div key={id} style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--sub)', fontSize: '0.8125rem', fontWeight: 500 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--sub)', display: 'inline-block', flexShrink: 0 }} />
                      {id.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                      <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: 'var(--green)', fontWeight: 600, background: 'rgba(16,185,129,0.15)', padding: '0.1rem 0.4rem', borderRadius: 4 }}>Active</span>
                    </label>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <div style={{ flex: 1, position: 'relative' }}>
                        <input
                          type={visibleKeys[id] ? 'text' : 'password'}
                          value={value}
                          onChange={e => handleKeyChange(id, e.target.value)}
                          style={{ ...inputStyle, paddingRight: '2.5rem' }}
                        />
                        <button
                          type="button"
                          onClick={() => toggleVisible(id)}
                          style={{
                            position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)',
                            background: 'none', border: 'none', cursor: 'pointer', color: 'var(--sub)',
                            fontSize: '0.875rem', padding: 0,
                          }}
                        >
                          {visibleKeys[id] ? 'Hide' : 'Show'}
                        </button>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveKey(id)}
                        style={{
                          padding: '0 0.875rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.3)',
                          background: 'rgba(239,68,68,0.1)', color: 'var(--red)', cursor: 'pointer',
                          fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap',
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))
              }

              {/* Add Custom Service */}
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                <input
                  type="text"
                  value={customServiceLabel}
                  onChange={e => setCustomServiceLabel(e.target.value)}
                  placeholder="Service name (e.g. MyService)"
                  style={{ ...inputStyle, flex: '1 1 150px', fontSize: '0.875rem', padding: '0.625rem 0.75rem' }}
                />
                <input
                  type="text"
                  value={customServiceKey}
                  onChange={e => setCustomServiceKey(e.target.value)}
                  placeholder="API key"
                  style={{ ...inputStyle, flex: '2 1 200px', fontSize: '0.875rem', padding: '0.625rem 0.75rem' }}
                />
                <button
                  type="button"
                  onClick={handleAddCustomKey}
                  disabled={!customServiceLabel.trim() || !customServiceKey.trim()}
                  style={{
                    padding: '0.625rem 1rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.4)',
                    background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', cursor: 'pointer',
                    fontSize: '0.875rem', fontWeight: 600, whiteSpace: 'nowrap',
                    opacity: (!customServiceLabel.trim() || !customServiceKey.trim()) ? 0.5 : 1,
                  }}
                >
                  + Add
                </button>
              </div>
            </div>

            {keysMsg && (
              <div style={{
                padding: '0.75rem', borderRadius: 8, marginTop: '1rem',
                background: keysMsg.type === 'error' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                color: keysMsg.type === 'error' ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem',
              }}>
                {keysMsg.text}
              </div>
            )}

            <button
              type="button"
              onClick={handleSaveKeys}
              disabled={keysLoading}
              style={{
                width: '100%', padding: '0.75rem', borderRadius: 8, marginTop: '1.25rem',
                background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer',
                fontSize: '0.9375rem', fontWeight: 600, opacity: keysLoading ? 0.7 : 1,
              }}
            >
              {keysLoading ? 'Saving...' : 'Save API Keys'}
            </button>
          </div>

          {/* ── Branding ── */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Branded Reports</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Customize logos and footer text in PDF exports</p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Company Name</label>
                <input value={brand.company_name} onChange={e => setBrand(b => ({...b, company_name: e.target.value}))}
                  style={{ width: '100%', padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} placeholder="Acme Corp" />
              </div>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Primary Color</label>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <input type="color" value={brand.primary_color} onChange={e => setBrand(b => ({...b, primary_color: e.target.value}))}
                    style={{ width: 44, height: 38, border: '1px solid var(--border)', borderRadius: 8, padding: 2, background: 'var(--surface)', cursor: 'pointer' }} />
                  <input value={brand.primary_color} onChange={e => setBrand(b => ({...b, primary_color: e.target.value}))}
                    style={{ flex: 1, padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} placeholder="var(--cyan)" />
                </div>
              </div>
            </div>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Logo URL (public image)</label>
              <input value={brand.logo_url} onChange={e => setBrand(b => ({...b, logo_url: e.target.value}))}
                style={{ width: '100%', padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} placeholder="https://example.com/logo.png" />
            </div>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Custom Footer Text</label>
              <textarea value={brand.footer_text} onChange={e => setBrand(b => ({...b, footer_text: e.target.value}))}
                rows={3} style={{ width: '100%', padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem', resize: 'vertical' }} placeholder="Confidential — Acme Corp Security Team" />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <button onClick={saveBrandSettings} style={{ padding: '0.625rem 1.25rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                Save Branding
              </button>
              {brandMsg && <span style={{ color: 'var(--green)', fontSize: '0.8125rem' }}>{brandMsg}</span>}
            </div>
          </div>

          {/* ── Scheduled Reports ── */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Scheduled Report Exports</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Auto-email PDF reports daily or weekly</p>

            {/* Add new */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px 140px auto', gap: '0.625rem', marginBottom: '1rem', alignItems: 'flex-end' }}>
              <input value={newSchedEmail} onChange={e => setNewSchedEmail(e.target.value)} placeholder="email@example.com"
                style={{ padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} />
              <select value={newSchedFreq} onChange={e => setNewSchedFreq(e.target.value)}
                style={{ padding: '0.625rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
              <input value={newSchedFilter} onChange={e => setNewSchedFilter(e.target.value)} placeholder="Filter (e.g. malicious)"
                style={{ padding: '0.625rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} />
              <button onClick={addScheduledReport} style={{ padding: '0.625rem 1rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                + Add
              </button>
            </div>

            {/* List */}
            {schedLoading ? <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>Loading...</p> : scheduled.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>No scheduled reports configured</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {scheduled.map(s => (
                  <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)' }}>
                    <div style={{ flex: 1 }}>
                      <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 500 }}>{s.email}</p>
                      <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>
                        {s.frequency} · {s.scan_filter ? `Filter: ${s.scan_filter}` : 'All verdicts'} · Next: {new Date(s.next_send_at).toLocaleDateString()}
                      </p>
                    </div>
                    <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600, background: s.is_active ? 'rgba(16,185,129,0.15)' : 'rgba(100,116,139,0.15)', color: s.is_active ? 'var(--green)' : 'var(--sub)' }}>
                      {s.is_active ? 'Active' : 'Inactive'}
                    </span>
                    <button onClick={() => removeScheduledReport(s.id)} style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: '0.875rem', padding: '0.25rem' }}>✕</button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── Export ── */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Export Data</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Download scan history and analytics as spreadsheet</p>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <button onClick={() => handleExport('csv')} disabled={exportLoading} style={{ padding: '0.75rem 1.25rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: exportLoading ? 0.6 : 1 }}>
                📋 Export History (CSV)
              </button>
              <button onClick={() => handleExport('xlsx')} disabled={exportLoading} style={{ padding: '0.75rem 1.25rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: exportLoading ? 0.6 : 1 }}>
                📊 Export History (XLSX)
              </button>
              <button onClick={() => handleExport('analytics')} disabled={exportLoading} style={{ padding: '0.75rem 1.25rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: exportLoading ? 0.6 : 1 }}>
                📈 Export Analytics
              </button>
            </div>
          </div>

          {/* Security */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Security</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginBottom: '1rem' }}>
              Password management is handled through your authentication provider.
            </p>
            <button disabled style={{
              width: '100%', padding: '0.75rem', borderRadius: 8,
              background: 'var(--border)', color: 'var(--sub)', border: 'none',
              cursor: 'not-allowed', fontSize: '0.9375rem', fontWeight: 600,
            }}>
              Change Password
            </button>
          </div>
        </div>

        {/* Stats Side Panel */}
        <div>
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Account Stats</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem', background: 'var(--surface)', borderRadius: 8 }}>
                <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>Total Scans</span>
                <span style={{ color: 'var(--cyan)', fontSize: '1rem', fontWeight: 600 }}>{stats?.total || 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem', background: 'var(--surface)', borderRadius: 8 }}>
                <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>Account Created</span>
                <span style={{ color: 'var(--text)', fontSize: '0.8125rem' }}>
                  {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem', background: 'var(--surface)', borderRadius: 8 }}>
                <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>User ID</span>
                <span style={{ color: 'var(--text)', fontSize: '0.8125rem', fontFamily: 'monospace' }}>{user?.id}</span>
              </div>
            </div>
          </div>

          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginTop: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '1.25rem', color: 'var(--amber)' }}>Tip</span>
              <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, margin: 0 }}>Tips</h3>
            </div>
            <ul style={{ color: 'var(--sub)', fontSize: '0.8125rem', paddingLeft: '1.25rem', margin: 0 }}>
              <li style={{ marginBottom: '0.5rem' }}>Use the Analyzer to scan suspicious emails</li>
              <li style={{ marginBottom: '0.5rem' }}>Check Analytics for threat trends</li>
              <li>Export reports for documentation</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}