import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import { useIsMobile } from '../hooks/useIsMobile'
import { updateProfile, getStats, getApiKeys, saveApiKeys, getBranding, saveBranding, getScheduledReports, createScheduledReport, deleteScheduledReport, exportHistoryCSV, exportHistoryXLSX, exportAnalytics, getPrivacySettings, savePrivacySettings, triggerCleanup, getImapAccounts, addImapAccount, deleteImapAccount, syncImapAccount, syncAllImap } from '../services/api'

function ActionButton({ label, desc, color, onClick, isMobile }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? color + '25' : color + '15',
        border: `1px solid ${hovered ? color + '60' : color + '30'}`,
        borderRadius: 12,
        padding: isMobile ? '0.875rem' : '1.25rem',
        cursor: 'pointer',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        transition: 'all 0.2s ease',
        transform: hovered ? 'translateY(-2px)' : 'translateY(0)',
        boxShadow: hovered ? `0 4px 12px ${color}20` : 'none',
      }}
    >
      <span style={{ color: color, fontWeight: 600, fontSize: '0.9375rem', display: 'block' }}>{label}</span>
      <p style={{ color: '#64748B', fontSize: '0.8125rem', margin: '0.5rem 0 0 0' }}>{desc}</p>
    </button>
  )
}

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

const TABS = [
  { id: 'account',      label: 'Account' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'reports',      label: 'Reports' },
  { id: 'privacy',      label: 'Privacy' },
]

export default function Settings() {
  const isMobile = useIsMobile()
  const { user, loading: authLoading, refreshUser } = useAuth()
  const [activeTab, setActiveTab] = useState('account')
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [loading, setLoading] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [msg, setMsg] = useState('')
  const [stats, setStats] = useState(null)

  // API Keys state
  const [keys, setKeys] = useState({})
  const [visibleKeys, setVisibleKeys] = useState({})
  const [keysLoading, setKeysLoading] = useState(true)
  const [keysMsg, setKeysMsg] = useState('')
  const [customServiceLabel, setCustomServiceLabel] = useState('')
  const [customServiceKey, setCustomServiceKey] = useState('')
  const { success, error: showError } = useToast()

  // Branding state
  const [brand, setBrand] = useState({ company_name: '', logo_url: '', footer_text: '', primary_color: '#06B6D4' })
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

  // Privacy state
  const [privacy, setPrivacy] = useState({ data_retention_days: 30, allow_analytics: false, auto_delete: true, tier2_consent: false })
  const [privacyLoading, setPrivacyLoading] = useState(true)
  const [privacyMsg, setPrivacyMsg] = useState('')
  const [lastCleanup, setLastCleanup] = useState(null)
  const [cleanupLoading, setCleanupLoading] = useState(false)

  // Legacy Privacy page state (migrated from Privacy.jsx)
  const [dataPolicy, setDataPolicy] = useState(true)
  const [anonymizedStats, setAnonymizedStats] = useState(true)
  const [showEmail, setShowEmail] = useState(false)

  // IMAP state
  const [imapAccounts, setImapAccounts] = useState([])
  const [imapLoading, setImapLoading] = useState(true)
  const [imapSyncing, setImapSyncing] = useState({})
  const [imapForm, setImapForm] = useState({ email_address: '', password: '', label: '', host: '', port: '', folder: 'INBOX', fetch_limit: 20 })
  const [imapFormOpen, setImapFormOpen] = useState(false)
  const [imapFormLoading, setImapFormLoading] = useState(false)
  const [imapGuideOpen, setImapGuideOpen] = useState(false)
  const [imapGuideProvider, setImapGuideProvider] = useState('gmail')
  const [imapSyncResults, setImapSyncResults] = useState({})

  useEffect(() => {
    if (authLoading) return
    loadStats()
    loadApiKeys()
    loadBranding()
    loadScheduled()
    loadPrivacy()
    loadImapAccounts()
  }, [authLoading])

  const loadStats = async () => {
    try { const { data } = await getStats(); setStats(data) } catch {}
  }

  const loadApiKeys = async () => {
    setKeysLoading(true)
    try { const { data } = await getApiKeys(); setKeys(data?.keys || {}) } catch {}
    setKeysLoading(false)
  }

  const loadBranding = async () => {
    setBrandLoading(true)
    try {
      const { data } = await getBranding()
      const loaded = data || { company_name: '', logo_url: '', footer_text: '', primary_color: '#06B6D4' }
      if (loaded.primary_color && loaded.primary_color.startsWith('var(')) loaded.primary_color = '#06B6D4'
      setBrand(loaded)
    } catch {}
    setBrandLoading(false)
  }

  const loadScheduled = async () => {
    setSchedLoading(true)
    try { const { data } = await getScheduledReports(); setScheduled(data?.reports || []) } catch {}
    setSchedLoading(false)
  }

  const saveBrandSettings = async () => {
    setBrandMsg('')
    try { await saveBranding(brand); setBrandMsg('Branding saved!'); success('Branding updated') }
    catch { setBrandMsg('Failed to save branding') }
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
      if (type === 'csv')       { res = await exportHistoryCSV();  filename = 'scan_history.csv' }
      else if (type === 'xlsx') { res = await exportHistoryXLSX(); filename = 'scan_history.xlsx' }
      else                      { res = await exportAnalytics();   filename = 'analytics.xlsx' }
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
    try { await updateProfile({ username, email }); await refreshUser(); setMsg('Profile updated successfully') }
    catch { setMsg('Error updating profile') }
    setLoading(false)
  }

  const handleSaveKeys = async () => {
    setKeysMsg('')
    setKeysLoading(true)
    try { await saveApiKeys(keys); setKeysMsg({ text: 'API keys saved successfully', type: 'success' }) }
    catch { setKeysMsg({ text: 'Error saving API keys', type: 'error' }) }
    setKeysLoading(false)
  }

  const handleKeyChange = (id, value) => setKeys(prev => ({ ...prev, [id]: value }))

  const handleAddCustomKey = () => {
    const label = customServiceLabel.trim().toLowerCase().replace(/\s+/g, '_')
    const key = customServiceKey.trim()
    if (!label || !key) return
    setKeys(prev => ({ ...prev, [label]: key }))
    setCustomServiceLabel('')
    setCustomServiceKey('')
  }

  const handleRemoveKey = (id) => {
    setKeys(prev => { const u = { ...prev }; delete u[id]; return u })
  }

  const toggleVisible = (id) => setVisibleKeys(prev => ({ ...prev, [id]: !prev[id] }))

  const loadPrivacy = async () => {
    setPrivacyLoading(true)
    try {
      const { data } = await getPrivacySettings()
      setPrivacy({ data_retention_days: data.data_retention_days, allow_analytics: data.allow_analytics, auto_delete: data.auto_delete, tier2_consent: data.tier2_consent ?? false })
      setLastCleanup(data.last_cleanup)
    } catch {}
    setPrivacyLoading(false)
  }

  const handleSavePrivacy = async () => {
    setPrivacyMsg('')
    try { await savePrivacySettings(privacy); setPrivacyMsg({ text: 'Privacy settings saved', type: 'success' }); success('Privacy settings updated') }
    catch { setPrivacyMsg({ text: 'Failed to save privacy settings', type: 'error' }) }
  }

  const handleCleanupNow = async () => {
    setCleanupLoading(true)
    try {
      const { data } = await triggerCleanup()
      setLastCleanup(new Date().toISOString())
      success(`Cleanup complete — ${data.deleted_scans} scan${data.deleted_scans !== 1 ? 's' : ''} removed`)
    } catch { showError('Cleanup failed') }
    setCleanupLoading(false)
  }

  const handleExportData = async () => {
    try {
      const { data } = await exportAnalytics()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `eta-data-export-${new Date().toISOString().split('T')[0]}.json`
      a.click()
      URL.revokeObjectURL(url)
      success('Data exported successfully')
    } catch { showError('Export failed') }
  }

  const handleClearData = async () => {
    if (window.confirm('Are you sure you want to delete all your scan history? This cannot be undone.')) {
      try {
        const { data } = await triggerCleanup()
        success(`All scans deleted — ${data.deleted_scans} scan${data.deleted_scans !== 1 ? 's' : ''} removed`)
      } catch { showError('Clear data failed') }
    }
  }

  const loadImapAccounts = async () => {
    setImapLoading(true)
    try { const { data } = await getImapAccounts(); setImapAccounts(data || []) } catch {}
    setImapLoading(false)
  }

  const handleAddImapAccount = async () => {
    if (!imapForm.email_address || !imapForm.password) { showError('Email and password are required'); return }
    setImapFormLoading(true)
    try {
      await addImapAccount({
        email_address: imapForm.email_address,
        password: imapForm.password,
        label: imapForm.label || undefined,
        host: imapForm.host || undefined,
        port: imapForm.port ? Number(imapForm.port) : undefined,
        folder: imapForm.folder,
        fetch_limit: Number(imapForm.fetch_limit) || 20,
      })
      await loadImapAccounts()
      setImapForm({ email_address: '', password: '', label: '', host: '', port: '', folder: 'INBOX', fetch_limit: 20 })
      setImapFormOpen(false)
      success('Email account connected')
    } catch (err) { showError(err?.response?.data?.detail || 'Failed to connect account') }
    setImapFormLoading(false)
  }

  const handleDeleteImapAccount = async (id) => {
    try { await deleteImapAccount(id); setImapAccounts(prev => prev.filter(a => a.id !== id)); success('Account removed') }
    catch { showError('Failed to remove account') }
  }

  const handleSyncImapAccount = async (id) => {
    setImapSyncing(prev => ({ ...prev, [id]: true }))
    try {
      const { data } = await syncImapAccount(id)
      await loadImapAccounts()
      setImapSyncResults(prev => ({ ...prev, [id]: data }))
      success(`Synced — ${data.fetched} email(s) fetched`)
    } catch (err) { showError(err?.response?.data?.detail || 'Sync failed') }
    setImapSyncing(prev => ({ ...prev, [id]: false }))
  }

  const handleSyncAll = async () => {
    setImapLoading(true)
    try {
      const { data } = await syncAllImap()
      await loadImapAccounts()
      const total = (data.accounts || []).reduce((s, a) => s + (a.fetched || 0), 0)
      success(`Sync complete — ${total} email(s) fetched across ${data.synced} account(s)`)
    } catch { showError('Sync all failed') }
    setImapLoading(false)
  }

  const getRoleColor = (role) => ({ superadmin: 'var(--red)', admin: 'var(--amber)', user: 'var(--cyan)' }[role] || 'var(--sub)')

  const inputStyle = {
    width: '100%', padding: '0.75rem', borderRadius: 8,
    border: '1px solid var(--border)', background: 'var(--surface)',
    color: 'var(--text)', fontSize: '0.9375rem', outline: 'none',
  }

  const card = { background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem' }

  const Toggle = ({ checked, onChange, label, color = 'var(--cyan)' }) => (
    <button
      type="button"
      onClick={onChange}
      style={{
        flexShrink: 0, width: 44, height: 24, minHeight: 0, minWidth: 0,
        borderRadius: 12, border: 'none', cursor: 'pointer', padding: 0,
        background: checked ? color : 'rgba(100,116,139,0.35)',
        position: 'relative', transition: 'background 0.2s', display: 'block',
      }}
      aria-label={label}
      aria-checked={checked}
      role="switch"
    >
      <span style={{
        position: 'absolute', top: 3, left: checked ? 23 : 3,
        width: 18, height: 18, borderRadius: '50%', background: '#fff',
        transition: 'left 0.2s', display: 'block', boxShadow: '0 1px 3px rgba(0,0,0,0.35)',
      }} />
    </button>
  )

  return (
    <div style={{ padding: isMobile ? '1rem' : '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.25rem' }}>Settings</h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.9375rem' }}>Manage your profile and preferences</p>
        </div>
        <button
          onClick={() => { setClearing(true); window.location.reload() }}
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

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: '1.75rem', overflowX: 'auto' }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '0.625rem 1.25rem',
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--cyan)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--cyan)' : 'var(--sub)',
              fontWeight: activeTab === tab.id ? 600 : 400,
              fontSize: '0.9375rem',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              transition: 'color 0.15s',
              marginBottom: -1,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Account tab ── */}
      {activeTab === 'account' && (
        <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '1.5rem', alignItems: 'start' }}>
          {/* Profile Form */}
          <div style={card}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Profile Information</h2>
            <form onSubmit={handleSave}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Username</label>
                <input type="text" value={username} onChange={e => setUsername(e.target.value)} disabled={loading} style={inputStyle} />
              </div>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Email</label>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} disabled={loading} style={inputStyle} />
              </div>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Role</label>
                <div style={{ padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', textTransform: 'uppercase', background: getRoleColor(user?.role) + '20', color: getRoleColor(user?.role), fontWeight: 600 }}>
                    {user?.role}
                  </span>
                  <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>Account type</span>
                </div>
              </div>
              {msg && (
                <div style={{ padding: '0.75rem', borderRadius: 8, marginBottom: '1rem', background: msg.includes('Error') ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', color: msg.includes('Error') ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem' }}>
                  {msg}
                </div>
              )}
              <button type="submit" disabled={loading} style={{ width: '100%', padding: '0.75rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.9375rem', fontWeight: 600, opacity: loading ? 0.7 : 1 }}>
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </form>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Account Stats */}
            <div style={card}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Account Stats</h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {[
                  { label: 'Total Scans', value: stats?.total || 0, color: 'var(--cyan)' },
                  { label: 'Account Created', value: user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A' },
                  { label: 'User ID', value: user?.id, mono: true },
                ].map(item => (
                  <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem', background: 'var(--surface)', borderRadius: 8 }}>
                    <span style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>{item.label}</span>
                    <span style={{ color: item.color || 'var(--text)', fontSize: item.color ? '1rem' : '0.8125rem', fontWeight: item.color ? 600 : 400, fontFamily: item.mono ? 'monospace' : 'inherit' }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Security */}
            <div style={card}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Security</h2>
              <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginBottom: '1rem' }}>
                Password management is handled through your authentication provider.
              </p>
              <button disabled style={{ width: '100%', padding: '0.75rem', borderRadius: 8, background: 'var(--border)', color: 'var(--sub)', border: 'none', cursor: 'not-allowed', fontSize: '0.9375rem', fontWeight: 600 }}>
                Change Password
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Integrations tab ── */}
      {activeTab === 'integrations' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* API Keys */}
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>API Keys</h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>
                {Object.keys(keys).length} key{Object.keys(keys).length !== 1 ? 's' : ''} configured
              </span>
            </div>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1.25rem', lineHeight: 1.5 }}>
              Add API keys for external threat intelligence services. Keys are stored securely and used during email analysis.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '0.875rem', marginBottom: '1rem' }}>
              {DEFAULT_SERVICES.map(service => (
                <div key={service.id} style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--sub)', fontSize: '0.8125rem', fontWeight: 500 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: service.color, display: 'inline-block', flexShrink: 0 }} />
                    {service.label}
                    {keys[service.id] && (
                      <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: 'var(--green)', fontWeight: 600, background: 'rgba(16,185,129,0.15)', padding: '0.1rem 0.4rem', borderRadius: 4 }}>Active</span>
                    )}
                  </label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <div style={{ flex: 1, position: 'relative' }}>
                      <input
                        type={visibleKeys[service.id] ? 'text' : 'password'}
                        value={keys[service.id] || ''}
                        onChange={e => handleKeyChange(service.id, e.target.value)}
                        placeholder={service.placeholder}
                        style={{ ...inputStyle, paddingRight: '2.5rem', fontSize: '0.875rem', padding: '0.625rem 2.5rem 0.625rem 0.75rem' }}
                      />
                      <button type="button" onClick={() => toggleVisible(service.id)}
                        style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--sub)', fontSize: '0.75rem', padding: 0 }}>
                        {visibleKeys[service.id] ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    {keys[service.id] && (
                      <button type="button" onClick={() => handleRemoveKey(service.id)}
                        style={{ padding: '0 0.75rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.1)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                        Remove
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Custom API keys */}
            {Object.entries(keys).filter(([id]) => !DEFAULT_SERVICES.find(s => s.id === id)).map(([id, value]) => (
              <div key={id} style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', marginBottom: '0.875rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--sub)', fontSize: '0.8125rem', fontWeight: 500 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--sub)', display: 'inline-block', flexShrink: 0 }} />
                  {id.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: 'var(--green)', fontWeight: 600, background: 'rgba(16,185,129,0.15)', padding: '0.1rem 0.4rem', borderRadius: 4 }}>Active</span>
                </label>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <div style={{ flex: 1, position: 'relative' }}>
                    <input type={visibleKeys[id] ? 'text' : 'password'} value={value} onChange={e => handleKeyChange(id, e.target.value)}
                      style={{ ...inputStyle, paddingRight: '2.5rem', fontSize: '0.875rem', padding: '0.625rem 2.5rem 0.625rem 0.75rem' }} />
                    <button type="button" onClick={() => toggleVisible(id)}
                      style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--sub)', fontSize: '0.75rem', padding: 0 }}>
                      {visibleKeys[id] ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <button type="button" onClick={() => handleRemoveKey(id)}
                    style={{ padding: '0 0.75rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.1)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    Remove
                  </button>
                </div>
              </div>
            ))}

            {/* Add custom service */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
              <input type="text" value={customServiceLabel} onChange={e => setCustomServiceLabel(e.target.value)} placeholder="Service name"
                style={{ ...inputStyle, flex: '1 1 150px', fontSize: '0.875rem', padding: '0.625rem 0.75rem' }} />
              <input type="text" value={customServiceKey} onChange={e => setCustomServiceKey(e.target.value)} placeholder="API key"
                style={{ ...inputStyle, flex: '2 1 200px', fontSize: '0.875rem', padding: '0.625rem 0.75rem' }} />
              <button type="button" onClick={handleAddCustomKey} disabled={!customServiceLabel.trim() || !customServiceKey.trim()}
                style={{ padding: '0.625rem 1rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.4)', background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600, whiteSpace: 'nowrap', opacity: (!customServiceLabel.trim() || !customServiceKey.trim()) ? 0.5 : 1 }}>
                + Add
              </button>
            </div>

            {keysMsg && (
              <div style={{ padding: '0.75rem', borderRadius: 8, marginBottom: '1rem', background: keysMsg.type === 'error' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', color: keysMsg.type === 'error' ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem' }}>
                {keysMsg.text}
              </div>
            )}
            <button type="button" onClick={handleSaveKeys} disabled={keysLoading}
              style={{ width: '100%', padding: '0.75rem', borderRadius: 8, marginTop: '0.75rem', background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.9375rem', fontWeight: 600, opacity: keysLoading ? 0.7 : 1 }}>
              {keysLoading ? 'Saving...' : 'Save API Keys'}
            </button>
          </div>

          {/* Connected Email Accounts */}
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Connected Email Accounts</h2>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {imapAccounts.length > 0 && (
                  <button onClick={handleSyncAll} disabled={imapLoading}
                    style={{ padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.4)', background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, opacity: imapLoading ? 0.6 : 1 }}>
                    {imapLoading ? 'Syncing...' : 'Sync All'}
                  </button>
                )}
                <button onClick={() => setImapFormOpen(o => !o)}
                  style={{ padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.4)', background: imapFormOpen ? 'rgba(6,182,212,0.15)' : 'rgba(6,182,212,0.08)', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600 }}>
                  {imapFormOpen ? 'Cancel' : '+ Connect Account'}
                </button>
              </div>
            </div>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem', lineHeight: 1.5 }}>
              Connect an IMAP mailbox to automatically fetch and scan incoming emails. Use an App Password for Gmail/Outlook — never your main password.
            </p>

            {imapFormOpen && (
              <div style={{ padding: '1rem', borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)', marginBottom: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '0.625rem' }}>
                  {[
                    { key: 'email_address', label: 'Email Address *', type: 'email', placeholder: 'you@gmail.com' },
                    { key: 'password', label: 'App Password *', type: 'password', placeholder: 'App password (not your main password)' },
                    { key: 'label', label: 'Label (optional)', type: 'text', placeholder: 'Work inbox' },
                    { key: 'folder', label: 'Folder', type: 'text', placeholder: 'INBOX' },
                    { key: 'host', label: 'IMAP Host (auto-detected)', type: 'text', placeholder: 'imap.gmail.com' },
                    { key: 'port', label: 'Port (default 993)', type: 'number', placeholder: '993' },
                  ].map(f => (
                    <div key={f.key}>
                      <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.25rem' }}>{f.label}</label>
                      <input type={f.type} value={imapForm[f.key]} onChange={e => setImapForm(fm => ({ ...fm, [f.key]: e.target.value }))} placeholder={f.placeholder}
                        style={{ ...inputStyle, fontSize: '0.875rem', padding: '0.625rem 0.75rem' }} />
                    </div>
                  ))}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <label style={{ color: 'var(--sub)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>Fetch limit — {imapForm.fetch_limit} emails</label>
                  <input type="range" min={5} max={100} value={imapForm.fetch_limit} onChange={e => setImapForm(f => ({ ...f, fetch_limit: Number(e.target.value) }))}
                    style={{ flex: 1, accentColor: 'var(--cyan)' }} />
                </div>

                {/* Setup guide */}
                <div style={{ borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden' }}>
                  <button onClick={() => setImapGuideOpen(o => !o)}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.625rem 0.875rem', background: 'rgba(6,182,212,0.06)', border: 'none', cursor: 'pointer', color: 'var(--cyan)', fontSize: '0.8125rem', fontWeight: 600 }}>
                    <span>Setup guide — how to get your App Password</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>{imapGuideOpen ? '▲ Hide' : '▼ Show'}</span>
                  </button>
                  {imapGuideOpen && (
                    <div style={{ padding: '1rem', background: 'var(--surface)', borderTop: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', gap: '0.375rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                        {[{ id: 'gmail', label: 'Gmail' }, { id: 'outlook', label: 'Outlook' }, { id: 'yahoo', label: 'Yahoo' }, { id: 'other', label: 'Other' }].map(p => (
                          <button key={p.id} onClick={() => setImapGuideProvider(p.id)}
                            style={{ padding: '0.3rem 0.75rem', borderRadius: 6, border: '1px solid var(--border)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, background: imapGuideProvider === p.id ? 'var(--cyan)' : 'transparent', color: imapGuideProvider === p.id ? '#0f172a' : 'var(--sub)' }}>
                            {p.label}
                          </button>
                        ))}
                      </div>

                      {imapGuideProvider === 'gmail' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                          <div style={{ padding: '0.625rem 0.875rem', borderRadius: 6, background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)', color: '#f59e0b', fontSize: '0.8125rem' }}>
                            Gmail blocks regular passwords for IMAP. You must use an App Password.
                          </div>
                          {[
                            { step: '1', title: 'Enable IMAP in Gmail', desc: 'Open Gmail → Gear icon → See all settings → Forwarding and POP/IMAP → Enable IMAP → Save Changes' },
                            { step: '2', title: 'Turn on 2-Step Verification', desc: 'Go to myaccount.google.com → Security → 2-Step Verification → Turn On (required for App Passwords)' },
                            { step: '3', title: 'Generate an App Password', desc: 'In Google Account → Security → search "App Passwords" → Select Mail → Other → name it "ETA" → Generate' },
                            { step: '4', title: 'Fill in the form', desc: 'Use your Gmail address + the 16-character app password (no spaces). Leave Host and Port blank — they are auto-detected.' },
                          ].map(s => (
                            <div key={s.step} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                              <span style={{ minWidth: 24, height: 24, borderRadius: '50%', background: 'var(--cyan)', color: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>{s.step}</span>
                              <div>
                                <div style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.125rem' }}>{s.title}</div>
                                <div style={{ color: 'var(--sub)', fontSize: '0.75rem', lineHeight: 1.5 }}>{s.desc}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {imapGuideProvider === 'outlook' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                          {[
                            { step: '1', title: 'Use your full email address', desc: 'Enter your full Outlook/Hotmail/Live address (e.g. yourname@outlook.com) as the Email Address.' },
                            { step: '2', title: 'Use your regular password', desc: 'Most personal Outlook accounts work with your normal Microsoft password. Leave Host blank — auto-detects outlook.office365.com.' },
                            { step: '3', title: 'If 2FA is enabled', desc: 'Go to account.microsoft.com → Security → Advanced security options → App passwords → Create a new app password.' },
                          ].map(s => (
                            <div key={s.step} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                              <span style={{ minWidth: 24, height: 24, borderRadius: '50%', background: 'var(--cyan)', color: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>{s.step}</span>
                              <div>
                                <div style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.125rem' }}>{s.title}</div>
                                <div style={{ color: 'var(--sub)', fontSize: '0.75rem', lineHeight: 1.5 }}>{s.desc}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {imapGuideProvider === 'yahoo' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                          {[
                            { step: '1', title: 'Generate a Yahoo App Password', desc: 'Go to Yahoo Account Security → Generate app password → select "Other app" → name it "ETA" → copy the password.' },
                            { step: '2', title: 'Fill in the form', desc: 'Email: yourname@yahoo.com · Password: the app password. Leave Host blank — auto-detects imap.mail.yahoo.com.' },
                          ].map(s => (
                            <div key={s.step} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                              <span style={{ minWidth: 24, height: 24, borderRadius: '50%', background: 'var(--cyan)', color: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>{s.step}</span>
                              <div>
                                <div style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.125rem' }}>{s.title}</div>
                                <div style={{ color: 'var(--sub)', fontSize: '0.75rem', lineHeight: 1.5 }}>{s.desc}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {imapGuideProvider === 'other' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', lineHeight: 1.6 }}>For custom domains, fill in the Host field manually.</p>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                                {['Provider', 'IMAP Host', 'Port'].map(h => (
                                  <th key={h} style={{ textAlign: 'left', padding: '0.375rem 0.5rem', color: 'var(--sub)', fontWeight: 600 }}>{h}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {[['iCloud','imap.mail.me.com','993'],['Zoho Mail','imap.zoho.com','993'],['Fastmail','imap.fastmail.com','993'],['ProtonMail','127.0.0.1 (Bridge)','1143'],['Custom','imap.yourdomain.com','993']].map(([provider, host, port]) => (
                                <tr key={provider} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                  <td style={{ padding: '0.375rem 0.5rem', color: 'var(--text)' }}>{provider}</td>
                                  <td style={{ padding: '0.375rem 0.5rem', color: 'var(--cyan)', fontFamily: 'monospace' }}>{host}</td>
                                  <td style={{ padding: '0.375rem 0.5rem', color: 'var(--sub)' }}>{port}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <button onClick={handleAddImapAccount} disabled={imapFormLoading || !imapForm.email_address || !imapForm.password}
                  style={{ padding: '0.625rem 1.25rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: '0.875rem', opacity: (imapFormLoading || !imapForm.email_address || !imapForm.password) ? 0.6 : 1 }}>
                  {imapFormLoading ? 'Connecting...' : 'Connect & Verify'}
                </button>
              </div>
            )}

            {imapLoading && imapAccounts.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>Loading...</p>
            ) : imapAccounts.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>No accounts connected yet</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                {imapAccounts.map(acc => {
                  const syncResult = imapSyncResults[acc.id]
                  const verdictColor = { malicious: 'var(--red)', suspicious: 'var(--amber)', safe: 'var(--green)' }
                  const verdictBg    = { malicious: 'rgba(239,68,68,0.12)', suspicious: 'rgba(245,158,11,0.12)', safe: 'rgba(16,185,129,0.12)' }
                  return (
                    <div key={acc.id} style={{ background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.875rem 1rem', flexWrap: 'wrap' }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{acc.label || acc.email_address}</p>
                          <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{acc.email_address} · {acc.folder} · {acc.host}:{acc.port}</p>
                          {acc.last_synced_at && <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginTop: '0.1rem' }}>Last synced: {new Date(acc.last_synced_at).toLocaleString()}</p>}
                        </div>
                        <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                          <button onClick={() => handleSyncImapAccount(acc.id)} disabled={imapSyncing[acc.id]}
                            style={{ padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.4)', background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, opacity: imapSyncing[acc.id] ? 0.6 : 1 }}>
                            {imapSyncing[acc.id] ? 'Syncing...' : 'Sync'}
                          </button>
                          <button onClick={() => handleDeleteImapAccount(acc.id)}
                            style={{ padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600 }}>
                            Remove
                          </button>
                        </div>
                      </div>
                      {syncResult?.results?.length > 0 && (
                        <div style={{ borderTop: '1px solid var(--border)', padding: '0.75rem 1rem' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.5rem' }}>
                            Last sync — {syncResult.fetched} email{syncResult.fetched !== 1 ? 's' : ''} scanned
                          </p>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                            {syncResult.results.map((r, i) => (
                              <div key={r.scan_id || i} style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', padding: '0.5rem 0.75rem', borderRadius: 6, background: 'var(--card)', border: `1px solid ${verdictColor[r.verdict] || 'var(--border)'}22` }}>
                                <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.625rem', fontWeight: 700, textTransform: 'uppercase', background: verdictBg[r.verdict] || 'rgba(100,100,100,0.1)', color: verdictColor[r.verdict] || 'var(--sub)', flexShrink: 0 }}>{r.verdict}</span>
                                <span style={{ flex: 1, color: 'var(--text)', fontSize: '0.8125rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.subject || `(no subject) — Email ${i + 1}`}</span>
                                <span style={{ color: verdictColor[r.verdict] || 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, flexShrink: 0 }}>{r.risk_score}/100</span>
                                <a href={`/reports/${r.scan_id}`} style={{ color: 'var(--cyan)', fontSize: '0.75rem', textDecoration: 'none', flexShrink: 0 }}>View</a>
                              </div>
                            ))}
                          </div>
                          {syncResult.errors?.length > 0 && (
                            <p style={{ color: 'var(--red)', fontSize: '0.75rem', marginTop: '0.5rem' }}>{syncResult.errors.length} email{syncResult.errors.length !== 1 ? 's' : ''} could not be processed</p>
                          )}
                        </div>
                      )}
                      {syncResult?.fetched === 0 && (
                        <div style={{ borderTop: '1px solid var(--border)', padding: '0.625rem 1rem' }}>
                          <p style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>No new emails found in this sync.</p>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Reports tab ── */}
      {activeTab === 'reports' && (
        <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '1.5rem', alignItems: 'start' }}>
          {/* Branding */}
          <div style={card}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Branded Reports</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Customize logos and footer text in PDF exports</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem', marginBottom: '1rem' }}>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Company Name</label>
                <input value={brand.company_name} onChange={e => setBrand(b => ({ ...b, company_name: e.target.value }))}
                  style={{ ...inputStyle, fontSize: '0.875rem', padding: '0.625rem 0.875rem' }} placeholder="Acme Corp" />
              </div>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Primary Color</label>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <input type="color" value={/^#[0-9a-fA-F]{6}$/.test(brand.primary_color) ? brand.primary_color : '#06B6D4'} onChange={e => setBrand(b => ({ ...b, primary_color: e.target.value }))}
                    aria-label="Pick primary color"
                    style={{ width: 44, height: 44, border: '1px solid var(--border)', borderRadius: 8, padding: 2, background: 'var(--surface)', cursor: 'pointer' }} />
                  <input value={brand.primary_color} onChange={e => setBrand(b => ({ ...b, primary_color: e.target.value }))}
                    style={{ flex: 1, padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} placeholder="#06B6D4" />
                </div>
              </div>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Logo URL (public image)</label>
                <input value={brand.logo_url} onChange={e => setBrand(b => ({ ...b, logo_url: e.target.value }))}
                  style={{ ...inputStyle, fontSize: '0.875rem', padding: '0.625rem 0.875rem' }} placeholder="https://example.com/logo.png" />
              </div>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.375rem' }}>Custom Footer Text</label>
                <textarea value={brand.footer_text} onChange={e => setBrand(b => ({ ...b, footer_text: e.target.value }))}
                  rows={3} style={{ ...inputStyle, fontSize: '0.875rem', padding: '0.625rem 0.875rem', resize: 'vertical' }} placeholder="Confidential — Acme Corp Security Team" />
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <button onClick={saveBrandSettings} style={{ padding: '0.625rem 1.25rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                Save Branding
              </button>
              {brandMsg && <span style={{ color: 'var(--green)', fontSize: '0.8125rem' }}>{brandMsg}</span>}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Scheduled Reports */}
            <div style={card}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Scheduled Report Exports</h2>
              <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Auto-email PDF reports daily or weekly</p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.625rem', marginBottom: '1rem', alignItems: 'flex-end' }}>
                <input value={newSchedEmail} onChange={e => setNewSchedEmail(e.target.value)} placeholder="email@example.com"
                  style={{ flex: '2 1 180px', padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} />
                <select value={newSchedFreq} onChange={e => setNewSchedFreq(e.target.value)}
                  style={{ flex: '1 1 100px', padding: '0.625rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
                <input value={newSchedFilter} onChange={e => setNewSchedFilter(e.target.value)} placeholder="Filter (optional)"
                  style={{ flex: '1 1 120px', padding: '0.625rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} />
                <button onClick={addScheduledReport} style={{ padding: '0.625rem 1rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                  + Add
                </button>
              </div>
              {schedLoading ? <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>Loading...</p> : scheduled.length === 0 ? (
                <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>No scheduled reports configured</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {scheduled.map(s => (
                    <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)' }}>
                      <div style={{ flex: 1 }}>
                        <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 500 }}>{s.email}</p>
                        <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{s.frequency} · {s.scan_filter ? `Filter: ${s.scan_filter}` : 'All verdicts'} · Next: {new Date(s.next_send_at).toLocaleDateString()}</p>
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

            {/* Export Data */}
            <div style={card}>
              <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Export Data</h2>
              <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1rem' }}>Download scan history and analytics as spreadsheet</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                {[
                  { type: 'csv',       label: 'Export History (CSV)' },
                  { type: 'xlsx',      label: 'Export History (XLSX)' },
                  { type: 'analytics', label: 'Export Analytics' },
                ].map(({ type, label }) => (
                  <button key={type} onClick={() => handleExport(type)} disabled={exportLoading}
                    style={{ padding: '0.75rem 1.25rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500, textAlign: 'left', opacity: exportLoading ? 0.6 : 1 }}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Privacy tab ── */}
      {activeTab === 'privacy' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: 680 }}>
          <div style={card}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>Privacy & Data</h2>
            <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '1.25rem', lineHeight: 1.5 }}>
              All analysis runs locally on this server. External enrichment (VirusTotal, AbuseIPDB, Shodan) is opt-in only — enabling it sends URLs, IPs, and file hashes to those services.
            </p>

            {privacyLoading ? <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>Loading...</p> : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {/* External threat intel consent */}
                <div style={{ padding: '1rem', borderRadius: 8, background: privacy.tier2_consent ? 'rgba(245,158,11,0.08)' : 'var(--surface)', border: `1px solid ${privacy.tier2_consent ? 'rgba(245,158,11,0.3)' : 'var(--border)'}` }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem' }}>External Threat Intelligence</p>
                      <p style={{ color: 'var(--sub)', fontSize: '0.75rem', lineHeight: 1.5 }}>
                        Allow URLs, IPs, and file hashes to be sent to VirusTotal, AbuseIPDB, and Shodan for enrichment. Requires API keys to be configured in the Integrations tab.
                      </p>
                    </div>
                    <Toggle checked={privacy.tier2_consent} onChange={() => setPrivacy(p => ({ ...p, tier2_consent: !p.tier2_consent }))} label="Toggle external threat intelligence" color="var(--amber)" />
                  </div>
                  {privacy.tier2_consent && (
                    <p style={{ color: 'var(--amber)', fontSize: '0.6875rem', marginTop: '0.5rem', fontWeight: 500 }}>
                      Enabled — client data will be sent to configured external services during analysis
                    </p>
                  )}
                </div>

                {/* Auto-delete */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.875rem 1rem', borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem' }}>Auto-delete old scans</p>
                    <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>Automatically remove scans older than the retention period</p>
                  </div>
                  <Toggle checked={privacy.auto_delete} onChange={() => setPrivacy(p => ({ ...p, auto_delete: !p.auto_delete }))} label="Toggle auto-delete" />
                </div>

                {/* Retention days */}
                {privacy.auto_delete && (
                  <div>
                    <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                      Retention period — {privacy.data_retention_days} day{privacy.data_retention_days !== 1 ? 's' : ''}
                    </label>
                    <input type="range" min={1} max={365} value={privacy.data_retention_days}
                      onChange={e => setPrivacy(p => ({ ...p, data_retention_days: Number(e.target.value) }))}
                      style={{ width: '100%', accentColor: 'var(--cyan)' }} />
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--sub)', fontSize: '0.6875rem', marginTop: '0.25rem' }}>
                      <span>1 day</span><span>365 days</span>
                    </div>
                  </div>
                )}

                {/* Last cleanup */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                  <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>
                    Last cleanup: {lastCleanup ? new Date(lastCleanup).toLocaleString() : 'Never'}
                  </p>
                  <button type="button" onClick={handleCleanupNow} disabled={cleanupLoading || !privacy.auto_delete}
                    style={{ padding: '0.5rem 1rem', borderRadius: 8, border: '1px solid rgba(6,182,212,0.3)', background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, opacity: (cleanupLoading || !privacy.auto_delete) ? 0.5 : 1 }}>
                    {cleanupLoading ? 'Running...' : 'Run Cleanup Now'}
                  </button>
                </div>

                {privacyMsg && (
                  <div style={{ padding: '0.75rem', borderRadius: 8, background: privacyMsg.type === 'error' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', color: privacyMsg.type === 'error' ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem' }}>
                    {privacyMsg.text}
                  </div>
                )}

                <button type="button" onClick={handleSavePrivacy}
                  style={{ width: '100%', padding: '0.75rem', borderRadius: 8, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.9375rem', fontWeight: 600 }}>
                  Save Privacy Settings
                </button>
              </div>
            )}
          </div>

          {/* Data Collection Policy */}
          <div style={card}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Data Collection Policy</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
              {[
                { key: 'dataPolicy',     title: 'Data Collection',          desc: 'Allow collection of scan data for threat intelligence',          enabled: dataPolicy,     setEnabled: setDataPolicy },
                { key: 'anonymizedStats', title: 'Anonymized Statistics',    desc: 'Share anonymized threat statistics to improve detection',      enabled: anonymizedStats, setEnabled: setAnonymizedStats },
                { key: 'showEmail',      title: 'Show Email in Reports',   desc: 'Include email sender in generated reports',                  enabled: showEmail,     setEnabled: setShowEmail },
              ].map(f => (
                <div key={f.key} style={{
                  padding: '0.875rem 1rem', borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem',
                }}>
                  <div>
                    <p style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 500, marginBottom: '0.125rem' }}>{f.title}</p>
                    <p style={{ color: '#64748B', fontSize: '0.8125rem', margin: 0 }}>{f.desc}</p>
                  </div>
                  <Toggle checked={f.enabled} onChange={() => f.setEnabled(!f.enabled)} />
                </div>
              ))}
            </div>
          </div>

          {/* Data Management */}
          <div style={card}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>Data Management</h2>
            <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '1rem' }}>
              <ActionButton label="Export Data" desc="Download your scan data as JSON" color="#06B6D4" onClick={handleExportData} isMobile={isMobile} />
              <ActionButton label="Clear Data" desc="Delete all your scan history" color="#EF4444" onClick={handleClearData} isMobile={isMobile} />
            </div>
          </div>

          {/* Data Protection Info */}
          <div style={{ ...card, background: 'var(--surface)' }}>
            <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, margin: '0 0 0.75rem 0' }}>Data Protection</h3>
            <p style={{ color: '#64748B', fontSize: '0.875rem', lineHeight: 1.6, marginBottom: '0.75rem' }}>
              Your scan data is encrypted and stored securely. We never share your individual scan data with third parties without your explicit consent.
            </p>
            <p style={{ color: '#64748B', fontSize: '0.875rem', lineHeight: 1.6, margin: 0 }}>
              By selecting anonymized statistics, you help improve threat detection for everyone while keeping your identity protected.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
