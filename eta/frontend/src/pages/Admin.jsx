import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import api, {
  getAuditLogs, getAdminStats, getAPIUsage, getAdminConfig, updateAdminConfig, getHealth,
  getDashboardActivity, getDashboardUsers, getPendingUsers, getDashboardTrends,
  approveUser, deleteUser, updateUserRole, bulkDeleteScans, exportAdminData,
  getWidgetOrder, saveWidgetOrder
} from '../services/api'

const ADMIN_WIDGET_REGISTRY = {
  threat_stats: { icon: '📊', title: 'Stats Cards', label: 'threat_stats' },
  verdict_chart: { icon: '🥧', title: 'Verdict Chart', label: 'verdict_chart' },
  recent_scans: { icon: '📋', title: 'Recent Scans', label: 'recent_scans' },
  quick_analyze: { icon: '⚡', title: 'Quick Analyze', label: 'quick_analyze' },
  top_threats: { icon: '🚨', title: 'Top Threats', label: 'top_threats' },
  activity_feed: { icon: '🔔', title: 'Activity Feed', label: 'activity_feed' },
}

const DEFAULT_ADMIN_WIDGET_ORDER = ['threat_stats', 'verdict_chart', 'recent_scans', 'quick_analyze', 'top_threats', 'activity_feed']

const ACTION_COLORS = {
  user_delete: 'var(--red)', user_approve: 'var(--green)', scan_delete: 'var(--amber)',
  config_update: 'var(--purple)', role_change: 'var(--cyan)', default: 'var(--sub)',
}
const getActionColor = (a) => ACTION_COLORS[a] || ACTION_COLORS.default

// Quick stats cards for dashboard
const StatCard = ({ icon, label, value, color, onClick }) => (
  <div onClick={onClick} style={{
    background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)',
    padding: '1.25rem', cursor: onClick ? 'pointer' : 'default',
    transition: 'transform 0.2s', ...(onClick && { transform: 'translateY(-2px)' })
  }}>
    <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>{label}</p>
    <p style={{ color: color, fontSize: '1.5rem', fontWeight: 700 }}>{value}</p>
  </div>
)

export default function Admin() {
  const { user } = useAuth()
  const { success, error: showError } = useToast()
  const [tab, setTab] = useState('dashboard') // dashboard | users | audit | stats | api | config | health

  // Logs / Audit
  const [logs, setLogs] = useState([])
  const [logPage, setLogPage] = useState(1)
  const [logTotal, setLogTotal] = useState(0)
  const [logAction, setLogAction] = useState('')
  const [logLoading, setLogLoading] = useState(true)

  // Stats
  const [stats, setStats] = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)

  // API usage
  const [apiUsage, setApiUsage] = useState([])
  const [apiLimits, setApiLimits] = useState({})
  const [apiLoading, setApiLoading] = useState(true)

  // Config
  const [configKeys, setConfigKeys] = useState([])
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')
  const [configLoading, setConfigLoading] = useState(true)

  // Health
  const [health, setHealth] = useState(null)
  const [healthLoading, setHealthLoading] = useState(true)

  // Dashboard
  const [dashActivity, setDashActivity] = useState([])
  const [dashUsers, setDashUsers] = useState([])
  const [dashPending, setDashPending] = useState([])
  const [dashTrends, setDashTrends] = useState([])
  const [dashLoading, setDashLoading] = useState(true)

  // Widget order
  const [widgetOrder, setWidgetOrder] = useState(DEFAULT_ADMIN_WIDGET_ORDER)
  const [editMode, setEditMode] = useState(false)

  useEffect(() => { loadAuditLogs() }, [logPage, logAction])

  useEffect(() => { if (tab === 'dashboard') loadWidgetOrder() }, [tab])

  const loadWidgetOrder = async () => {
    try {
      const { data } = await getWidgetOrder()
      if (data?.order && Array.isArray(data.order)) setWidgetOrder(data.order)
    } catch {}
  }

  const saveOrder = async (newOrder) => {
    try { await saveWidgetOrder(newOrder) } catch {}
  }

  // Move widget up
  const moveUp = (idx) => {
    if (idx <= 0) return
    const n = [...widgetOrder]
    const temp = n[idx]
    n[idx] = n[idx - 1]
    n[idx - 1] = temp
    setWidgetOrder(n)
  }

  // Move widget down
  const moveDown = (idx) => {
    if (idx >= widgetOrder.length - 1) return
    const n = [...widgetOrder]
    const temp = n[idx]
    n[idx] = n[idx + 1]
    n[idx + 1] = temp
    setWidgetOrder(n)
  }

  // Users Management
  const [allUsers, setAllUsers] = useState([])
  const [userPage, setUserPage] = useState(1)
  const [userSearch, setUserSearch] = useState('')
  const [userLoading, setUserLoading] = useState(true)
  const [showRoleModal, setShowRoleModal] = useState(null)

  useEffect(() => { loadAuditLogs() }, [logPage, logAction])

  const loadAuditLogs = async () => {
    setLogLoading(true)
    try {
      const { data } = await getAuditLogs(logPage, 30, logAction)
      setLogs(data.logs || [])
      setLogTotal(data.total || 0)
    } catch { /* ignore */ }
    setLogLoading(false)
  }

  const loadStats = async () => {
    setStatsLoading(true)
    try { const { data } = await getAdminStats(); setStats(data) } catch {}
    setStatsLoading(false)
  }

  const loadAPIUsage = async () => {
    setApiLoading(true)
    try {
      const { data } = await getAPIUsage()
      setApiUsage(data.usage || [])
      setApiLimits(data.limits || {})
    } catch {}
    setApiLoading(false)
  }

  const loadConfig = async () => {
    setConfigLoading(true)
    try {
      const { data } = await getAdminConfig()
      setConfigKeys(Object.entries(data.config || {}).map(([k, v]) => ({ key: k, value: v })))
    } catch {}
    setConfigLoading(false)
  }

  const loadHealth = async () => {
    setHealthLoading(true)
    try { const { data } = await getHealth(); setHealth(data) } catch {}
    setHealthLoading(false)
  }

  const loadDashboard = async () => {
    setDashLoading(true)
    try {
      const [actRes, userRes, pendRes, trendRes] = await Promise.all([
        getDashboardActivity(15),
        getDashboardUsers(10),
        getPendingUsers(),
        getDashboardTrends(14)
      ])
      setDashActivity(actRes.data || [])
      setDashUsers(userRes.data || [])
      setDashPending(pendRes.data || [])
      setDashTrends(trendRes.data || [])
    } catch { /* ignore */ }
    setDashLoading(false)
  }

  const loadUsers = async () => {
    setUserLoading(true)
    try {
      const { data } = await api.get('/api/users/', { params: { page: userPage, limit: 20, ...(userSearch ? { search: userSearch } : {}) }})
      setAllUsers(Array.isArray(data) ? data : (data?.logs || []))
    } catch { /* ignore */ }
    setUserLoading(false)
  }

  useEffect(() => { loadUsers() }, [userPage, userSearch])

  // Load data when tab changes
  useEffect(() => {
    if (tab === 'dashboard') loadDashboard()
    if (tab === 'users') loadUsers()
    if (tab === 'audit') loadAuditLogs()
    if (tab === 'stats') loadStats()
    if (tab === 'api') loadAPIUsage()
    if (tab === 'config') loadConfig()
    if (tab === 'health') loadHealth()
  }, [tab])

  const handleNewConfig = async () => {
    if (!newKey.trim()) { showError('Key is required'); return }
    try {
      await updateAdminConfig(newKey.trim(), newVal)
      setNewKey(''); setNewVal('')
      await loadConfig()
      success('Config saved')
    } catch { showError('Failed to save config') }
  }

  const handleKeyEdit = async (key, val) => {
    try { await updateAdminConfig(key, val); success('Updated') }
    catch { showError('Failed to update') }
  }

  const tabs = [
    ['dashboard', '📈 Dashboard'], ['users', '👥 Users'], ['audit', '📋 Audit Log'], ['stats', '📊 Usage Stats'], ['api', '🔑 API Monitoring'],
    ['config', '⚙️ Config'], ['health', '💚 Health'],
  ]

  const isAdmin = user?.role === 'admin' || user?.role === 'superadmin'

  if (!isAdmin) return (
    <div style={{ padding: '3rem', textAlign: 'center' }}>
      <p style={{ color: 'var(--red)', fontSize: '1.25rem', fontWeight: 600 }}>Access Denied</p>
      <p style={{ color: 'var(--sub)', marginTop: '0.5rem' }}>Admin privileges required</p>
    </div>
  )

  return (
    <div style={{ padding: '1.5rem' }}>
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.25rem' }}>Admin Panel</h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>System administration, audit logs, and monitoring</p>
        </div>
        <button onClick={() => setEditMode(!editMode)} style={{ padding: '0.5rem 1rem', borderRadius: 8, border: '1px solid var(--border)', background: editMode ? 'var(--cyan)' : 'var(--surface)', color: editMode ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 500 }}>
          {editMode ? 'Done' : 'Customize'}
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0', marginBottom: '1.25rem', borderBottom: '1px solid var(--border)' }}>
        {tabs.map(([t, label]) => (
          <button key={t} onClick={() => setTab(t)}
            style={{ padding: '0.625rem 1.25rem', border: 'none', borderBottom: `2px solid ${tab === t ? 'var(--cyan)' : 'transparent'}`,
              background: 'transparent', color: tab === t ? 'var(--cyan)' : 'var(--sub)',
              cursor: 'pointer', fontSize: '0.875rem', fontWeight: tab === t ? 600 : 400, marginBottom: -1 }}>
            {label}
          </button>
        ))}
      </div>

      {/* ── Dashboard ── */}
      {tab === 'dashboard' && editMode && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem', marginBottom: '1.5rem' }}>
          <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '1rem' }}>Reorder Dashboard Widgets</h3>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {widgetOrder.map((wid, idx) => (
              <div key={wid} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '0.375rem 0.625rem' }}>
                <button disabled={idx === 0} onClick={() => moveUp(idx)}
                  style={{ background: 'none', border: 'none', color: idx === 0 ? 'var(--sub)' : 'var(--text)', cursor: idx === 0 ? 'not-allowed' : 'pointer', fontSize: '0.75rem', padding: '0 0.25rem' }}>⬆</button>
                <span style={{ fontSize: '0.8125rem', color: 'var(--text)' }}>{ADMIN_WIDGET_REGISTRY[wid]?.icon} {ADMIN_WIDGET_REGISTRY[wid]?.title}</span>
                <button disabled={idx === widgetOrder.length - 1} onClick={() => moveDown(idx)}
                  style={{ background: 'none', border: 'none', color: idx === widgetOrder.length - 1 ? 'var(--sub)' : 'var(--text)', cursor: idx === widgetOrder.length - 1 ? 'not-allowed' : 'pointer', fontSize: '0.75rem', padding: '0 0.25rem' }}>⬇</button>
              </div>
            ))}
          </div>
          <button onClick={() => { saveOrder(widgetOrder); setEditMode(false) }}
            style={{ marginTop: '1rem', padding: '0.5rem 1rem', borderRadius: 8, background: 'var(--cyan)', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
            Save & Exit
          </button>
        </div>
      )}

      {tab === 'dashboard' && (
        dashLoading ? (
          <div style={{ padding: '3rem', textAlign: 'center' }}>
            <p style={{ color: 'var(--sub)' }}>Loading dashboard...</p>
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>

            {/* Stats Cards */}
            <div style={{ gridColumn: '1 / -1', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <StatCard label="Total Users" value={dashUsers.length + dashPending.length} color="var(--cyan)" />
              <StatCard label="Pending Approvals" value={dashPending.length} color="var(--amber)" />
              <StatCard label="Recent Scans" value={dashTrends.reduce((s, t) => s + t.total, 0)} color="var(--green)" />
              <StatCard label="Threats Detected" value={dashTrends.reduce((s, t) => s + t.malicious, 0)} color="var(--red)" />
            </div>

            {/* Trend Chart */}
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem', gridColumn: '1 / -1' }}>
              <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '1rem' }}>📊 Scan Trends (Last 14 Days)</h3>
              {dashTrends.length > 0 ? (
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: 120 }}>
                  {dashTrends.map((d, i) => {
                    const maxVal = Math.max(...dashTrends.map(t => t.total), 1)
                    const h = maxVal > 0 ? (d.total / maxVal) * 100 : 0
                    const malH = maxVal > 0 ? (d.malicious / maxVal) * 100 : 0
                    return (
                      <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}>
                        <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
                          <div style={{ width: '100%', height: h, background: 'var(--cyan)', borderRadius: '2px 2px 0 0', opacity: 0.8 }} />
                          <div style={{ width: '100%', height: malH, background: 'var(--red)', borderRadius: '0 0 2px 2px' }} />
                        </div>
                        <span style={{ fontSize: '0.5625rem', color: 'var(--sub)', writingMode: 'vertical-rl', transform: 'rotate(180deg)', height: 40 }}>{d.date.slice(5)}</span>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <p style={{ color: 'var(--sub)' }}>No scan data available</p>
              )}
              <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.6875rem' }}>
                <span style={{ color: 'var(--cyan)' }}>● Total</span>
                <span style={{ color: 'var(--red)' }}>● Malicious</span>
              </div>
            </div>

            {/* Recent Activity */}
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>🔔 Recent Activity</h3>
              </div>
              {dashActivity.length === 0 ? (
                <p style={{ color: 'var(--sub)', padding: '1.5rem', textAlign: 'center' }}>No recent activity</p>
              ) : (
                <div style={{ maxHeight: 300, overflow: 'auto' }}>
                  {dashActivity.slice(0, 10).map(a => (
                    <div key={a.id} style={{ padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--cyan)', flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 500 }}>{a.username}</p>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem' }}>{a.action} {a.target_type && `on ${a.target_type}`}</p>
                      </div>
                      <span style={{ color: 'var(--sub)', fontSize: '0.6875rem', flexShrink: 0 }}>
                        {new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recent Users */}
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>👥 Recent Users</h3>
              </div>
              {dashUsers.length === 0 ? (
                <p style={{ color: 'var(--sub)', padding: '1.5rem', textAlign: 'center' }}>No users found</p>
              ) : (
                <div style={{ maxHeight: 300, overflow: 'auto' }}>
                  {dashUsers.map(u => (
                    <div key={u.id} style={{ padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 500 }}>{u.username}</p>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem' }}>{u.email}</p>
                      </div>
                      <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                        background: u.role === 'admin' || u.role === 'superadmin' ? 'rgba(0, 188, 212, 0.2)' : 'var(--muted)',
                        color: u.role === 'admin' || u.role === 'superadmin' ? 'var(--cyan)' : 'var(--sub)' }}>
                        {u.role}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Pending Approvals */}
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>⏳ Pending Approvals</h3>
                <span style={{ background: 'var(--amber)', color: 'var(--text)', padding: '0.125rem 0.5rem', borderRadius: 10, fontSize: '0.6875rem', fontWeight: 600 }}>
                  {dashPending.length}
                </span>
              </div>
              {dashPending.length === 0 ? (
                <p style={{ color: 'var(--sub)', padding: '1.5rem', textAlign: 'center' }}>No pending users</p>
              ) : (
                <div style={{ maxHeight: 300, overflow: 'auto' }}>
                  {dashPending.map(u => (
                    <div key={u.id} style={{ padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 500 }}>{u.username}</p>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem' }}>{u.email}</p>
                      </div>
                      <button
                        onClick={async () => {
                          try {
                            await approveUser(u.id)
                            success(`Approved ${u.username}`)
                            loadDashboard()
                          } catch { showError('Failed to approve user') }
                        }}
                        style={{ background: 'var(--green)', color: 'var(--text)', border: 'none', padding: '0.375rem 0.75rem', borderRadius: 6, cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600 }}>
                        Approve
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

          </div>
        )
      )}

      {/* ── Users Management ── */}
      {tab === 'users' && (
        <div>
          {/* Search & Actions */}
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <input
              value={userSearch}
              onChange={e => setUserSearch(e.target.value)}
              placeholder="Search users..."
              style={{ flex: '1 1 200px', padding: '0.5rem 0.75rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }}
            />
            <select
              onChange={async e => {
                const days = parseInt(e.target.value) || 30
                if (confirm(`Delete all scans older than ${days} days?`)) {
                  try {
                    const { data } = await bulkDeleteScans(days)
                    success(data.message)
                  } catch { showError('Failed to delete scans') }
                }
              }}
              style={{ padding: '0.5rem 0.75rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.8125rem' }}>
              <option value="">🗑️ Bulk Delete Scans</option>
              <option value="7">Delete older than 7 days</option>
              <option value="30">Delete older than 30 days</option>
              <option value="90">Delete older than 90 days</option>
            </select>
            <button
              onClick={async () => {
                try {
                  const { data } = await exportAdminData('users')
                  const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = 'users-export.json'
                  a.click()
                  success('Users exported')
                } catch { showError('Export failed') }
              }}
              style={{ padding: '0.5rem 1rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem' }}>
              📥 Export Users
            </button>
          </div>

          {/* Users Table */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
            {userLoading ? (
              <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>Loading...</p>
            ) : allUsers.length === 0 ? (
              <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>No users found</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['User', 'Role', 'Status', 'Approved', 'Joined', 'Actions'].map(h => (
                      <th key={h} style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {allUsers.map(u => (
                    <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.75rem' }}>
                        <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 500 }}>{u.username}</p>
                        <p style={{ color: 'var(--sub)', fontSize: '0.6875rem' }}>{u.email}</p>
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                          background: u.role === 'admin' || u.role === 'superadmin' ? 'rgba(0, 188, 212, 0.2)' : 'var(--muted)',
                          color: u.role === 'admin' || u.role === 'superadmin' ? 'var(--cyan)' : 'var(--sub)' }}>
                          {u.role}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{ color: u.is_active ? 'var(--green)' : 'var(--red)', fontSize: '0.8125rem' }}>
                          {u.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{ color: u.is_approved ? 'var(--green)' : 'var(--amber)', fontSize: '0.8125rem' }}>
                          {u.is_approved ? 'Approved' : 'Pending'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', color: 'var(--sub)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem', display: 'flex', gap: '0.375rem' }}>
                        {!u.is_approved && (
                          <button
                            onClick={async () => {
                              try { await approveUser(u.id); success('Approved'); loadUsers() }
                              catch { showError('Failed to approve') }
                            }}
                            style={{ background: 'var(--green)', color: 'var(--text)', border: 'none', padding: '0.25rem 0.5rem', borderRadius: 4, cursor: 'pointer', fontSize: '0.6875rem', fontWeight: 600 }}>
                            Approve
                          </button>
                        )}
                        <button
                          onClick={() => setShowRoleModal(u)}
                          style={{ background: 'var(--muted)', color: 'var(--text)', border: 'none', padding: '0.25rem 0.5rem', borderRadius: 4, cursor: 'pointer', fontSize: '0.6875rem' }}>
                          Role
                        </button>
                        <button
                          onClick={async () => {
                            if (confirm(`Delete user ${u.username}?`)) {
                              try { await deleteUser(u.id); success('Deleted'); loadUsers() }
                              catch { showError('Failed to delete') }
                            }
                          }}
                          style={{ background: 'var(--red)', color: 'var(--text)', border: 'none', padding: '0.25rem 0.5rem', borderRadius: 4, cursor: 'pointer', fontSize: '0.6875rem' }}>
                          Del
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', marginTop: '1rem' }}>
            <button onClick={() => setUserPage(p => Math.max(1, p-1))} disabled={userPage === 1}
              style={{ padding: '0.5rem 1rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem' }}>← Prev</button>
            <span style={{ padding: '0.5rem', color: 'var(--sub)', fontSize: '0.875rem' }}>Page {userPage}</span>
            <button onClick={() => setUserPage(p => p+1)} disabled={allUsers.length < 20}
              style={{ padding: '0.5rem 1rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem' }}>Next →</button>
          </div>

          {/* Role Modal */}
          {showRoleModal && (
            <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
              <div style={{ background: 'var(--card)', borderRadius: 12, padding: '1.5rem', maxWidth: 300, width: '90%' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Change Role for {showRoleModal.username}</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {['user', 'analyst', 'admin', 'superadmin'].map(r => (
                    <button
                      key={r}
                      onClick={async () => {
                        try {
                          await updateUserRole(showRoleModal.id, r)
                          success('Role updated')
                          setShowRoleModal(null)
                          loadUsers()
                        } catch { showError('Failed to update role') }
                      }}
                      style={{
                        padding: '0.625rem', borderRadius: 6, border: showRoleModal.role === r ? '2px solid var(--cyan)' : '1px solid var(--border)',
                        background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer', fontWeight: showRoleModal.role === r ? 600 : 400,
                        textTransform: 'capitalize'
                      }}>
                      {r}
                    </button>
                  ))}
                </div>
                <button onClick={() => setShowRoleModal(null)} style={{ marginTop: '1rem', width: '100%', padding: '0.625rem', borderRadius: 6, border: 'none', background: 'var(--muted)', color: 'var(--text)', cursor: 'pointer' }}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Audit Log ── */}
      {tab === 'audit' && (
        <div>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <label style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>Filter:</label>
            <select value={logAction} onChange={e => { setLogAction(e.target.value); setLogPage(1) }}
              style={{ padding: '0.375rem 0.75rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.8125rem' }}>
              <option value="">All actions</option>
              <option value="user_delete">User Delete</option>
              <option value="user_approve">User Approve</option>
              <option value="scan_delete">Scan Delete</option>
              <option value="config_update">Config Update</option>
              <option value="role_change">Role Change</option>
            </select>
            <span style={{ color: 'var(--sub)', fontSize: '0.75rem', marginLeft: 'auto' }}>{logTotal} entries</span>
          </div>

          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
            {logLoading ? <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>Loading...</p> : logs.length === 0 ? (
              <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>No audit logs found</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Timestamp', 'User ID', 'Action', 'Target', 'IP Address', 'Details'].map(h => (
                      <th key={h} style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {logs.map(log => (
                    <tr key={log.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.75rem', color: 'var(--sub)', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.8125rem' }}>#{log.user_id}</td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{ padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600, background: getActionColor(log.action) + '20', color: getActionColor(log.action) }}>
                          {log.action.replace('_', ' ')}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', color: 'var(--sub)', fontSize: '0.8125rem' }}>
                        {log.target_type}{log.target_id ? ` #${log.target_id}` : ''}
                      </td>
                      <td style={{ padding: '0.75rem', color: 'var(--sub)', fontSize: '0.75rem', fontFamily: 'monospace' }}>{log.ip_address || '—'}</td>
                      <td style={{ padding: '0.75rem', color: 'var(--sub)', fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {log.details ? JSON.stringify(log.details) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', marginTop: '1rem' }}>
            <button onClick={() => setLogPage(p => Math.max(1, p-1))} disabled={logPage === 1}
              style={{ padding: '0.5rem 1rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem' }}>← Prev</button>
            <span style={{ padding: '0.5rem', color: 'var(--sub)', fontSize: '0.875rem' }}>Page {logPage}</span>
            <button onClick={() => setLogPage(p => p+1)} disabled={logs.length < 30}
              style={{ padding: '0.5rem 1rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem' }}>Next →</button>
          </div>
        </div>
      )}

      {/* ── Usage Stats ── */}
      {tab === 'stats' && (
        statsLoading ? <p style={{ color: 'var(--sub)' }}>Loading...</p> : stats ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {[
              ['Total Scans', stats.total_scans, 'var(--cyan)'],
              ['This Month', stats.scans_this_month, 'var(--amber)'],
              ['Active Users (30d)', stats.active_users_30d, 'var(--green)'],
              ['Total Users', stats.total_users, 'var(--purple)'],
              ['Avg Risk Score', stats.avg_risk_score, 'var(--red)'],
              ['Malicious Rate', (stats.verdict_counts?.malicious || 0) + '/' + stats.total_scans + ' (' + Math.round((stats.verdict_counts?.malicious || 0) / Math.max(1, stats.total_scans) * 100) + '%)', 'var(--red)'],
            ].map(([label, val, color]) => (
              <div key={String(label)} style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
                <p style={{ color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>{label}</p>
                <p style={{ color: color, fontSize: '1.5rem', fontWeight: 700 }}>{val}</p>
              </div>
            ))}
          </div>
        ) : <p style={{ color: 'var(--sub)' }}>Stats unavailable</p>
      )}

      {/* ── API Rate Monitoring ── */}
      {tab === 'api' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
            {Object.entries(apiLimits).map(([svc, limit]) => {
              const usage = (apiUsage.filter(u => u.service === svc) || []).reduce((s, u) => s + u.requests, 0)
              const pct = limit > 0 ? Math.min(100, (usage / limit) * 100) : 0
              return (
                <div key={svc} style={{ background: 'var(--card)', borderRadius: 10, border: '1px solid var(--border)', padding: '1rem' }}>
                  <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, textTransform: 'capitalize', marginBottom: '0.375rem' }}>{svc}</p>
                  <div style={{ background: 'var(--muted)', borderRadius: 4, height: 6, marginBottom: '0.375rem', overflow: 'hidden' }}>
                    <div style={{ width: pct + '%', height: '100%', background: pct > 80 ? 'var(--red)' : pct > 50 ? 'var(--amber)' : 'var(--green)', borderRadius: 4, transition: 'width 0.5s ease' }} />
                  </div>
                  <p style={{ color: 'var(--sub)', fontSize: '0.6875rem' }}>{usage} / {limit}/hr ({Math.round(pct)}%)</p>
                </div>
              )
            })}
          </div>
          {apiUsage.length > 0 && (
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>Per-User API Usage</h3>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['User', 'Service', 'Total Requests'].map(h => (
                      <th key={h} style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {apiUsage.map((row, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.875rem' }}>{row.username} <span style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>#{row.user_id}</span></td>
                      <td style={{ padding: '0.75rem', color: 'var(--cyan)', fontSize: '0.8125rem', textTransform: 'capitalize' }}>{row.service}</td>
                      <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600 }}>{row.requests}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Config UI ── */}
      {tab === 'config' && (
        <div>
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem', marginBottom: '1rem' }}>
            <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.75rem' }}>Add / Update Config Key</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr auto', gap: '0.625rem', alignItems: 'flex-end' }}>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.6875rem', display: 'block', marginBottom: '0.25rem', textTransform: 'uppercase' }}>Key</label>
                <input value={newKey} onChange={e => setNewKey(e.target.value)} placeholder="MAINTENANCE_MODE"
                  style={{ width: '100%', padding: '0.5rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem', fontFamily: 'monospace' }} />
              </div>
              <div>
                <label style={{ color: 'var(--sub)', fontSize: '0.6875rem', display: 'block', marginBottom: '0.25rem', textTransform: 'uppercase' }}>Value</label>
                <input value={newVal} onChange={e => setNewVal(e.target.value)} placeholder="true"
                  style={{ width: '100%', padding: '0.5rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.875rem' }} />
              </div>
              <button onClick={handleNewConfig} style={{ padding: '0.5rem 1rem', borderRadius: 6, background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                Save
              </button>
            </div>
          </div>

          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
            {configLoading ? <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>Loading...</p> : configKeys.length === 0 ? (
              <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center' }}>No configuration keys set</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Key', 'Value', 'Actions'].map(h => (
                      <th key={h} style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {configKeys.map(({ key, value }) => (
                    <tr key={key} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.75rem', color: 'var(--cyan)', fontSize: '0.8125rem', fontFamily: 'monospace' }}>{key}</td>
                      <td style={{ padding: '0.75rem', color: 'var(--text)', fontSize: '0.8125rem', fontFamily: 'monospace', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value || '—'}</td>
                      <td style={{ padding: '0.75rem' }}>
                        <button onClick={() => { const v = prompt('New value:', value); if (v !== null) handleKeyEdit(key, v) }}
                          style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--sub)', cursor: 'pointer', fontSize: '0.75rem', padding: '0.25rem 0.625rem', borderRadius: 4 }}>
                          Edit
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Health Check ── */}
      {tab === 'health' && (
        healthLoading ? <p style={{ color: 'var(--sub)' }}>Loading...</p> : health ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
              <span style={{ fontSize: '2rem' }}>{health.status === 'healthy' ? '✅' : '⚠️'}</span>
              <div>
                <p style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 700, textTransform: 'capitalize' }}>{health.status}</p>
                <p style={{ color: 'var(--sub)', fontSize: '0.8125rem' }}>ETA v{health.version}</p>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
                <h4 style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem' }}>Database</h4>
                <p style={{ color: health.database.ok ? 'var(--green)' : 'var(--red)', fontSize: '0.875rem' }}>
                  {health.database.ok ? '✅ Connected' : '❌ Error: ' + health.database.message}
                </p>
              </div>
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
                <h4 style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem' }}>Uptime</h4>
                <p style={{ color: 'var(--cyan)', fontSize: '2rem', fontWeight: 700 }}>{health.uptime_hours}h</p>
                <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>Server has been running</p>
              </div>
              <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
                <h4 style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem' }}>Disk Usage</h4>
                {health.disk?.error ? <p style={{ color: 'var(--red)', fontSize: '0.875rem' }}>{health.disk.error}</p> : (
                  <>
                    <div style={{ background: 'var(--muted)', borderRadius: 4, height: 8, marginBottom: '0.5rem', overflow: 'hidden' }}>
                      <div style={{ width: health.disk.percent + '%', height: '100%', background: health.disk.percent > 85 ? 'var(--red)' : health.disk.percent > 70 ? 'var(--amber)' : 'var(--green)', borderRadius: 4 }} />
                    </div>
                    <p style={{ color: 'var(--text)', fontSize: '0.8125rem' }}>
                      {health.disk.used_gb} GB used / {health.disk.total_gb} GB total ({health.disk.percent}%)
                    </p>
                    <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{health.disk.free_gb} GB free</p>
                  </>
                )}
              </div>
            </div>
          </div>
        ) : <p style={{ color: 'var(--sub)' }}>Health check unavailable</p>
      )}
    </div>
  )
}