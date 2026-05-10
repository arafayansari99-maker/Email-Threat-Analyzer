import { useState, useEffect } from 'react'
import api from '../services/api'
import { useAuth } from '../hooks/useAuth'
import { useIsMobile } from '../hooks/useIsMobile'

const ACTION_LABELS = {
  workspace_created: { text: 'created workspace', color: '#06B6D4' },
  member_added: { text: 'added a member', color: '#8B5CF6' },
  comment_added: { text: 'added a comment', color: '#10B981' },
  scan_created: { text: 'ran a scan', color: '#F59E0B' },
  user_approved: { text: 'approved user', color: '#06B6D4' },
  user_deleted: { text: 'removed user', color: '#EF4444' },
  role_changed: { text: 'changed user role', color: '#6366F1' },
}

const timeAgo = (date) => {
  const now = new Date()
  const d = new Date(date)
  const diff = Math.floor((now - d) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function ActivityFeedItem({ log }) {
  const info = ACTION_LABELS[log.action] || { text: log.action, color: '#64748B' }
  return (
    <div style={{ display: 'flex', gap: '0.75rem', padding: '0.875rem', borderBottom: '1px solid var(--border)', alignItems: 'flex-start' }}>
      <div style={{
        width: 8, height: 8, borderRadius: '50%', background: info.color,
        flexShrink: 0, marginTop: 6,
      }} />
      <div style={{ flex: 1 }}>
        <p style={{ color: 'var(--text)', fontSize: '0.8125rem', marginBottom: '0.125rem' }}>
          <strong style={{ color: '#06B6D4' }}>{log.username}</strong>{' '}
          <span style={{ color: '#9CA3AF' }}>{info.text}</span>
          {log.details?.name && <span style={{ color: '#64748B' }}> — {log.details.name}</span>}
          {log.details?.added_username && <span style={{ color: '#8B5CF6' }}> {log.details.added_username}</span>}
          {log.details?.scan_id && <span style={{ color: '#64748B' }}> — {log.details.scan_id.slice(0, 12)}...</span>}
        </p>
        <p style={{ color: '#4B5563', fontSize: '0.6875rem' }}>{timeAgo(log.created_at)}</p>
      </div>
    </div>
  )
}

export default function Collaborate() {
  const { user } = useAuth()
  const isMobile = useIsMobile()
  const [tab, setTab] = useState('workspaces')
  const [workspaces, setWorkspaces] = useState([])
  const [activity, setActivity] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newWs, setNewWs] = useState({ name: '', description: '' })
  const [allUsers, setAllUsers] = useState([])
  const [selectedWs, setSelectedWs] = useState(null)
  const [members, setMembers] = useState([])
  const [membersLoading, setMembersLoading] = useState(false)
  const [showAddMember, setShowAddMember] = useState(false)
  const [addRole, setAddRole] = useState('analyst')
  const [creating, setCreating] = useState(false)
  const [adding, setAdding] = useState(false)
  const [message, setMessage] = useState(null) // { type: 'success'|'error', text: string }

  const showMsg = (type, text) => {
    setMessage({ type, text })
    setTimeout(() => setMessage(null), 3500)
  }

  const isManager = user?.role === 'admin' || user?.role === 'superadmin'
  const isAnalyst = user?.role === 'analyst'

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [wsRes, actRes, usersRes] = await Promise.all([
        api.get('/api/collaboration/workspaces'),
        api.get('/api/collaboration/activity?limit=30'),
        api.get('/api/users/'),
      ])
      setWorkspaces(Array.isArray(wsRes.data) ? wsRes.data : [])
      setActivity(Array.isArray(actRes.data) ? actRes.data : [])
      setAllUsers(Array.isArray(usersRes.data) ? usersRes.data : [])
    } catch (err) {
      console.error('Failed to load collaboration data:', err)
      // Fallback demo data
      setActivity([])
    } finally {
      setLoading(false)
    }
  }

  const loadWorkspaceMembers = async (wsId) => {
    setMembersLoading(true)
    setMembers([])
    try {
      const { data } = await api.get(`/api/collaboration/workspaces/${wsId}/members`)
      setMembers(data || [])
    } catch (err) {
      console.error(err)
      setMembers([])
    } finally {
      setMembersLoading(false)
    }
  }

  const handleCreateWorkspace = async () => {
    if (!newWs.name.trim()) return
    setCreating(true)
    try {
      const { data } = await api.post('/api/collaboration/workspaces', newWs)
      setWorkspaces(prev => [data, ...prev])
      setShowCreate(false)
      setNewWs({ name: '', description: '' })
      showMsg('success', 'Workspace created successfully.')
    } catch (err) {
      console.error('Create workspace error:', err)
      showMsg('error', 'Failed to create workspace. Please try again.')
    } finally {
      setCreating(false)
    }
  }

  const handleAddMember = async (userId) => {
    if (!selectedWs || !userId) return
    setAdding(true)
    try {
      await api.post(`/api/collaboration/workspaces/${selectedWs.id}/members`, { user_id: userId, role: addRole })
      await loadWorkspaceMembers(selectedWs.id)
      setShowAddMember(false)
      showMsg('success', 'Member added successfully.')
    } catch (err) {
      console.error('Add member error:', err)
      showMsg('error', 'Failed to add member. Please try again.')
    } finally {
      setAdding(false)
    }
  }

  const getRoleBadge = (role) => {
    const colors = { owner: '#06B6D4', admin: '#8B5CF6', analyst: '#F59E0B', viewer: '#64748B', member: '#64748B' }
    const r = (role || 'member').toLowerCase()
    return { bg: colors[r] || '#64748B', text: r.toUpperCase() }
  }

  return (
    <div style={{ padding: isMobile ? '1rem' : '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Collaborate</h1>
          <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Workspaces, comments & team activity</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={() => setShowCreate(true)} style={{
            padding: '0.625rem 1rem', borderRadius: 8, background: '#06B6D4', color: 'var(--text)',
            border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
          }}>+ New Workspace</button>
        </div>
      </div>

      {message && (
        <div style={{
          marginBottom: '1rem', padding: '0.75rem 1rem', borderRadius: 8,
          background: message.type === 'success' ? '#10B98118' : '#EF444418',
          border: `1px solid ${message.type === 'success' ? '#10B981' : '#EF4444'}`,
          color: message.type === 'success' ? '#10B981' : '#EF4444',
          fontSize: '0.875rem', fontWeight: 500,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>{message.text}</span>
          <button onClick={() => setMessage(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontSize: '0.875rem', padding: '0 0.25rem' }}>✕</button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
        {['workspaces', 'activity'].map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: '0.5rem 1rem', borderRadius: 6, border: 'none', cursor: 'pointer',
            fontSize: '0.875rem', fontWeight: 600,
            background: tab === t ? '#06B6D4' : 'transparent',
            color: tab === t ? '#fff' : '#64748B',
            textTransform: 'capitalize',
          }}>{t}</button>
        ))}
      </div>

      {/* ── Workspaces Tab ── */}
      {tab === 'workspaces' && (
        <div>
          {loading ? (
            <div style={{ color: '#64748B', textAlign: 'center', padding: '3rem' }}>Loading...</div>
          ) : workspaces.length === 0 ? (
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '3rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', marginBottom: '1rem' }}>No workspaces yet. Create one to start collaborating.</p>
              <button onClick={() => setShowCreate(true)} style={{
                padding: '0.625rem 1.5rem', borderRadius: 8, background: '#06B6D4', color: 'var(--text)',
                border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
              }}>Create Workspace</button>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fill, minmax(${isMobile ? '260px' : '300px'}, 1fr))`, gap: '1rem' }}>
              {workspaces.map(ws => (
                <div key={ws.id} style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <div style={{ flex: 1 }}>
                      <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>{ws.name}</h3>
                      {ws.description && <p style={{ color: '#64748B', fontSize: '0.8125rem' }}>{ws.description}</p>}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', alignItems: 'flex-end' }}>
                      <button
                        onClick={() => { setSelectedWs(ws); loadWorkspaceMembers(ws.id) }}
                        style={{ background: '#06B6D420', color: '#06B6D4', border: '1px solid #06B6D440', borderRadius: 6, padding: '0.25rem 0.5rem', fontSize: '0.6875rem', cursor: 'pointer', fontWeight: 600 }}
                      >Members</button>
                    </div>
                  </div>
                  <p style={{ color: '#4B5563', fontSize: '0.6875rem' }}>Created {new Date(ws.created_at).toLocaleDateString()}</p>
                </div>
              ))}
            </div>
          )}

          {/* Members Panel */}
          {selectedWs && (
            <div style={{ marginTop: '1.5rem', background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>{selectedWs.name} — Members</h3>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <select
                    value={addRole}
                    onChange={(e) => setAddRole(e.target.value)}
                    style={{ padding: '0.375rem 0.5rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.75rem' }}
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  {showAddMember ? (
                    <div style={{ display: 'flex', gap: '0.25rem' }}>
                      <select
                        onChange={(e) => { if (e.target.value) handleAddMember(parseInt(e.target.value)); setShowAddMember(false) }}
                        style={{ padding: '0.375rem 0.5rem', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.75rem', minWidth: 150 }}
                      >
                        <option value="">Select user...</option>
                        {allUsers.filter(u => !members.find(m => m.user_id === u.id)).map(u => (
                          <option key={u.id} value={u.id}>{u.username} ({u.role})</option>
                        ))}
                      </select>
                      <button onClick={() => setShowAddMember(false)} style={{ background: 'var(--border)', border: 'none', borderRadius: 6, color: '#64748B', cursor: 'pointer', padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>✕</button>
                    </div>
                  ) : (
                    <button onClick={() => setShowAddMember(true)} style={{ background: '#06B6D420', border: '1px solid #06B6D440', borderRadius: 6, color: '#06B6D4', cursor: 'pointer', padding: '0.375rem 0.75rem', fontSize: '0.75rem', fontWeight: 600 }}>+ Add Member</button>
                  )}
                  <button onClick={() => setSelectedWs(null)} style={{ background: 'var(--border)', border: 'none', borderRadius: 6, color: '#64748B', cursor: 'pointer', padding: '0.375rem 0.5rem', fontSize: '0.75rem' }}>✕</button>
                </div>
              </div>
              {membersLoading ? (
                <p style={{ color: '#64748B', fontSize: '0.875rem' }}>Loading members...</p>
              ) : members.length === 0 ? (
                <p style={{ color: '#64748B', fontSize: '0.875rem' }}>No members found.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {members.map(m => {
                    const badge = getRoleBadge(m.role)
                    return (
                      <div key={m.user_id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem', background: 'var(--surface)', borderRadius: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <div style={{ width: 32, height: 32, borderRadius: '50%', background: '#1F2937', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text)', fontSize: '0.875rem', fontWeight: 600 }}>
                            {m.username?.[0]?.toUpperCase()}
                          </div>
                          <div>
                            <p style={{ color: 'var(--text)', fontSize: '0.875rem', fontWeight: 500 }}>{m.username}</p>
                            <p style={{ color: '#4B5563', fontSize: '0.6875rem' }}>{m.email}</p>
                          </div>
                        </div>
                        <span style={{
                          padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.625rem', fontWeight: 700, textTransform: 'uppercase',
                          background: badge.bg + '22', color: badge.bg,
                        }}>{badge.text}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Activity Feed Tab ── */}
      {tab === 'activity' && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
          <div style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, margin: 0 }}>Activity Feed</h2>
          </div>
          {loading ? (
            <div style={{ color: '#64748B', textAlign: 'center', padding: '3rem' }}>Loading...</div>
          ) : activity.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center' }}>
              <p style={{ color: '#64748B', fontSize: '0.875rem' }}>No activity yet. Create a workspace to start tracking.</p>
            </div>
          ) : (
            <div style={{ maxHeight: isMobile ? 300 : 500, overflowY: 'auto' }}>
              {activity.map(log => (
                <ActivityFeedItem key={log.id} log={log} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Create Workspace Modal ── */}
      {showCreate && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem',
        }} onClick={() => setShowCreate(false)}>
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: isMobile ? '1rem' : '1.5rem', width: '95vw', maxWidth: 440 }} onClick={e => e.stopPropagation()}>
            <h2 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600, marginBottom: '1.25rem' }}>Create Workspace</h2>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Workspace Name *</label>
              <input
                type="text"
                placeholder="e.g. SOC Team Alpha"
                value={newWs.name}
                onChange={e => setNewWs(prev => ({ ...prev, name: e.target.value }))}
                style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.9375rem' }}
              />
            </div>
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Description</label>
              <textarea
                placeholder="Describe the purpose of this workspace..."
                value={newWs.description}
                onChange={e => setNewWs(prev => ({ ...prev, description: e.target.value }))}
                rows={3}
                style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '0.9375rem', fontFamily: 'inherit', resize: 'vertical' }}
              />
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button onClick={() => setShowCreate(false)} style={{ padding: '0.625rem 1rem', borderRadius: 8, background: '#fff', color: '#000', border: '1px solid var(--border)', cursor: 'pointer', fontSize: '0.875rem' }}>Cancel</button>
              <button onClick={handleCreateWorkspace} disabled={creating || !newWs.name.trim()} style={{ padding: '0.625rem 1.5rem', borderRadius: 8, background: creating || !newWs.name.trim() ? '#06B6D440' : '#06B6D4', color: 'var(--text)', border: 'none', cursor: creating || !newWs.name.trim() ? 'not-allowed' : 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>{creating ? 'Creating...' : 'Create'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}