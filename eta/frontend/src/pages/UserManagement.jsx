import { useState, useEffect } from 'react'
import api from '../services/api'
import { useToast } from '../hooks/useToast'

export default function UserManagement() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [showModal, setShowModal] = useState(false)
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'user' })
  const [creating, setCreating] = useState(false)
  const { success, error: showError } = useToast()

  useEffect(() => { loadUsers() }, [filter])

  const loadUsers = async () => {
    setLoading(true)
    try {
      const endpoint = filter === 'pending' ? '/api/users/pending' : '/api/users/'
      const { data } = await api.get(endpoint)
      setUsers(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      setUsers([])
    } finally {
      setLoading(false)
    }
  }

  const handleCreateUser = async (e) => {
    e.preventDefault()
    setCreating(true)
    try {
      await api.post('/api/auth/register', newUser)
      success('User created successfully')
      setShowModal(false)
      setNewUser({ username: '', email: '', password: '', role: 'user' })
      loadUsers()
    } catch (err) {
      showError(err.response?.data?.detail || 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  const handleApprove = async (id) => {
    try {
      await api.post(`/api/users/${id}/approve`)
      success('User approved successfully')
      loadUsers()
    } catch (err) { showError('Failed to approve user') }
  }

  const handleDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this user?')) return
    try {
      await api.delete(`/api/users/${id}`)
      success('User deleted')
      loadUsers()
    } catch (err) { showError('Failed to delete user') }
  }

  const handleRoleChange = async (userId, newRole) => {
    try {
      await api.patch(`/api/users/${userId}`, { role: newRole })
      success('Role updated successfully')
      loadUsers()
    } catch (err) { showError('Failed to update role') }
  }

  const filteredUsers = users.filter(u =>
    u.username?.toLowerCase().includes(search.toLowerCase()) ||
    u.email?.toLowerCase().includes(search.toLowerCase())
  )

  const getRoleColor = (role) => ({
    superadmin: { bg: '#EF4444', text: '#fff' },
    admin: { bg: '#F59E0B', text: '#fff' },
    soc_analyst: { bg: '#8B5CF6', text: '#fff' },
    user: { bg: '#06B6D4', text: '#fff' },
  }[role] || { bg: '#64748B', text: '#fff' })

  return (
    <div style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>User Management</h1>
          <p style={{ color: '#64748B', fontSize: '0.9375rem' }}>Manage users and their roles</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={() => setShowModal(true)}
            style={{
              padding: '0.625rem 1rem',
              borderRadius: 8,
              border: 'none',
              background: '#06B6D4',
              color: '#fff',
              fontSize: '0.875rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            + Add User
          </button>
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              padding: '0.625rem 1rem',
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--card)',
              color: 'var(--text)',
              fontSize: '0.875rem',
              cursor: 'pointer'
            }}
          >
            <option value="all">All Users</option>
            <option value="pending">Pending Approval</option>
          </select>
        </div>
      </div>

      {/* Add User Modal */}
      {showModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000
        }} onClick={() => setShowModal(false)}>
          <div style={{
            background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)',
            padding: '2rem', width: '100%', maxWidth: '420px'
          }} onClick={e => e.stopPropagation()}>
            <h2 style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1.5rem' }}>Add New User</h2>
            <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Username</label>
                <input
                  type="text" placeholder="username" value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} required
                  style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Email</label>
                <input
                  type="email" placeholder="user@example.com" value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} required
                  style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Password</label>
                <input
                  type="password" placeholder="Min 8 characters" value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} required minLength={8}
                  style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>Role</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  style={{ width: '100%', padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }}
                >
                  <option value="user">User</option>
                  <option value="soc_analyst">SOC Analyst</option>
                  <option value="admin">Admin</option>
                  <option value="superadmin">Superadmin</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  style={{ flex: 1, padding: '0.75rem', borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text)', cursor: 'pointer', fontSize: '1rem', fontWeight: 600 }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  style={{ flex: 1, padding: '0.75rem', borderRadius: 8, border: 'none', background: '#06B6D4', color: '#fff', cursor: 'pointer', fontSize: '1rem', fontWeight: 600, opacity: creating ? 0.5 : 1 }}
                >
                  {creating ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Search */}
      <div style={{ marginBottom: '1.5rem' }}>
        <input
          type="text"
          placeholder="Search users..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            width: '100%',
            maxWidth: 400,
            padding: '0.75rem 1rem',
            borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--card)',
            color: 'var(--text)',
            fontSize: '0.9375rem'
          }}
        />
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem', color: '#64748B' }}>Loading users...</div>
      ) : filteredUsers.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)' }}>
          <p style={{ color: '#64748B', fontSize: '1rem' }}>No users found</p>
        </div>
      ) : (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden', marginBottom: '1.5rem' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg)', borderBottom: '2px solid var(--border)' }}>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>User</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>Role</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>Status</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>Created</th>
                <th style={{ padding: '0.875rem', textAlign: 'right', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((u, idx) => {
                const roleStyle = getRoleColor(u.role)
                return (
                  <tr key={u.id || idx} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.875rem' }}>
                      <p style={{ color: 'var(--text)', fontWeight: 500, marginBottom: '0.25rem' }}>{u.username}</p>
                      <p style={{ color: '#64748B', fontSize: '0.8125rem' }}>{u.email}</p>
                    </td>
                    <td style={{ padding: '0.875rem' }}>
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        style={{
                          padding: '0.375rem 0.625rem',
                          borderRadius: 6,
                          border: `1px solid ${roleStyle.bg}`,
                          background: roleStyle.bg + '20',
                          color: 'var(--text)',
                          fontSize: '0.75rem',
                          textTransform: 'uppercase',
                          fontWeight: 600,
                          cursor: 'pointer'
                        }}
                      >
                        <option value="user">User</option>
                        <option value="soc_analyst">SOC Analyst</option>
                        <option value="admin">Admin</option>
                        <option value="superadmin">Superadmin</option>
                      </select>
                    </td>
                    <td style={{ padding: '0.875rem' }}>
                      <span style={{
                        padding: '0.25rem 0.625rem',
                        borderRadius: 6,
                        fontSize: '0.75rem',
                        fontWeight: 500,
                        background: u.is_approved ? '#10B98120' : '#F59E0B20',
                        color: u.is_approved ? '#10B981' : '#F59E0B',
                      }}>
                        {u.is_approved ? 'Approved' : 'Pending'}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem', color: '#64748B', fontSize: '0.875rem' }}>
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td style={{ padding: '0.875rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                        {!u.is_approved && (
                          <button
                            onClick={() => handleApprove(u.id)}
                            style={{
                              padding: '0.375rem 0.75rem',
                              borderRadius: 6,
                              border: '1px solid #10B981',
                              background: 'transparent',
                              color: '#10B981',
                              cursor: 'pointer',
                              fontSize: '0.75rem',
                              fontWeight: 500,
                              transition: 'all 0.15s ease'
                            }}
                          >
                            Approve
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(u.id)}
                          style={{
                            padding: '0.375rem 0.75rem',
                            borderRadius: 6,
                            border: '1px solid #EF4444',
                            background: 'transparent',
                            color: '#EF4444',
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                            fontWeight: 500,
                            transition: 'all 0.15s ease'
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Total</p>
          <p style={{ color: '#06B6D4', fontSize: '1.5rem', fontWeight: 'bold' }}>{users.length}</p>
        </div>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Admins</p>
          <p style={{ color: '#F59E0B', fontSize: '1.5rem', fontWeight: 'bold' }}>{users.filter(u => u.role === 'admin' || u.role === 'superadmin').length}</p>
        </div>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Pending</p>
          <p style={{ color: '#F59E0B', fontSize: '1.5rem', fontWeight: 'bold' }}>{users.filter(u => !u.is_approved).length}</p>
        </div>
      </div>
    </div>
  )
}