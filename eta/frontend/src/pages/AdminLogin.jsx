import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../services/api'

export default function AdminLogin() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showTotp, setShowTotp] = useState(false)
  const [pendingToken, setPendingToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    if (showTotp) {
      try {
        const { data } = await api.post('/api/auth/login/verify-2fa', { code: totpCode }, {
          headers: { 'Authorization': `Bearer ${pendingToken}`, 'Content-Type': 'application/json' }
        })
        localStorage.setItem('eta_token', data.access_token)
        localStorage.setItem('eta_user', JSON.stringify(data.user))
        api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
        navigate('/admin')
      } catch (err) {
        setError(err.response?.data?.detail || 'Invalid 2FA code')
      } finally {
        setLoading(false)
      }
      return
    }

    try {
      const formData = new URLSearchParams()
      formData.append('username', email)
      formData.append('password', password)
      const { data } = await api.post('/api/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      })

      if (data.user?._2fa_required) {
        setPendingToken(data.access_token)
        setShowTotp(true)
        setLoading(false)
        return
      }

      localStorage.setItem('eta_token', data.access_token)
      localStorage.setItem('eta_user', JSON.stringify(data.user))
      api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
      navigate('/admin')
    } catch (err) {
      if (err.response?.status === 429) {
        setError('Too many attempts. Please wait 15 minutes.')
      } else {
        setError(err.response?.data?.detail || 'Login failed. Check credentials.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', padding: '1rem' }}>
      <div style={{ padding: '2rem', borderRadius: '12px', background: 'var(--card)', border: '1px solid var(--border)', width: '100%', maxWidth: '400px' }}>
        <h1 style={{ color: 'var(--text)', marginBottom: '1.5rem', textAlign: 'center', fontSize: '1.5rem', fontWeight: 'bold' }}>
          {showTotp ? 'Two-Factor Authentication' : 'ETA Admin Login'}
        </h1>

        {error && (
          <div style={{ color: 'var(--red)', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.3)', fontSize: '0.875rem' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} autoComplete="on" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label htmlFor="admin-email" style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Email or Username</label>
            <input
              id="admin-email"
              name="email"
              type="text" placeholder="email@example.com or username" value={email} onChange={(e) => setEmail(e.target.value)} required disabled={showTotp}
              autoComplete="username"
              style={{ width: '100%', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem', opacity: showTotp ? 0.5 : 1 }} />
          </div>

          <div>
            <label htmlFor="admin-password" style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Password</label>
            <div style={{ position: 'relative' }}>
              <input
                id="admin-password"
                name="password"
                type="password"
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={showTotp}
                autoComplete="current-password"
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  background: 'var(--surface)',
                  color: 'var(--text)',
                  fontSize: '1rem',
                  opacity: showTotp ? 0.5 : 1,
                  WebkitTextSecurity: 'disc',
                  textSecurity: 'disc',
                }}
              />
            </div>
          </div>

          {showTotp && (
            <div>
              <label htmlFor="admin-totp" style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Authentication Code
              </label>
              <input
                id="admin-totp"
                name="totp-code"
                type="text" placeholder="000000" value={totpCode} onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))} required autoFocus maxLength={6}
                autoComplete="one-time-code"
                style={{ width: '100%', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }} />
              <p style={{ color: 'var(--sub)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
                Open your authenticator app and enter the 6-digit code. You can also use a backup code.
              </p>
            </div>
          )}

          <button type="submit" disabled={loading}
            style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '1rem', fontWeight: 600, opacity: loading ? 0.5 : 1 }}>
            {loading ? 'Please wait...' : showTotp ? 'Verify Code' : 'Admin Login'}
          </button>
        </form>

        {showTotp && (
          <button onClick={() => { setShowTotp(false); setTotpCode(''); setPendingToken('') }}
            style={{ width: '100%', marginTop: '0.75rem', padding: '0.5rem', background: 'transparent', color: 'var(--sub)', border: '1px solid var(--border)', borderRadius: '8px', cursor: 'pointer', fontSize: '0.875rem' }}>
            ← Back to login
          </button>
        )}

        <p style={{ color: 'var(--sub)', marginTop: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>
          <Link to="/login" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>User Login</Link>
        </p>
      </div>
    </div>
  )
}