import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../hooks/useAuth'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showTotp, setShowTotp] = useState(false)
  const [pendingToken, setPendingToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { syncUser } = useAuth()

  // Check for redirect after login from extension
  useEffect(() => {
    const redirectScan = localStorage.getItem('redirect_after_login')
    if (redirectScan) {
      localStorage.removeItem('redirect_after_login')
    }
  }, [])

  const handleLoginSuccess = (user) => {
    // Check if we need to redirect to a report
    const redirectScan = localStorage.getItem('redirect_after_login')
    if (redirectScan) {
      localStorage.removeItem('redirect_after_login')
      navigate(`/report/${redirectScan}`)
    } else if (user?.role === 'admin' || user?.role === 'superadmin' || user?.role === 'soc_analyst') {
      navigate('/admin')
    } else {
      navigate('/dashboard')
    }
  }

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
        syncUser(data.user)
        handleLoginSuccess(data.user)
      } catch (err) {
        setError(err.response?.data?.detail || 'Invalid 2FA code')
      } finally {
        setLoading(false)
      }
      return
    }

    try {
      console.log('Login attempt with:', email)
      const params = new URLSearchParams()
      params.append('username', email)
      params.append('password', password)
      console.log('Sending params:', params.toString())

      let response
      try {
        response = await api.post('/api/auth/login', params.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        })
      } catch (axiosErr) {
        // Handle different error types
        console.log('Axios error:', axiosErr)
        const errResponse = axiosErr.response

        if (!errResponse) {
          setError('Network error. Server may be offline.')
        } else if (errResponse.status === 401) {
          setError('Invalid email or password.')
        } else if (errResponse.status === 403) {
          const detail = errResponse.data?.detail
          if (detail?.includes('pending')) {
            setError('Account pending approval. Please wait for admin to approve.')
          } else if (detail?.includes('disabled')) {
            setError('Account is disabled. Contact admin.')
          } else {
            setError(detail || 'Access denied.')
          }
        } else if (errResponse.status === 429) {
          setError('Too many attempts. Please wait 15 minutes.')
        } else if (errResponse.status >= 500) {
          setError('Server error. Please try again later.')
        } else {
          setError(errResponse.data?.detail || errResponse.data?.message || `Error: ${errResponse.status}`)
        }
        setLoading(false)
        return
      }

      const data = response?.data
      console.log('Login response:', data)

      // Check for empty response
      if (!data || Object.keys(data).length === 0) {
        setError('Login failed. Server returned empty response.')
        setLoading(false)
        return
      }

      // Check for token
      if (!data.access_token) {
        setError('Login failed. No access token received.')
        setLoading(false)
        return
      }

      if (data.user?._2fa_required) {
        setPendingToken(data.access_token)
        setShowTotp(true)
        setLoading(false)
        return
      }

      localStorage.setItem('eta_token', data.access_token)
      localStorage.setItem('eta_user', JSON.stringify(data.user))
      api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
      syncUser(data.user)
      handleLoginSuccess(data.user)
    } catch (err) {
      console.log('Login error:', err)
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
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg)',
      padding: '1.5rem',
    }}>
      <div style={{
        padding: '2rem',
        borderRadius: '16px',
        background: 'var(--card)',
        border: '1px solid var(--border)',
        width: '100%',
        maxWidth: '400px',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
          <div style={{
            width: 64, height: 64, margin: '0 auto 1rem',
            borderRadius: 16, background: 'rgba(6,182,212,0.15)',
            border: '1px solid rgba(6,182,212,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <span style={{ color: 'var(--cyan)', fontSize: 28, fontWeight: 'bold' }}>E</span>
          </div>
          <h1 style={{ color: 'var(--text)', fontSize: '1.5rem', fontWeight: 'bold' }}>
            {showTotp ? 'Two-Factor' : 'ETA Login'}
          </h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            {showTotp ? 'Enter your authentication code' : 'Sign in to your account'}
          </p>
        </div>

        {error && (
          <div style={{
            color: 'var(--red)', marginBottom: '1rem', padding: '0.875rem',
            background: 'rgba(239,68,68,0.1)', borderRadius: '8px',
            border: '1px solid rgba(239,68,68,0.3)', fontSize: '0.875rem',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label htmlFor="login-email" style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Email or Username
            </label>
            <input
              id="login-email"
              name="email"
              type="text" placeholder="email@example.com" value={email}
              onChange={(e) => setEmail(e.target.value)} required disabled={showTotp}
              autoComplete="username"
              style={{
                width: '100%', padding: '0.875rem', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface)',
                color: 'var(--text)', fontSize: '1rem', opacity: showTotp ? 0.5 : 1,
              }}
            />
          </div>

          <div>
            <label htmlFor="login-password" style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Password
            </label>
            <input
              id="login-password"
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
                padding: '0.875rem',
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

          {showTotp && (
            <div>
              <label htmlFor="login-totp" style={{
                display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
                marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
              }}>
                Authentication Code
              </label>
              <input
                id="login-totp"
                name="totp-code"
                type="text" placeholder="000000" value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                required autoFocus maxLength={6}
                autoComplete="one-time-code"
                style={{
                  width: '100%', padding: '0.875rem', borderRadius: '8px',
                  border: '1px solid var(--border)', background: 'var(--surface)',
                  color: 'var(--text)', fontSize: '1.25rem', textAlign: 'center', letterSpacing: '0.25em',
                }}
              />
              <p style={{ color: 'var(--sub)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
                Enter the 6-digit code from your authenticator app
              </p>
            </div>
          )}

          <button type="submit" disabled={loading}
            style={{
              padding: '0.875rem', borderRadius: '8px', background: 'var(--cyan)',
              color: '#fff', border: 'none', cursor: 'pointer',
              fontSize: '1rem', fontWeight: 600, opacity: loading ? 0.5 : 1,
            }}>
            {loading ? 'Please wait...' : showTotp ? 'Verify Code' : 'Login'}
          </button>
        </form>

        {showTotp && (
          <button onClick={() => { setShowTotp(false); setTotpCode(''); setPendingToken('') }}
            style={{
              width: '100%', marginTop: '0.75rem', padding: '0.75rem',
              background: 'transparent', color: 'var(--cyan)', border: 'none',
              borderRadius: '8px', cursor: 'pointer', fontSize: '0.875rem',
            }}>
            ← Back to login
          </button>
        )}

        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginTop: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/register" style={{ color: 'var(--cyan)', textDecoration: 'none', fontSize: '0.875rem' }}>
            Register
          </Link>
          <Link to="/check-status" style={{ color: 'var(--cyan)', textDecoration: 'none', fontSize: '0.875rem' }}>
            Check Status
          </Link>
        </div>
      </div>
    </div>
  )
}