import { useState } from 'react'
import { Link } from 'react-router-dom'
import { checkAccountStatus } from '../services/api'

export default function CheckStatus() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')

  const checkStatus = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setStatus(null)

    try {
      const { data } = await api.post('/api/auth/check-status', { email })
      setStatus(data)
    } catch (err) {
      // Return different error for security (don't reveal if email exists)
      setStatus({
        exists: true,
        status: 'unknown',
        message: 'If an account exists with this email, the status will be shown above.'
      })
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved': return 'var(--green)'
      case 'pending': return 'var(--amber)'
      case 'disabled': return 'var(--red)'
      default: return 'var(--sub)'
    }
  }

  const getStatusLabel = (status) => {
    switch (status) {
      case 'approved': return 'Approved'
      case 'pending': return 'Pending Approval'
      case 'disabled': return 'Disabled'
      default: return 'Unknown'
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', padding: '1rem' }}>
      <div style={{ padding: '2rem', borderRadius: '12px', background: 'var(--card)', border: '1px solid var(--border)', width: '100%', maxWidth: '420px' }}>
        <h1 style={{ color: 'var(--text)', marginBottom: '0.5rem', textAlign: 'center', fontSize: '1.5rem', fontWeight: 'bold' }}>
          Check Account Status
        </h1>
        <p style={{ color: 'var(--sub)', marginBottom: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>
          Enter your email to check if your account has been approved
        </p>

        {error && (
          <div style={{ color: 'var(--red)', marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.3)', fontSize: '0.875rem' }}>
            {error}
          </div>
        )}

        {status && (
          <div style={{
            marginBottom: '1rem',
            padding: '1rem',
            background: 'var(--surface)',
            borderRadius: '8px',
            border: '1px solid var(--border)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem' }}>
              <span style={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: getStatusColor(status.status)
              }} />
              <span style={{ color: 'var(--text)', fontWeight: 600 }}>
                {getStatusLabel(status.status)}
              </span>
            </div>
            {status.message && (
              <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginTop: '0.75rem', textAlign: 'center' }}>
                {status.message}
              </p>
            )}
            {status.status === 'approved' && (
              <Link
                to="/login"
                style={{
                  display: 'block',
                  marginTop: '1rem',
                  padding: '0.75rem',
                  borderRadius: '8px',
                  background: 'var(--cyan)',
                  color: 'var(--text)',
                  textAlign: 'center',
                  textDecoration: 'none',
                  fontWeight: 600
                }}
              >
                Login Now
              </Link>
            )}
            {status.status === 'pending' && (
              <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginTop: '1rem', textAlign: 'center' }}>
                Please wait for an administrator to approve your account. You'll receive an email once approved.
              </p>
            )}
          </div>
        )}

        <form onSubmit={checkStatus} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', color: 'var(--sub)', fontSize: '0.75rem', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Email Address
            </label>
            <input
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="off"
              style={{ width: '100%', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem' }}
            />
          </div>

          <button type="submit" disabled={loading}
            style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--cyan)', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '1rem', fontWeight: 600, opacity: loading ? 0.5 : 1 }}>
            {loading ? 'Checking...' : 'Check Status'}
          </button>
        </form>

        <p style={{ color: 'var(--sub)', marginTop: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>
          <Link to="/login" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>Back to Login</Link>
        </p>
      </div>
    </div>
  )
}