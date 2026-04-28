import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

function getPasswordStrength(password) {
  if (!password) return { score: 0, label: '', color: '' }
  let score = 0
  if (password.length >= 8)  score++
  if (password.length >= 12) score++
  if (/[A-Z]/.test(password)) score++
  if (/[a-z]/.test(password)) score++
  if (/[0-9]/.test(password)) score++
  if (/[^A-Za-z0-9]/.test(password)) score++
  if (score <= 1) return { score, label: 'Very Weak',  color: '#EF4444' }
  if (score <= 2) return { score, label: 'Weak',       color: '#F97316' }
  if (score <= 3) return { score, label: 'Fair',       color: '#EAB308' }
  if (score <= 4) return { score, label: 'Strong',     color: '#22C55E' }
  return               { score, label: 'Very Strong', color: '#06B6D4' }
}

export default function Register() {
  const [form, setForm]     = useState({ username: '', email: '', password: '', confirm: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')
  const [success, setSuccess] = useState('')
  const { register } = useAuth()
  const navigate = useNavigate()

  const strength = getPasswordStrength(form.password)

  const handleChange = (field) => (e) => {
    setForm({ ...form, [field]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (form.password !== form.confirm) {
      setError('Passwords do not match')
      return
    }
    if (strength.score < 2) {
      setError('Password is too weak — please use a stronger password')
      return
    }
    setLoading(true)
    setError('')
    setSuccess('')
    try {
      await register(form.username.trim(), form.email.trim(), form.password)
      setSuccess('Registration successful! Your account is pending admin approval. You will be notified once approved.')
      setForm({ username: '', email: '', password: '', confirm: '' })
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed. Please try again.')
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
        maxWidth: '420px',
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
            Create Account
          </h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Join the security platform
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

        {success && (
          <div style={{
            color: 'var(--green)', marginBottom: '1rem', padding: '0.875rem',
            background: 'rgba(16,185,129,0.1)', borderRadius: '8px',
            border: '1px solid rgba(16,185,129,0.3)', fontSize: '0.875rem',
          }}>
            {success}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Username
            </label>
            <input type="text" placeholder="analyst_01" value={form.username}
              onChange={handleChange('username')} required autoComplete="off"
              style={{
                width: '100%', padding: '0.875rem', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface)',
                color: 'var(--text)', fontSize: '1rem',
              }}
            />
          </div>

          <div>
            <label style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Email
            </label>
            <input type="email" placeholder="you@company.com" value={form.email}
              onChange={handleChange('email')} required autoComplete="off"
              style={{
                width: '100%', padding: '0.875rem', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface)',
                color: 'var(--text)', fontSize: '1rem',
              }}
            />
          </div>

          <div>
            <label style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Password
            </label>
            <input type="password" placeholder="Min 8 characters" value={form.password}
              onChange={handleChange('password')} required autoComplete="off"
              style={{
                width: '100%', padding: '0.875rem', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface)',
                color: 'var(--text)', fontSize: '1rem',
              }}
            />
            {form.password && (
              <div style={{ marginTop: '0.5rem' }}>
                <div style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
                  {[1, 2, 3, 4, 5].map(i => (
                    <div key={i} style={{
                      flex: 1, height: '4px', borderRadius: '2px',
                      background: i <= strength.score ? strength.color : 'var(--border)',
                      transition: 'background 0.3s'
                    }} />
                  ))}
                </div>
                <span style={{ fontSize: '0.75rem', color: strength.color, fontWeight: 600 }}>
                  {strength.label}
                </span>
              </div>
            )}
          </div>

          <div>
            <label style={{
              display: 'block', color: 'var(--sub)', fontSize: '0.75rem',
              marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em'
            }}>
              Confirm Password
            </label>
            <input type="password" placeholder="Repeat password" value={form.confirm}
              onChange={handleChange('confirm')} required autoComplete="off"
              style={{
                width: '100%', padding: '0.875rem', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface)',
                color: 'var(--text)', fontSize: '1rem',
              }}
            />
          </div>

          <button type="submit" disabled={loading}
            style={{
              padding: '0.875rem', borderRadius: '8px', background: 'var(--cyan)',
              color: '#fff', border: 'none', cursor: 'pointer',
              fontSize: '1rem', fontWeight: 600, opacity: loading ? 0.5 : 1,
            }}>
            {loading ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <p style={{ color: 'var(--sub)', marginTop: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>Sign in</Link>
        </p>
      </div>
    </div>
  )
}