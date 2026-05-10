import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useIsMobile } from '../hooks/useIsMobile'
import { getSessions, revokeSession, revokeAllSessions, get2FAStatus, setup2FA, enable2FA, disable2FA } from '../services/api'

function formatDate(d) {
  if (!d) return 'Never'
  return new Date(d).toLocaleString()
}

function SessionRow({ session, onRevoke }) {
  const isMobile = useIsMobile()
  const [revoking, setRevoking] = useState(false)
  const handleRevoke = async () => {
    setRevoking(true)
    await onRevoke(session.id)
    setRevoking(false)
  }
  return (
    <tr style={{ borderBottom: '1px solid #1E2D40' }}>
      <td style={{ padding: '0.75rem 1rem', color: '#94A3B8', fontSize: '0.875rem' }}>{session.ip_address || '—'}</td>
      <td style={{ padding: '0.75rem 1rem', color: '#94A3B8', fontSize: '0.875rem', maxWidth: isMobile ? '120px' : '60px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {session.device_info ? session.device_info.slice(0, 60) + (session.device_info.length > 60 ? '…' : '') : '—'}
      </td>
      <td style={{ padding: '0.75rem 1rem', color: '#94A3B8', fontSize: '0.875rem' }}>{formatDate(session.created_at)}</td>
      <td style={{ padding: '0.75rem 1rem', color: '#94A3B8', fontSize: '0.875rem' }}>{formatDate(session.last_used_at)}</td>
      <td style={{ padding: '0.75rem 1rem' }}>
        <button onClick={handleRevoke} disabled={revoking}
          style={{ padding: '0.35rem 0.75rem', borderRadius: '6px', background: 'rgba(239,68,68,0.1)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: '0.8rem', opacity: revoking ? 0.5 : 1 }}>
          Revoke
        </button>
      </td>
    </tr>
  )
}

export default function Sessions() {
  const isMobile = useIsMobile()
  const { user } = useAuth()
  const navigate = useNavigate()
  const isAdmin = user?.role === 'admin' || user?.role === 'superadmin'

  const [sessions, setSessions]       = useState([])
  const [twoFA, setTwoFA]             = useState({ enabled: false, loading: false, step: 'idle', secret: '', otpauth: '', backupCodes: [], verifyCode: '' })
  const [alert, setAlert]             = useState(null)
  const [loading, setLoading]         = useState(true)

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [sessRes, twoFARes] = await Promise.all([getSessions(), isAdmin ? get2FAStatus() : Promise.resolve({ data: { enabled: false } })])
      setSessions(Array.isArray(sessRes.data) ? sessRes.data : [])
      setTwoFA(prev => ({ ...prev, enabled: twoFARes.data.enabled }))
    } catch { /* ignore */ }
    setLoading(false)
  }

  const showAlert = (msg, type = 'info') => {
    setAlert({ msg, type })
    setTimeout(() => setAlert(null), 4000)
  }

  const handleRevoke = async (id) => {
    try { await revokeSession(id); setSessions(s => s.filter(x => x.id !== id)); showAlert('Session revoked', 'success') }
    catch { showAlert('Failed to revoke session', 'error') }
  }

  const handleRevokeAll = async () => {
    if (!confirm('Revoke all sessions? You will be logged out of all devices.')) return
    try { await revokeAllSessions(); setSessions([]); showAlert('All sessions revoked', 'success') }
    catch { showAlert('Failed to revoke sessions', 'error') }
  }

  const handleSetup2FA = async () => {
    setTwoFA(prev => ({ ...prev, loading: true }))
    try {
      const { data } = await setup2FA()
      setTwoFA(prev => ({ ...prev, loading: false, step: 'confirm', secret: data.secret, otpauth: data.otpauth_url, backupCodes: data.backup_codes, verifyCode: '' }))
    } catch { showAlert('Failed to setup 2FA', 'error'); setTwoFA(prev => ({ ...prev, loading: false })) }
  }

  const handleEnable2FA = async () => {
    if (!twoFA.verifyCode || twoFA.verifyCode.length < 6) { showAlert('Enter a valid 6-digit code', 'error'); return }
    setTwoFA(prev => ({ ...prev, loading: true }))
    try {
      await enable2FA(twoFA.verifyCode)
      showAlert('2FA enabled successfully!', 'success')
      setTwoFA(prev => ({ ...prev, enabled: true, step: 'idle', secret: '', backupCodes: [] }))
    } catch { showAlert('Invalid code — 2FA not enabled', 'error'); setTwoFA(prev => ({ ...prev, loading: false })) }
  }

  const handleDisable2FA = async () => {
    if (!twoFA.verifyCode || twoFA.verifyCode.length < 6) { showAlert('Enter your TOTP code or backup code to disable', 'error'); return }
    setTwoFA(prev => ({ ...prev, loading: true }))
    try {
      await disable2FA(twoFA.verifyCode)
      showAlert('2FA disabled', 'success')
      setTwoFA(prev => ({ ...prev, enabled: false, step: 'idle', verifyCode: '' }))
    } catch { showAlert('Invalid code — 2FA not disabled', 'error'); setTwoFA(prev => ({ ...prev, loading: false })) }
  }

  const alertStyle = (type) => ({
    padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.875rem', marginBottom: '1rem',
    background: type === 'error' ? 'rgba(239,68,68,0.1)' : type === 'success' ? 'rgba(34,197,94,0.1)' : 'rgba(6,182,212,0.1)',
    border: `1px solid ${type === 'error' ? 'rgba(239,68,68,0.3)' : type === 'success' ? 'rgba(34,197,94,0.3)' : 'rgba(6,182,212,0.3)'}`,
    color: type === 'error' ? '#EF4444' : type === 'success' ? '#22C55E' : '#06B6D4',
  })

  return (
    <div style={{ padding: isMobile ? '1rem' : '2rem', maxWidth: '900px', margin: '0 auto' }}>
      <h1 style={{ color: 'var(--text)', fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '2rem' }}>Security</h1>

      {alert && <div style={alertStyle(alert.type)}>{alert.msg}</div>}

      {/* ── Active Sessions ── */}
      <section style={{ background: 'var(--card)', border: '1px solid #1E2D40', borderRadius: '12px', padding: isMobile ? '1rem' : '1.5rem', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1.1rem', fontWeight: 600 }}>Active Sessions</h2>
          {sessions.length > 0 && (
            <button onClick={handleRevokeAll}
              style={{ padding: '0.4rem 0.8rem', borderRadius: '6px', background: 'rgba(239,68,68,0.1)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: '0.8rem' }}>
              Revoke All
            </button>
          )}
        </div>

        {loading ? (
          <p style={{ color: '#64748B' }}>Loading sessions...</p>
        ) : sessions.length === 0 ? (
          <p style={{ color: '#64748B' }}>No active sessions found.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #1E2D40' }}>
                  {['IP Address', 'Device', 'Created', 'Last Active', 'Actions'].map(h => (
                    <th key={h} style={{ padding: '0.5rem 1rem', color: '#64748B', fontSize: '0.75rem', textAlign: 'left', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => <SessionRow key={s.id} session={s} onRevoke={handleRevoke} />)}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── 2FA (admin only) ── */}
      {isAdmin && (
        <section style={{ background: 'var(--card)', border: '1px solid #1E2D40', borderRadius: '12px', padding: isMobile ? '1rem' : '1.5rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>Two-Factor Authentication</h2>

          {twoFA.step === 'idle' && (
            <>
              <p style={{ color: '#64748B', fontSize: '0.875rem', marginBottom: '1rem' }}>
                {twoFA.enabled
                  ? '2FA is <span style="color:#22C55E;font-weight:600">enabled</span> — admins must enter a TOTP code on every login.'
                  : 'Add an extra layer of security. Admins will be required to enter a 6-digit code from their authenticator app after entering their password.'}
              </p>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                {!twoFA.enabled && (
                  <button onClick={handleSetup2FA} disabled={twoFA.loading}
                    style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: '#06B6D4', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                    {twoFA.loading ? 'Setting up...' : 'Enable 2FA'}
                  </button>
                )}
                {twoFA.enabled && (
                  <button onClick={() => setTwoFA(prev => ({ ...prev, step: 'disable', verifyCode: '' }))}
                    style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: 'rgba(239,68,68,0.1)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                    Disable 2FA
                  </button>
                )}
              </div>
            </>
          )}

          {twoFA.step === 'confirm' && (
            <div>
              <p style={{ color: '#94A3B8', fontSize: '0.875rem', marginBottom: '1rem' }}>
                <strong style={{ color: '#F59E0B' }}>Important:</strong> Scan the QR code below with your authenticator app (Google Authenticator, Authy, etc.), then enter a 6-digit code to confirm.
              </p>
              <div style={{ background: 'var(--surface)', border: '1px solid #1E2D40', borderRadius: '8px', padding: '1rem', marginBottom: '1rem', display: 'inline-block' }}>
                <p style={{ color: '#06B6D4', fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{twoFA.otpauth}</p>
              </div>
              {twoFA.backupCodes.length > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <p style={{ color: '#F59E0B', fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem' }}>Backup Codes — store these safely!</p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {twoFA.backupCodes.map((code, i) => (
                      <span key={i} style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: '#94A3B8', background: 'var(--surface)', padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid #1E2D40' }}>{code}</span>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ marginBottom: '1rem' }}>
                <input
                  type="text" placeholder="000000" value={twoFA.verifyCode}
                  onChange={e => setTwoFA(prev => ({ ...prev, verifyCode: e.target.value.replace(/\D/g, '').slice(0, 6) }))}
                  style={{ width: '160px', padding: '0.75rem', borderRadius: '8px', border: '1px solid #1E2D40', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem', letterSpacing: '0.2em' }} />
              </div>
              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button onClick={handleEnable2FA} disabled={twoFA.loading}
                  style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: '#06B6D4', color: 'var(--text)', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                  {twoFA.loading ? 'Verifying...' : 'Confirm & Enable'}
                </button>
                <button onClick={() => setTwoFA(prev => ({ ...prev, step: 'idle', secret: '', backupCodes: [] }))}
                  style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: 'transparent', color: '#64748B', border: '1px solid #1E2D40', cursor: 'pointer', fontSize: '0.875rem' }}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {twoFA.step === 'disable' && (
            <div>
              <p style={{ color: '#94A3B8', fontSize: '0.875rem', marginBottom: '1rem' }}>
                Enter your TOTP code (or a backup code) to disable 2FA.
              </p>
              <div style={{ marginBottom: '1rem' }}>
                <input
                  type="text" placeholder="000000" value={twoFA.verifyCode}
                  onChange={e => setTwoFA(prev => ({ ...prev, verifyCode: e.target.value.replace(/\D/g, '').slice(0, 6) }))}
                  style={{ width: '160px', padding: '0.75rem', borderRadius: '8px', border: '1px solid #1E2D40', background: 'var(--surface)', color: 'var(--text)', fontSize: '1rem', letterSpacing: '0.2em' }} />
              </div>
              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button onClick={handleDisable2FA} disabled={twoFA.loading}
                  style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: 'rgba(239,68,68,0.1)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                  {twoFA.loading ? 'Verifying...' : 'Confirm Disable'}
                </button>
                <button onClick={() => setTwoFA(prev => ({ ...prev, step: 'idle', verifyCode: '' }))}
                  style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', background: 'transparent', color: '#64748B', border: '1px solid #1E2D40', cursor: 'pointer', fontSize: '0.875rem' }}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}