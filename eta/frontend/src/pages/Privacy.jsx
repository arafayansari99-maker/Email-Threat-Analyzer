import { useState, useEffect } from 'react'

function ActionButton({ label, desc, color, onClick }) {
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
        padding: '1.25rem',
        cursor: 'pointer',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        transition: 'all 0.2s ease',
        transform: hovered ? 'translateY(-2px)' : 'translateY(0)',
        boxShadow: hovered ? `0 4px 12px ${color}20` : 'none'
      }}
    >
      <span style={{ color: color, fontWeight: 600, fontSize: '0.9375rem', display: 'block' }}>{label}</span>
      <p style={{ color: '#64748B', fontSize: '0.8125rem', margin: '0.5rem 0 0 0' }}>{desc}</p>
    </button>
  )
}

function Toggle({ checked, onChange }) {
  return (
    <label style={{ position: 'relative', display: 'inline-block', width: 48, height: 26, cursor: 'pointer' }}>
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        style={{ opacity: 0, width: 0, height: 0 }}
      />
      <span style={{
        position: 'absolute',
        inset: 0,
        background: checked ? '#06B6D4' : 'var(--border)',
        borderRadius: 13,
        transition: 'all 0.2s ease'
      }} />
      <span style={{
        position: 'absolute',
        top: 3,
        left: checked ? 25 : 3,
        width: 20,
        height: 20,
        borderRadius: '50%',
        background: '#fff',
        transition: 'all 0.2s ease',
        pointerEvents: 'none'
      }} />
    </label>
  )
}

export default function Privacy() {
  const [loading, setLoading] = useState(true)
  const [dataPolicy, setDataPolicy] = useState(true)
  const [anonymizedStats, setAnonymizedStats] = useState(true)
  const [showEmail, setShowEmail] = useState(false)

  useEffect(() => {
    setLoading(false)
  }, [])

  const handleExport = async () => {
    alert('Exporting your data...')
  }

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete all your scan history? This cannot be undone.')) {
      alert('All scans deleted')
    }
  }

  const features = [
    { id: 'dataPolicy', title: 'Data Collection Policy', desc: 'Allow collection of scan data for threat intelligence', enabled: dataPolicy, setEnabled: setDataPolicy },
    { id: 'anonymizedStats', title: 'Anonymized Statistics', desc: 'Share anonymized threat statistics to improve detection', enabled: anonymizedStats, setEnabled: setAnonymizedStats },
    { id: 'showEmail', title: 'Show Email in Reports', desc: 'Include email sender in generated reports', enabled: showEmail, setEnabled: setShowEmail },
  ]

  return (
    <div style={{ padding: '1.5rem' }}>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Privacy Settings</h1>
      <p style={{ color: '#64748B', fontSize: '0.9375rem', marginBottom: '2rem' }}>Manage your privacy and data preferences</p>

      {loading ? (
        <p style={{ color: '#64748B' }}>Loading...</p>
      ) : (
        <>
          {/* Privacy Settings */}
          <div style={{ marginBottom: '2rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Privacy Options</h2>
            <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
              {features.map((f, i) => (
                <div key={f.id} style={{
                  padding: '1rem 1.25rem',
                  borderBottom: i < features.length - 1 ? '1px solid var(--border)' : 'none',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
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
          <div style={{ marginBottom: '2rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Data Management</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <ActionButton label="Export Data" desc="Download your scan data as JSON" color="#06B6D4" onClick={handleExport} />
              <ActionButton label="Clear Data" desc="Delete all your scan history" color="#EF4444" onClick={handleDelete} />
            </div>
          </div>

          {/* Info Section */}
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
            <h3 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, margin: '0 0 0.75rem 0' }}>Data Protection</h3>
            <p style={{ color: '#64748B', fontSize: '0.875rem', lineHeight: 1.6, marginBottom: '0.75rem' }}>
              Your scan data is encrypted and stored securely. We never share your individual scan data with third parties without your explicit consent.
            </p>
            <p style={{ color: '#64748B', fontSize: '0.875rem', lineHeight: 1.6, margin: 0 }}>
              By selecting anonymized statistics, you help improve threat detection for everyone while keeping your identity protected.
            </p>
          </div>
        </>
      )}
    </div>
  )
}