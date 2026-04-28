import { useState } from 'react'
import { Link } from 'react-router-dom'

const API_SECTIONS = [
  {
    id: 'auth',
    title: 'Authentication',
    description: 'JWT-based authentication endpoints',
    endpoints: [
      {
        method: 'POST',
        path: '/api/auth/login',
        params: 'username, password',
        description: 'Login with email or username',
        returns: 'access_token, user',
      },
      {
        method: 'POST',
        path: '/api/auth/register',
        params: 'username, email, password',
        description: 'Create new account',
        returns: 'access_token, user',
      },
      {
        method: 'POST',
        path: '/api/auth/check-status',
        params: 'email',
        description: 'Check if account is approved',
        returns: 'status, message',
      },
      {
        method: 'POST',
        path: '/api/auth/password-reset-request',
        params: 'email',
        description: 'Request password reset token',
        returns: 'message',
      },
      {
        method: 'POST',
        path: '/api/auth/password-reset-confirm',
        params: 'token, new_password',
        description: 'Reset password with token',
        returns: 'message',
      },
    ],
  },
  {
    id: 'analysis',
    title: 'Email Analysis',
    description: 'Email threat analysis endpoints',
    endpoints: [
      {
        method: 'POST',
        path: '/api/analyze-email',
        params: 'file (multipart)',
        description: 'Analyze single email file',
        returns: 'scan_id, risk_score, verdict, threats',
      },
      {
        method: 'POST',
        path: '/api/analyze-batch',
        params: 'files (multipart)',
        description: 'Analyze multiple email files',
        returns: 'results array',
      },
      {
        method: 'POST',
        path: '/api/extension-scan',
        params: 'email text, subject, sender',
        description: 'Scan email from extension',
        returns: 'scan_id, verdict, risk_score',
      },
    ],
  },
  {
    id: 'history',
    title: 'Scan History',
    description: 'Retrieve and manage scan history',
    endpoints: [
      {
        method: 'GET',
        path: '/api/scan-history',
        params: 'page, limit, verdict, search',
        description: 'Get paginated scan history',
        returns: 'records array, total, pages',
      },
      {
        method: 'GET',
        path: '/api/stats',
        params: '-',
        description: 'Get scan statistics',
        returns: 'total, malicious, suspicious, safe',
      },
      {
        method: 'DELETE',
        path: '/api/scan/{id}',
        params: '-',
        description: 'Delete a scan record',
        returns: 'message',
      },
    ],
  },
  {
    id: 'reports',
    title: 'Reports',
    description: 'Generate and export reports',
    endpoints: [
      {
        method: 'GET',
        path: '/api/report/{id}',
        params: '-',
        description: 'Get full report JSON',
        returns: 'report object',
      },
      {
        method: 'GET',
        path: '/api/report/{id}/json',
        params: '-',
        description: 'Download report as JSON',
        returns: 'file download',
      },
      {
        method: 'POST',
        path: '/api/report/{id}/pdf',
        params: '-',
        description: 'Generate PDF report',
        returns: 'file download',
      },
      {
        method: 'POST',
        path: '/api/reports/share/{scan_id}',
        params: 'hours',
        description: 'Create shareable link',
        returns: 'share_url, expires_at',
      },
    ],
  },
  {
    id: 'admin',
    title: 'Admin',
    description: 'Administration endpoints (admin only)',
    endpoints: [
      {
        method: 'GET',
        path: '/api/admin/users',
        params: 'page, limit, search',
        description: 'List all users',
        returns: 'users array',
      },
      {
        method: 'POST',
        path: '/api/admin/users/{id}/approve',
        params: '-',
        description: 'Approve user account',
        returns: 'message',
      },
      {
        method: 'DELETE',
        path: '/api/admin/users/{id}',
        params: '-',
        description: 'Delete user account',
        returns: 'message',
      },
      {
        method: 'GET',
        path: '/api/admin/audit-logs',
        params: 'page, limit, action',
        description: 'Get audit trail',
        returns: 'logs array',
      },
    ],
  },
]

export default function APIDocumentation() {
  const [activeSection, setActiveSection] = useState('auth')
  const [searchQuery, setSearchQuery] = useState('')

  const filteredSections = API_SECTIONS.map(section => ({
    ...section,
    endpoints: section.endpoints.filter(e =>
      e.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.description.toLowerCase().includes(searchQuery.toLowerCase())
    )
  })).filter(section => section.endpoints.length > 0)

  const getMethodColor = (method) => {
    switch (method) {
      case 'GET': return 'var(--green)'
      case 'POST': return 'var(--cyan)'
      case 'PUT': return 'var(--amber)'
      case 'DELETE': return 'var(--red)'
      case 'PATCH': return 'var(--purple)'
      default: return 'var(--sub)'
    }
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Sidebar */}
      <aside style={{
        width: 240, flexShrink: 0, borderRight: '1px solid var(--border)',
        background: 'var(--surface)', padding: '1.5rem', position: 'sticky', top: 0, height: '100vh',
      }}>
        <Link to="/dashboard" style={{ color: 'var(--cyan)', textDecoration: 'none', fontSize: '0.875rem' }}>
          ← Back to Dashboard
        </Link>
        <h2 style={{ color: 'var(--text)', fontSize: '1.25rem', fontWeight: 600, marginTop: '1.5rem', marginBottom: '1rem' }}>
          API Reference
        </h2>

        <input
          type="text"
          placeholder="Search endpoints..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            width: '100%', padding: '0.5rem', borderRadius: 8,
            border: '1px solid var(--border)', background: 'var(--card)',
            color: 'var(--text)', fontSize: '0.875rem', marginBottom: '1rem',
          }}
        />

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {API_SECTIONS.map(section => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              style={{
                padding: '0.5rem 0.75rem', borderRadius: 6, border: 'none',
                background: activeSection === section.id ? 'var(--cyan)' : 'transparent',
                color: activeSection === section.id ? '#fff' : 'var(--sub)',
                cursor: 'pointer', fontSize: '0.875rem', textAlign: 'left',
                fontWeight: activeSection === section.id ? 600 : 400,
              }}
            >
              {section.title}
            </button>
          ))}
        </nav>
      </aside>

      {/* Main Content */}
      <main style={{ flex: 1, padding: '2rem', overflowY: 'auto' }}>
        {filteredSections.map(section => (
          <div key={section.id} style={{ marginBottom: '2.5rem' }} id={section.id}>
            <h3 style={{ color: 'var(--text)', fontSize: '1.5rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              {section.title}
            </h3>
            <p style={{ color: 'var(--sub)', fontSize: '0.9375rem', marginBottom: '1.5rem' }}>
              {section.description}
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {section.endpoints.map((endpoint, idx) => (
                <div key={idx} style={{
                  background: 'var(--card)', borderRadius: 10,
                  border: '1px solid var(--border)', padding: '1rem',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                    <span style={{
                      padding: '0.25rem 0.5rem', borderRadius: 4,
                      background: getMethodColor(endpoint.method),
                      color: '#fff', fontSize: '0.75rem', fontWeight: 700,
                    }}>
                      {endpoint.method}
                    </span>
                    <code style={{
                      color: 'var(--text)', fontSize: '0.9375rem',
                      fontFamily: 'monospace', fontWeight: 500,
                    }}>
                      {endpoint.path}
                    </code>
                  </div>
                  <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', marginBottom: '0.5rem' }}>
                    {endpoint.description}
                  </p>
                  <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem' }}>
                    {endpoint.params !== '-' && (
                      <span>
                        <span style={{ color: 'var(--sub)' }}>Params: </span>
                        <code style={{ color: 'var(--cyan)' }}>{endpoint.params}</code>
                      </span>
                    )}
                    <span>
                      <span style={{ color: 'var(--sub)' }}>Returns: </span>
                      <code style={{ color: 'var(--green)' }}>{endpoint.returns}</code>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </main>
    </div>
  )
}