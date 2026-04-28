import { useState, useEffect } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'
import { useTheme } from '../../hooks/useTheme'

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/history', label: 'Scan History' },
  { to: '/reports', label: 'Reports' },
  { to: '/analytics', label: 'Analytics' },
]

const TOOLS_NAV = [
  { to: '/analyze', label: 'Analyzer' },
  { to: '/graph', label: 'IOC Graph' },
  { to: '/collaborate', label: 'Collaborate' },
  { to: '/news', label: 'Cyber News' },
  { to: '/privacy', label: 'Privacy' },
  { to: '/sessions', label: 'Security' },
  { to: '/settings', label: 'Settings' },
]

const ADMIN_NAV = [
  { to: '/users', label: 'User Management' },
  { to: '/admin', label: 'Admin Panel' },
]

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const isDark = theme === 'dark'

  // Mobile menu state
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)

  // Check for mobile viewport
  useEffect(() => {
    const checkMobile = () => setIsMobile(window.innerWidth < 768)
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  useEffect(() => window.scrollTo(0, 0), [location.pathname])

  // Close sidebar on route change (mobile)
  useEffect(() => {
    if (isMobile) setSidebarOpen(false)
  }, [location.pathname, isMobile])

  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false)
  const handleLogout = () => setShowLogoutConfirm(true)
  const confirmLogout = () => { logout(); navigate('/login'); setShowLogoutConfirm(false) }
  const cancelLogout = () => setShowLogoutConfirm(false)
  const initials = user?.username?.slice(0, 2).toUpperCase() || 'AN'

  // Responsive sidebar styles
  const sidebarStyle = isMobile ? {
    position: 'fixed', inset: 0, width: '100%', height: '100vh',
    zIndex: 999, transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)',
    transition: 'transform 0.3s ease',
  } : {
    width: 260, flexShrink: 0, borderRight: '1px solid var(--border)',
    background: 'var(--surface)', display: 'flex', flexDirection: 'column',
    position: 'sticky', top: 0, height: '100vh', overflow: 'hidden',
  }

  return (
    <div style={{ display: 'flex', width: '100%', minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Mobile overlay */}
      {isMobile && sidebarOpen && (
        <div
          onClick={() => setSidebarOpen(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 998 }}
        />
      )}

      {/* Sidebar */}
      <aside style={sidebarStyle}>
        {/* Logo */}
        <div style={{ padding: '1.25rem', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: 40, height: 40, borderRadius: 12,
              background: isDark ? 'rgba(6,182,212,0.15)' : 'rgba(2,132,199,0.1)',
              border: `1px solid ${isDark ? 'rgba(6,182,212,0.3)' : 'rgba(2,132,199,0.25)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <span style={{ color: 'var(--cyan)', fontSize: 20, fontWeight: 'bold' }}>E</span>
            </div>
            <div>
              <p style={{ fontSize: 15, fontWeight: 'bold', color: 'var(--text)', letterSpacing: '0.05em' }}>ETA</p>
              <p style={{ fontSize: 10, color: 'var(--sub)', letterSpacing: '0.05em' }}>Email Threat Analyzer</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '1rem 0.75rem', overflowY: 'auto' }}>
          <div style={{ marginBottom: '0.5rem' }}>
            <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Main</p>
          </div>
          {NAV.map(({ to, label, icon }) => (
            <NavLink key={to} to={to} end={to === '/dashboard'}
              style={({ isActive }) => ({
                display: 'block',
                padding: '0.75rem 0.75rem', borderRadius: 8, fontSize: 14,
                marginBottom: 4, fontWeight: 500,
                background: isActive ? 'var(--cyan)' + '20' : 'transparent',
                color: isActive ? 'var(--cyan)' : 'var(--text)',
                border: isActive ? '1px solid var(--cyan)' + '40' : '1px solid transparent',
                textDecoration: 'none', transition: 'all 0.15s ease',
              })}
            >
              {label}
            </NavLink>
          ))}

          <div style={{ marginBottom: '0.5rem', marginTop: '0.75rem' }}>
            <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Tools</p>
          </div>
          {TOOLS_NAV.map(({ to, label, icon }) => (
            <NavLink key={to} to={to}
              style={({ isActive }) => ({
                display: 'block',
                padding: '0.75rem 0.75rem', borderRadius: 8, fontSize: 14,
                marginBottom: 4, fontWeight: 500,
                background: isActive ? 'var(--cyan)' + '20' : 'transparent',
                color: isActive ? 'var(--cyan)' : 'var(--text)',
                border: isActive ? '1px solid var(--cyan)' + '40' : '1px solid transparent',
                textDecoration: 'none', transition: 'all 0.15s ease',
              })}
            >
              {label}
            </NavLink>
          ))}

          {user?.role?.includes('admin') && (
            <>
              <div style={{ marginBottom: '0.5rem', marginTop: '0.75rem' }}>
                <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Admin</p>
              </div>
              {ADMIN_NAV.map(({ to, label }) => (
                <NavLink key={to} to={to}
                  style={({ isActive }) => ({
                    display: 'block',
                    padding: '0.75rem 0.75rem', borderRadius: 8, fontSize: 14,
                    marginBottom: 4, fontWeight: 500,
                    background: isActive ? 'var(--cyan)' + '20' : 'transparent',
                    color: isActive ? 'var(--cyan)' : 'var(--text)',
                    border: isActive ? '1px solid var(--cyan)' + '40' : '1px solid transparent',
                    textDecoration: 'none', transition: 'all 0.15s ease',
                  })}
                >
                  {label}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        {/* User section */}
        <div style={{ padding: '1rem', borderTop: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(6,182,212,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <span style={{ color: 'var(--cyan)', fontSize: 13, fontWeight: 'bold' }}>{initials}</span>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.username}</p>
              <p style={{ fontSize: 11, color: 'var(--sub)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.email}</p>
            </div>
          </div>
          <button onClick={handleLogout} style={{
            width: '100%', padding: '0.75rem', borderRadius: 8,
            background: 'rgba(239,68,68,0.1)', color: 'var(--red)', border: 'none',
            cursor: 'pointer', fontSize: 13, fontWeight: 500,
          }}>
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', minHeight: '100vh', background: 'var(--bg)' }}>
        {/* Mobile header */}
        {isMobile && (
          <header style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '1rem', borderBottom: '1px solid var(--border)',
            background: 'var(--surface)', position: 'sticky', top: 0, zIndex: 100,
          }}>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              style={{
                width: 40, height: 40, borderRadius: 8,
                background: 'var(--card)', border: '1px solid var(--border)',
                color: 'var(--text)', fontSize: 20, cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
            >
              ☰
            </button>
            <span style={{ fontSize: 16, fontWeight: 600, color: 'var(--text)' }}>ETA</span>
            <div style={{ width: 40 }} />
          </header>
        )}
        {children}
      </main>

      {/* Logout Confirmation Modal */}
      {showLogoutConfirm && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000, padding: '1rem',
        }}>
          <div style={{
            background: 'var(--card)',
            borderRadius: 12,
            border: '1px solid var(--border)',
            padding: '1.5rem',
            maxWidth: 360,
            width: '100%',
          }}>
            <h3 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.75rem' }}>
              Sign Out?
            </h3>
            <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginBottom: '1.5rem' }}>
              Are you sure you want to sign out?
            </p>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                onClick={cancelLogout}
                style={{
                  flex: 1, padding: '0.875rem', borderRadius: 8,
                  background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500,
                }}
              >
                Cancel
              </button>
              <button
                onClick={confirmLogout}
                style={{
                  flex: 1, padding: '0.875rem', borderRadius: 8,
                  background: 'var(--red)', color: '#fff', border: 'none',
                  cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500,
                }}
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}