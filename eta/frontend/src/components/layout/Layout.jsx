import { useState, useEffect, useRef } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'
import { useTheme } from '../../hooks/useTheme'
import { useNotifications } from '../../hooks/useNotifications'

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/history', label: 'Scan History' },
  { to: '/reports', label: 'Reports' },
  { to: '/analytics', label: 'Analytics' },
]

const TOOLS_NAV = [
  { to: '/analyze', label: 'Analyzer' },
  { to: '/graph', label: 'IOC Graph' },
{ to: '/news', label: 'Cyber News' },
  { to: '/sessions', label: 'Security' },
  { to: '/settings', label: 'Settings' },
]

const ADMIN_NAV = [
  { to: '/users', label: 'User Management' },
  { to: '/admin', label: 'Admin Panel' },
]

const TYPE_COLOR = { scan: '#06B6D4', message: '#8B5CF6', settings: '#64748B', system: '#F59E0B' }

function NotificationBell({ isMobile }) {
  const { notifications, unreadCount, markAllRead, markRead } = useNotifications()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleOpen = () => {
    setOpen(v => !v)
    if (!open && unreadCount > 0) markAllRead()
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={handleOpen}
        title="Notifications"
        style={{
          width: 38, height: 38, borderRadius: 10, border: '1px solid var(--border)',
          background: 'var(--card)', color: 'var(--text)', cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18, position: 'relative', flexShrink: 0,
        }}
      >
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
        </svg>
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute', top: -4, right: -4,
            background: '#EF4444', color: '#fff',
            borderRadius: '50%', width: 18, height: 18,
            fontSize: 10, fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '2px solid var(--bg)',
          }}>
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: 46, right: 0,
          width: 320, maxHeight: 400, overflowY: 'auto',
          background: 'var(--card)', border: '1px solid var(--border)',
          borderRadius: 12, boxShadow: '0 8px 32px rgba(0,0,0,0.25)',
          zIndex: 2000,
        }}>
          <div style={{ padding: '0.875rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Notifications</span>
            {notifications.length > 0 && (
              <button onClick={markAllRead} style={{ background: 'none', border: 'none', color: 'var(--cyan)', cursor: 'pointer', fontSize: 11 }}>
                Mark all read
              </button>
            )}
          </div>
          {notifications.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--sub)', fontSize: 13 }}>
              No notifications yet
            </div>
          ) : (
            notifications.slice(0, 20).map(n => (
              <div
                key={n.id}
                onClick={() => markRead(n.id)}
                style={{
                  padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)',
                  background: n.is_read ? 'transparent' : 'rgba(6,182,212,0.05)',
                  cursor: 'pointer', display: 'flex', gap: '0.625rem', alignItems: 'flex-start',
                }}
              >
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: TYPE_COLOR[n.type] || '#64748B', flexShrink: 0, marginTop: 5 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 13, fontWeight: n.is_read ? 500 : 700, color: 'var(--text)', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.title}</p>
                  {n.body && <p style={{ fontSize: 11, color: 'var(--sub)', lineHeight: 1.4 }}>{n.body}</p>}
                  <p style={{ fontSize: 10, color: 'var(--sub)', marginTop: 2 }}>{new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
                </div>
                {!n.is_read && <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--cyan)', flexShrink: 0, marginTop: 4 }} />}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const isDark = theme === 'dark'

  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)

  useEffect(() => {
    const checkMobile = () => setIsMobile(window.innerWidth < 768)
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  useEffect(() => window.scrollTo(0, 0), [location.pathname])

  useEffect(() => {
    if (isMobile) setSidebarOpen(false)
  }, [location.pathname, isMobile])

  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false)
  const handleLogout = () => setShowLogoutConfirm(true)
  const confirmLogout = () => { logout(); navigate('/login'); setShowLogoutConfirm(false) }
  const cancelLogout = () => setShowLogoutConfirm(false)
  const initials = user?.username?.slice(0, 2).toUpperCase() || 'AN'

  const sidebarStyle = isMobile ? {
    position: 'fixed', top: 0, left: 0, bottom: 0,
    width: 280, maxWidth: '85vw', height: '100vh',
    zIndex: 999, transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)',
    transition: 'transform 0.3s ease',
    background: 'var(--surface)', borderRight: '1px solid var(--border)',
    display: 'flex', flexDirection: 'column', overflowY: 'auto',
  } : {
    width: 260, flexShrink: 0, borderRight: '1px solid var(--border)',
    background: 'var(--surface)', display: 'flex', flexDirection: 'column',
    position: 'sticky', top: 0, height: '100vh', overflow: 'hidden',
  }

  const navLinkStyle = ({ isActive }) => ({
    display: 'block', padding: '0.75rem 0.75rem', borderRadius: 8, fontSize: 14,
    marginBottom: 4, fontWeight: 500,
    background: isActive ? 'var(--cyan)20' : 'transparent',
    color: isActive ? 'var(--cyan)' : 'var(--text)',
    border: isActive ? '1px solid var(--cyan)40' : '1px solid transparent',
    textDecoration: 'none', transition: 'all 0.15s ease',
  })

  return (
    <div style={{ display: 'flex', width: '100%', minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Mobile overlay */}
      {isMobile && sidebarOpen && (
        <div onClick={() => setSidebarOpen(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 998 }} />
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
          <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.5rem' }}>Main</p>
          {NAV.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to === '/dashboard'} style={navLinkStyle}>{label}</NavLink>
          ))}

          <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.5rem', marginTop: '0.75rem' }}>Tools</p>
          {TOOLS_NAV.map(({ to, label }) => (
            <NavLink key={to} to={to} style={navLinkStyle}>{label}</NavLink>
          ))}

          {user?.role?.includes('admin') && (
            <>
              <p style={{ fontSize: 11, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.5rem', marginTop: '0.75rem' }}>Admin</p>
              {ADMIN_NAV.map(({ to, label }) => (
                <NavLink key={to} to={to} style={navLinkStyle}>{label}</NavLink>
              ))}
            </>
          )}
        </nav>

        {/* User section */}
        <div style={{ padding: '1rem', borderTop: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(6,182,212,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
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
      <main style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', minHeight: '100vh', background: 'var(--bg)', paddingBottom: isMobile ? '4rem' : 0, display: 'flex', flexDirection: 'column' }}>
        {/* Top bar — mobile hamburger + notification bell */}
        <header style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: isMobile ? '0.75rem 1rem' : '1.25rem 1.5rem',
          borderBottom: '1px solid var(--border)',
          background: 'var(--surface)', position: 'sticky', top: 0, zIndex: 100,
          gap: '0.75rem',
        }}>
          {isMobile ? (
            <button onClick={() => setSidebarOpen(!sidebarOpen)} style={{
              width: 38, height: 38, borderRadius: 8,
              background: 'var(--card)', border: '1px solid var(--border)',
              color: 'var(--text)', fontSize: 18, cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>☰</button>
          ) : (
            <span style={{ fontSize: 13, color: 'var(--sub)' }}>
              {new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })}
            </span>
          )}

          {isMobile && <span style={{ fontSize: 16, fontWeight: 600, color: 'var(--text)' }}>ETA</span>}

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginLeft: 'auto' }}>
            {/* Theme toggle */}
            <button onClick={toggle} title="Toggle theme" style={{
              width: 38, height: 38, borderRadius: 10, border: '1px solid var(--border)',
              background: 'var(--card)', cursor: 'pointer', fontSize: 16,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {isDark ? (
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <circle cx="12" cy="12" r="5"/>
                <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
              </svg>
            ) : (
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            )}
            </button>
            {/* Notification bell */}
            <NotificationBell isMobile={isMobile} />
          </div>
        </header>

        <div style={{ flex: 1 }}>
          {children}
        </div>
      </main>

      {/* Mobile Bottom Navigation */}
      {isMobile && (
        <nav className="bottom-nav" aria-label="Main navigation">
          <NavLink to="/dashboard" className={({ isActive }) => `bottom-nav-item${isActive ? ' active' : ''}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
            <span>Home</span>
          </NavLink>
          <NavLink to="/analyze" className={({ isActive }) => `bottom-nav-item${isActive ? ' active' : ''}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <span>Analyze</span>
          </NavLink>
          <NavLink to="/history" className={({ isActive }) => `bottom-nav-item${isActive ? ' active' : ''}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span>History</span>
          </NavLink>
          <NavLink to="/reports" className={({ isActive }) => `bottom-nav-item${isActive ? ' active' : ''}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Reports</span>
          </NavLink>
        </nav>
      )}

      {/* Logout Confirmation Modal */}
      {showLogoutConfirm && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000, padding: '1rem',
        }}>
          <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', maxWidth: 360, width: '100%' }}>
            <h3 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.75rem' }}>Sign Out?</h3>
            <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginBottom: '1.5rem' }}>Are you sure you want to sign out?</p>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button onClick={cancelLogout} style={{ flex: 1, padding: '0.875rem', borderRadius: 8, background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500 }}>Cancel</button>
              <button onClick={confirmLogout} style={{ flex: 1, padding: '0.875rem', borderRadius: 8, background: 'var(--red)', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500 }}>Sign Out</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
