import React, { useState, useCallback, useEffect, lazy, Suspense } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { ThemeProvider } from './hooks/useTheme'
import { ToastProvider } from './hooks/useToast'
import Layout from './components/layout/Layout'
import SearchBar from './components/ui/SearchBar'
import SupportChat from './components/ui/SupportChat'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import Login from './pages/Login'
import CheckStatus from './pages/CheckStatus'
import Dashboard from './pages/Dashboard'
import Analyze from './pages/Analyze'

// Lazy load other pages for better initial load time
const Register = lazy(() => import('./pages/Register').then(m => ({ default: m.default })))
const History = lazy(() => import('./pages/History').then(m => ({ default: m.default })))
const Analytics = lazy(() => import('./pages/Analytics').then(m => ({ default: m.default })))
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.default })))
const UserManagement = lazy(() => import('./pages/UserManagement').then(m => ({ default: m.default })))
const Privacy = lazy(() => import('./pages/Privacy').then(m => ({ default: m.default })))
const Report = lazy(() => import('./pages/Report').then(m => ({ default: m.default })))
const IOCGraph = lazy(() => import('./pages/IOCGraph').then(m => ({ default: m.default })))
const Collaborate = lazy(() => import('./pages/Collaborate').then(m => ({ default: m.default })))
const Admin = lazy(() => import('./pages/Admin').then(m => ({ default: m.default })))
const Sessions = lazy(() => import('./pages/Sessions').then(m => ({ default: m.default })))
const News = lazy(() => import('./pages/News').then(m => ({ default: m.default })))
const APIDocumentation = lazy(() => import('./pages/APIDocumentation').then(m => ({ default: m.default })))

// Loading fallback component
function PageLoader() {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '50vh',
      color: 'var(--sub)'
    }}>
      <div style={{ textAlign: 'center' }}>
        <div className="skeleton" style={{ width: 40, height: 40, borderRadius: '50%', margin: '0 auto 1rem' }} />
        <p>Loading...</p>
      </div>
    </div>
  )
}

const routerConfig = {
  future: {
    v7_startTransition: true,
    v7_relativeSplatPath: true,
  },
}

function OfflineIndicator() {
  const [isOffline, setIsOffline] = useState(!navigator.onLine)

  useEffect(() => {
    const handleOnline = () => setIsOffline(false)
    const handleOffline = () => setIsOffline(true)

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  return (
    <div className={`offline-indicator ${isOffline ? 'visible' : ''}`}>
      You are offline. Some features may be limited.
    </div>
  )
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return (
    <div style={{ padding: 50, color: 'var(--sub)', textAlign: 'center', display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
      <div style={{ textAlign: 'center' }}>
        <div className="skeleton" style={{ width: 48, height: 48, borderRadius: '50%', margin: '0 auto 1rem' }} />
        <div className="skeleton skeleton-text" style={{ width: 100 }} />
      </div>
    </div>
  )
  if (!user) return <Navigate to="/login" />
  return <Layout>{children}</Layout>
}

function AppShell() {
  const [searchOpen, setSearchOpen] = useState(false)
  const [chatOpen, setChatOpen] = useState(false)
  const openSearch  = useCallback(() => setSearchOpen(true),  [])
  const closeSearch = useCallback(() => setSearchOpen(false), [])

  // Global keyboard shortcuts
  useKeyboardShortcuts({ onSearch: openSearch })

  // Listen for sidebar button click (eta:open-search dispatched from Layout)
  useEffect(() => {
    const h = () => openSearch()
    document.addEventListener('eta:open-search', h)
    return () => document.removeEventListener('eta:open-search', h)
  }, [openSearch])

  return (
    <>
      {searchOpen && <SearchBar onClose={closeSearch} />}

      {/* Support Chat FAB - rendered at root level */}
      <button
        className={`support-fab ${chatOpen ? 'open' : ''}`}
        onClick={() => setChatOpen(!chatOpen)}
        title="Get Support"
        aria-label="Open support chat"
        style={{
          position: 'fixed',
          bottom: '1.5rem',
          right: '1.5rem',
          zIndex: 9999,
        }}
      >
        💬
      </button>

      {/* Support Chat Panel */}
      {chatOpen && (
        <div
          className="support-chat-wrapper"
          style={{
            position: 'fixed',
            bottom: '5.5rem',
            right: '1.5rem',
            zIndex: 9998,
          }}
        >
          <SupportChat onClose={() => setChatOpen(false)} />
        </div>
      )}

      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/check-status" element={<CheckStatus />} />
          <Route path="/news" element={<ProtectedRoute><News /></ProtectedRoute>} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/analyze" element={<ProtectedRoute><Analyze /></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
          <Route path="/analytics" element={<ProtectedRoute><Analytics /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
          <Route path="/privacy" element={<ProtectedRoute><Privacy /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute><Report /></ProtectedRoute>} />
          <Route path="/reports/:id" element={<ProtectedRoute><Report /></ProtectedRoute>} />
          <Route path="/graph" element={<ProtectedRoute><IOCGraph /></ProtectedRoute>} />
          <Route path="/users" element={<ProtectedRoute><UserManagement /></ProtectedRoute>} />
          <Route path="/collaborate" element={<ProtectedRoute><Collaborate /></ProtectedRoute>} />
          <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
          <Route path="/sessions" element={<ProtectedRoute><Sessions /></ProtectedRoute>} />
          <Route path="/api-docs" element={<ProtectedRoute><APIDocumentation /></ProtectedRoute>} />
          <Route path="/" element={<Navigate to="/dashboard" />} />
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Routes>
      </Suspense>
    </>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <Router {...routerConfig}>
            <OfflineIndicator />
            <AppShell />
          </Router>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}