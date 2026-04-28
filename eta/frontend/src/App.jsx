import React, { useState, useCallback, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { ThemeProvider } from './hooks/useTheme'
import { ToastProvider } from './hooks/useToast'
import Layout from './components/layout/Layout'
import SearchBar from './components/ui/SearchBar'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import Login from './pages/Login'
import Register from './pages/Register'
import CheckStatus from './pages/CheckStatus'
import Dashboard from './pages/Dashboard'
import Analyze from './pages/Analyze'
import History from './pages/History'
import Analytics from './pages/Analytics'
import Settings from './pages/Settings'
import UserManagement from './pages/UserManagement'
import Privacy from './pages/Privacy'
import Report from './pages/Report'
import IOCGraph from './pages/IOCGraph'
import Collaborate from './pages/Collaborate'
import Admin from './pages/Admin'
import Sessions from './pages/Sessions'
import News from './pages/News'
import APIDocumentation from './pages/APIDocumentation'

const routerConfig = {
  future: {
    v7_startTransition: true,
    v7_relativeSplatPath: true,
  },
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <div style={{ padding: 50, color: 'var(--sub)', textAlign: 'center' }}>Loading...</div>
  if (!user) return <Navigate to="/login" />
  return <Layout>{children}</Layout>
}

function AppShell() {
  const [searchOpen, setSearchOpen] = useState(false)
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
    </>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <Router {...routerConfig}>
            <AppShell />
          </Router>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}