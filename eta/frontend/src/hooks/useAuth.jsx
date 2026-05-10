import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import api, { setToken } from '../services/api'
import { getProfile } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(() => {
    // Restore user profile from localStorage for instant render (no token, just display info).
    // Guard against corrupt/oversized storage entries.
    try {
      const raw = localStorage.getItem('eta_user')
      if (!raw) return null
      const parsed = JSON.parse(raw)
      // Reject anything that isn't a plain user object
      if (!parsed || typeof parsed !== 'object' || !parsed.id) return null
      return parsed
    } catch {
      localStorage.removeItem('eta_user')
      return null
    }
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // On page load there is no in-memory token (cleared by refresh).
    // Try the httpOnly refresh-token cookie to silently re-issue an access token.
    // Use raw axios (no interceptors) to avoid the 401 interceptor retrying refresh in a loop.
    const initAuth = async () => {
      try {
        const { data } = await axios.post('/api/auth/refresh', {}, { withCredentials: true })
        setToken(data.access_token)
        // Fetch fresh profile to confirm identity
        const { data: profile } = await getProfile()
        localStorage.setItem('eta_user', JSON.stringify(profile))
        setUser(profile)
      } catch {
        // No valid refresh token — clear stale user data and stay on current page.
        // The 401 interceptor in api.js will redirect to /login if a protected
        // endpoint is subsequently called.
        setToken(null)
        localStorage.removeItem('eta_user')
        setUser(null)
      } finally {
        setLoading(false)
      }
    }
    initAuth()
  }, [])

  const login = useCallback(async (email, password) => {
    const formData = new URLSearchParams()
    formData.append('username', email)
    formData.append('password', password)
    const { data } = await api.post('/api/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })

    setToken(data.access_token)
    try { localStorage.setItem('eta_user', JSON.stringify(data.user)) } catch { /* storage unavailable */ }
    setUser(data.user)
    return data.user
  }, [])

  const register = useCallback(async (username, email, password) => {
    const { data } = await api.post('/api/auth/register', { username, email, password })
    setToken(data.access_token)
    try { localStorage.setItem('eta_user', JSON.stringify(data.user)) } catch { /* storage unavailable */ }
    setUser(data.user)
    return data.user
  }, [])

  const logout = useCallback(async () => {
    // Tell backend to revoke the refresh-token cookie
    try { await api.post('/api/auth/logout') } catch { /* ignore if already expired */ }
    setToken(null)
    localStorage.removeItem('eta_user')
    setUser(null)
  }, [])

  const refreshUser = useCallback(async () => {
    try {
      const { data } = await getProfile()
      try { localStorage.setItem('eta_user', JSON.stringify(data)) } catch { /* storage unavailable */ }
      setUser(data)
      return data
    } catch {
      logout()
    }
  }, [logout])

  const syncUser = useCallback((userData) => {
    setUser(userData)
  }, [])

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser, syncUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
