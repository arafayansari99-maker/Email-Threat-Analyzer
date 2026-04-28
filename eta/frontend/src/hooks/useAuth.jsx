import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import api from '../services/api'
import { getProfile } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('eta_token')
      if (token) {
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`
        await refreshUser()
      }
      setLoading(false)
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
    _persist(data)
    setUser(data.user)
    return data.user
  }, [])

  const register = useCallback(async (username, email, password) => {
    const { data } = await api.post('/api/auth/register', { username, email, password })
    _persist(data)
    setUser(data.user)
    return data.user
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('eta_token')
    localStorage.removeItem('eta_user')
    delete api.defaults.headers.common['Authorization']
    setUser(null)
  }, [])

  const refreshUser = useCallback(async () => {
    try {
      const { data } = await getProfile()
      localStorage.setItem('eta_user', JSON.stringify(data))
      setUser(data)
      return data
    } catch (err) {
      console.error('Failed to refresh user:', err)
      logout()
    }
  }, [logout])

  // Sync user state from already-stored data — used by Login.jsx after manual token storage
  const syncUser = useCallback((userData) => {
    setUser(userData)
  }, [])

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser, syncUser }}>
      {children}
    </AuthContext.Provider>
  )
}

function _persist(data) {
  localStorage.setItem('eta_token', data.access_token)
  localStorage.setItem('eta_user', JSON.stringify(data.user))
  api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
