import { useState, useEffect, useCallback, useRef } from 'react'
import { getNotifications, markAllNotificationsRead, markNotificationRead } from '../services/api'
import { useAuth } from './useAuth'

export function useNotifications(pollInterval = 30000) {
  const { user } = useAuth()
  const [notifications, setNotifications] = useState([])
  const timerRef = useRef(null)

  const fetch = useCallback(async () => {
    if (!user) return
    try {
      const { data } = await getNotifications()
      setNotifications(data || [])
    } catch {}
  }, [user])

  // Poll on mount and on interval
  useEffect(() => {
    if (!user) return
    fetch()
    timerRef.current = setInterval(fetch, pollInterval)
    return () => clearInterval(timerRef.current)
  }, [user, fetch, pollInterval])

  const unreadCount = notifications.filter(n => !n.is_read).length

  const markAllRead = useCallback(async () => {
    setNotifications(prev => prev.map(n => ({ ...n, is_read: true })))
    try { await markAllNotificationsRead() } catch {}
  }, [])

  const markRead = useCallback(async (id) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, is_read: true } : n))
    try { await markNotificationRead(id) } catch {}
  }, [])

  // Allow other parts of the app to push a local notification immediately
  const pushLocal = useCallback((notif) => {
    setNotifications(prev => [{ id: Date.now(), is_read: false, created_at: new Date().toISOString(), ...notif }, ...prev])
  }, [])

  return { notifications, unreadCount, markAllRead, markRead, pushLocal, refresh: fetch }
}
