import axios from 'axios'

// The frontend only uses a backend URL here. No secret API keys should be stored in client code.
// In production, set VITE_API_URL to the backend host; in dev Vite proxy sends /api requests to localhost:8000.
const BASE = import.meta.env.VITE_API_URL || ''

// ── In-memory token storage ────────────────────────────────────────────────────
// Storing the JWT in localStorage exposes it to XSS. Keep it in a JS module
// variable instead — it survives navigation but is cleared on page refresh,
// at which point the httpOnly refresh-token cookie silently re-issues it.
let _token = null

export const setToken = (t) => {
  _token = t
  if (t) api.defaults.headers.common['Authorization'] = `Bearer ${t}`
  else   delete api.defaults.headers.common['Authorization']
}
export const getToken = () => _token

// ── Simple in-memory cache for API responses ───────────────────────────────────
const cache = new Map()
const CACHE_DURATION = 5 * 60 * 1000

const inflight = new Map()

const API_TIMEOUT = 15000

let lastPrune = Date.now()
function pruneCache() {
  const now = Date.now()
  if (now - lastPrune < 60000) return
  lastPrune = now
  for (const [key, value] of cache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) cache.delete(key)
  }
}

const api = axios.create({
  baseURL: BASE,
  timeout: API_TIMEOUT,
  withCredentials: true,  // send httpOnly refresh-token cookie on every request
})

// ── Request interceptor ────────────────────────────────────────────────────────
// Token is set directly on api.defaults.headers by setToken(); no localStorage read needed.
api.interceptors.request.use(cfg => cfg)

// ── 401 interceptor with cookie-based silent refresh ──────────────────────────
// When a request returns 401 the interceptor tries POST /api/auth/refresh once.
// If the refresh cookie is valid a new access token is issued, stored in memory,
// and the original request is retried transparently.
let _refreshing = false
let _waiters    = []

api.interceptors.response.use(
  r => r,
  async err => {
    const orig = err.config
    if (err.response?.status !== 401 || orig._retry) {
      return Promise.reject(err)
    }

    // Queue concurrent 401s while a refresh is in flight
    if (_refreshing) {
      return new Promise((resolve, reject) => _waiters.push({ resolve, reject }))
        .then(token => {
          orig.headers = { ...orig.headers, Authorization: `Bearer ${token}` }
          return api(orig)
        })
    }

    orig._retry  = true
    _refreshing  = true

    try {
      // Use base axios (no interceptors) to avoid infinite retry loop
      const { data } = await axios.post(
        `${BASE}/api/auth/refresh`,
        {},
        { withCredentials: true, timeout: API_TIMEOUT }
      )
      setToken(data.access_token)
      _waiters.forEach(w => w.resolve(data.access_token))
      _waiters = []
      orig.headers = { ...orig.headers, Authorization: `Bearer ${data.access_token}` }
      return api(orig)
    } catch {
      setToken(null)
      _waiters.forEach(w => w.reject())
      _waiters = []
      localStorage.removeItem('eta_user')
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login'
      }
      return Promise.reject(err)
    } finally {
      _refreshing = false
    }
  }
)

// ── Cached GET with in-flight deduplication ────────────────────────────────────
export const cachedGet = async (url, options = {}) => {
  const { cacheKey, ttl = CACHE_DURATION, ...params } = options
  const key = cacheKey || (url + (Object.keys(params).length ? JSON.stringify(params) : ''))

  pruneCache()

  const cached = cache.get(key)
  if (cached && Date.now() - cached.timestamp < ttl) return cached.data

  if (inflight.has(key)) return inflight.get(key)

  const promise = api.get(url, { params })
    .then(response => {
      cache.set(key, { data: response.data, timestamp: Date.now() })
      inflight.delete(key)
      return response.data
    })
    .catch(err => {
      inflight.delete(key)
      throw err
    })

  inflight.set(key, promise)
  return promise
}

export const clearCache = (pattern) => {
  if (pattern) {
    for (const key of cache.keys()) {
      if (key.includes(pattern)) cache.delete(key)
    }
  } else {
    cache.clear()
  }
}

export const analyzeEmail = (files, onProgress, isBatch = false) => {
  const fd = new FormData()
  if (isBatch) {
    files.forEach(f => fd.append('files', f))
  } else {
    fd.append('file', files)
  }
  return api.post(isBatch ? '/api/analyze-batch' : '/api/analyze-email', fd, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: e => onProgress?.(Math.round((e.loaded * 100) / e.total)),
    timeout: 180000,
  })
}

export const analyzeEmailText = data => api.post('/api/extension-scan', data, { timeout: 180000 })

export const getReport    = id   => api.get(`/api/reports/report/${id}`)
export const getHistory   = (p, l, v, search) => api.get('/api/history/scan-history', { params: { page:p, limit:l, ...(v ? { verdict: v } : {}), ...(search ? { search } : {}) }})
export const getFavourites  = () => api.get('/api/history/favourites')
export const addFavourite   = scanId => api.post(`/api/history/favourites/${scanId}`)
export const removeFavourite = scanId => api.delete(`/api/history/favourites/${scanId}`)
export const getStats     = ()   => api.get('/api/history/stats')

// Analytics
export const getScanTrends = (days) => api.get('/api/analytics/trends', { params: { days }})
export const getIOCStats = (limit) => api.get('/api/analytics/ioc-stats', { params: { limit }})
export const getRiskDistribution = () => api.get('/api/analytics/risk-distribution')
export const getTimeAnalysis = () => api.get('/api/analytics/time-analysis')

export const deleteScan   = id   => api.delete(`/api/history/scan/${id}`)
export const downloadJSON = id   => api.get(`/api/reports/report/${id}/json`, { responseType: 'blob' })
export const generatePDF  = id   => api.post(`/api/reports/report/${id}/pdf`, {}, { responseType: 'blob', timeout: 60000 })

export const getProfile = () => api.get('/api/auth/me')
export const updateProfile = body => api.patch('/api/auth/profile', body)

// Sessions
export const getSessions       = () => api.get('/api/auth/sessions')
export const revokeSession     = id => api.delete(`/api/auth/sessions/${id}`)
export const revokeAllSessions  = () => api.post('/api/auth/sessions/revoke-all')

export const checkAccountStatus = email => api.post('/api/auth/check-status', { email })

// 2FA
export const get2FAStatus      = () => api.get('/api/auth/2fa/status')
export const setup2FA          = () => api.post('/api/auth/2fa/setup')
export const enable2FA          = code => api.post('/api/auth/2fa/enable', { code })
export const disable2FA         = code => api.post('/api/auth/2fa/disable', { code })
export const getApiKeys = () => api.get('/api/settings/keys')
export const saveApiKeys = keys => api.post('/api/settings/keys', { keys })

// Scheduled reports
export const getScheduledReports = () => api.get('/api/reports/scheduled-reports')
export const createScheduledReport = data => api.post('/api/reports/scheduled-reports', data)
export const deleteScheduledReport = id => api.delete(`/api/reports/scheduled-reports/${id}`)

// Branding
export const getBranding = () => api.get('/api/reports/branding')
export const saveBranding = data => api.put('/api/reports/branding', data)

// Branded PDF
export const generateBrandedPDF = id => api.post(`/api/reports/report/${id}/pdf/branded`, {}, { responseType: 'blob', timeout: 60000 })

// Share link
export const createShareLink = (scanId, hours) => api.post(`/api/reports/share/${scanId}`, { hours })

// Exports
export const exportHistoryCSV = () => api.get('/api/reports/export/history', { params: { format: 'csv' }, responseType: 'blob' })
export const exportHistoryXLSX = () => api.get('/api/reports/export/history', { params: { format: 'xlsx' }, responseType: 'blob' })
export const exportAnalytics = () => api.get('/api/reports/export/analytics', { responseType: 'blob' })

// Admin
export const getAuditLogs = (page, limit, action) => api.get('/api/admin/audit-logs', { params: { page, limit, action: action || undefined }})
export const getAdminStats = () => api.get('/api/admin/admin-stats')
export const getAPIUsage = () => api.get('/api/admin/api-usage')
export const getAdminConfig = () => api.get('/api/admin/admin-config')
export const updateAdminConfig = (key, value) => api.put(`/api/admin/admin-config/${key}`, { value })
export const getHealth = () => api.get('/api/admin/health')

// Admin Dashboard
export const getDashboardActivity = (limit) => api.get('/api/admin/dashboard/recent-activity', { params: { limit }})
export const getDashboardUsers = (limit) => api.get('/api/admin/dashboard/recent-users', { params: { limit }})
export const getPendingUsers = () => api.get('/api/admin/dashboard/pending-users')
export const getDashboardTrends = (days) => api.get('/api/admin/dashboard/trends', { params: { days }})

// Admin Actions
export const approveUser = (userId) => api.post(`/api/admin/users/${userId}/approve`)
export const deleteUser = (userId) => api.delete(`/api/admin/users/${userId}`)
export const updateUserRole = (userId, role) => api.patch(`/api/admin/users/${userId}/role`, { role })
export const bulkDeleteScans = (olderThanDays, verdict) => api.delete('/api/admin/scans/bulk', { params: { older_than_days: olderThanDays, verdict: verdict || undefined }})
export const exportAdminData = (dataType, format) => api.get(`/api/admin/export/${dataType}`, { params: { format }})

// Dashboard widget order
export const getWidgetOrder = () => api.get('/api/settings/widget-order')
export const saveWidgetOrder = order => api.post('/api/settings/widget-order', { order })

// Privacy & Data
export const getPrivacySettings = () => api.get('/api/privacy/user/privacy-settings')
export const savePrivacySettings = ({ data_retention_days, allow_analytics, auto_delete, tier2_consent }) =>
  api.post('/api/privacy/user/privacy-settings', null, {
    params: { data_retention_days, allow_analytics, auto_delete, tier2_consent },
  })
export const triggerCleanup = () => api.post('/api/privacy/auto-cleanup')

// Notifications
export const getNotifications = () => api.get('/api/notifications')
export const getNotificationUnreadCount = () => api.get('/api/notifications/unread-count')
export const markAllNotificationsRead = () => api.post('/api/notifications/mark-read')
export const markNotificationRead = (id) => api.patch(`/api/notifications/${id}/read`)

// Chat (REST history)
export const getChatMessages = () => api.get('/api/chat/messages')
export const markChatRead = () => api.post('/api/chat/messages/read')
export const getAdminConversations = () => api.get('/api/chat/admin/conversations')
export const getAdminUserMessages = (userId) => api.get(`/api/chat/admin/messages/${userId}`)

// Build WebSocket URL for chat (strips /api prefix, uses ws:// scheme)
export const getChatWsUrl = (role) => {
  const base = (import.meta.env.VITE_API_URL || window.location.origin).replace(/^http/, 'ws')
  const token = getToken()
  return `${base}/api/chat/ws/${role}?token=${encodeURIComponent(token || '')}`
}

// IMAP accounts
export const getImapAccounts    = ()          => api.get('/api/imap/accounts')
export const addImapAccount     = data        => api.post('/api/imap/accounts', data)
export const deleteImapAccount  = id          => api.delete(`/api/imap/accounts/${id}`)
export const syncImapAccount    = id          => api.post(`/api/imap/accounts/${id}/sync`, {}, { timeout: 120000 })
export const syncAllImap        = ()          => api.post('/api/imap/sync-all', {}, { timeout: 120000 })
export const getImapFolders     = id          => api.get(`/api/imap/accounts/${id}/folders`)

export default api
