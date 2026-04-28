import axios from 'axios'

// Use proxy in dev (empty = Vite handles routing), full URL when VITE_API_URL is set (production)
const BASE = import.meta.env.VITE_API_URL || ''

// Simple in-memory cache for API responses
const cache = new Map()
const CACHE_DURATION = 5 * 60 * 1000 // 5 minutes

// Request timeout - responsive within 2 seconds
const API_TIMEOUT = 2000 // ms - fast but reliable

// Clear expired cache entries periodically
setInterval(() => {
  const now = Date.now()
  for (const [key, value] of cache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      cache.delete(key)
    }
  }
}, 60000) // Check every minute

const api = axios.create({
  baseURL: BASE,
  timeout: API_TIMEOUT, // Stricter timeout for faster response
  // Don't set Content-Type for FormData - browser sets it with boundary
})

// Request interceptor
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('eta_token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

// Response interceptor with cache
api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('eta_token')
      localStorage.removeItem('eta_user')
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

// Cached GET request
export const cachedGet = async (url, options = {}) => {
  const { cacheKey, ttl = CACHE_DURATION, ...params } = options
  const key = cacheKey || url + JSON.stringify(params)

  const cached = cache.get(key)
  if (cached && Date.now() - cached.timestamp < ttl) {
    return cached.data
  }

  const response = await api.get(url, { params })
  cache.set(key, { data: response.data, timestamp: Date.now() })
  return response.data
}

// Clear specific cache
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

// Use /api/auth instead of /auth for all endpoints
export const getProfile = () => api.get('/api/auth/me')
export const updateProfile = body => api.patch('/api/auth/profile', body)

// Sessions
export const getSessions       = () => api.get('/api/auth/sessions')
export const revokeSession     = id => api.delete(`/api/auth/sessions/${id}`)
export const revokeAllSessions  = () => api.post('/api/auth/sessions/revoke-all')

// Account status check (no auth required)
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

export default api