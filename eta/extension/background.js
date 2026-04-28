// background.js - Service worker for ETA Extension

// Track scan statistics
let scanStats = {
  total: 0,
  malicious: 0,
  suspicious: 0,
  safe: 0,
  recentScans: []
}

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    chrome.action.setBadgeBackgroundColor({ color: '#06B6D4' })
  }
})

// Handle messages from content.js and popup.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'scanDone') {
    updateBadge(msg.result)
    sendNotification(msg.result)
    updateStats(msg.result)
  }
  if (msg.action === 'setToken') {
    chrome.storage.local.set({ eta_token: msg.token })
    sendResponse({ ok: true })
  }
  if (msg.action === 'setAPI') {
    chrome.storage.local.set({ api_url: msg.url })
    sendResponse({ ok: true })
  }
  if (msg.action === 'getToken') {
    chrome.storage.local.get(['eta_token'], (result) => {
      sendResponse({ token: result.eta_token })
    })
    return true // async response
  }
  if (msg.action === 'getStats') {
    sendResponse(scanStats)
  }
  if (msg.action === 'getRecentScans') {
    sendResponse({ scans: scanStats.recentScans })
  }
  if (msg.action === 'clearStats') {
    scanStats = { total: 0, malicious: 0, suspicious: 0, safe: 0, recentScans: [] }
    chrome.storage.local.set({ eta_scan_stats: scanStats })
    sendResponse({ ok: true })
  }
  if (msg.action === 'generateReport') {
    generatePDFReport(msg.scanId)
    sendResponse({ ok: true })
  }
  return true
})

function updateBadge(r) {
  const v = r?.verdict
  const cfg = {
    malicious:  { text: '!!', color: '#EF4444' },
    suspicious: { text: `${Math.round(r?.risk_score||0)}`, color: '#F59E0B' },
    safe:       { text: '✓',  color: '#10B981' },
  }[v] || { text: '?', color: '#64748B' }

  chrome.action.setBadgeText({ text: cfg.text })
  chrome.action.setBadgeBackgroundColor({ color: cfg.color })

  // Clear badge after 60 seconds
  setTimeout(() => {
    chrome.action.setBadgeText({ text: '' })
  }, 60000)
}

function sendNotification(r) {
  const v = r?.verdict || 'safe'
  const score = Math.round(r?.risk_score || 0)

  // Only notify for threats
  if (v === 'safe') return

  const title = v === 'malicious'
    ? '⚠️ MALICIOUS Email Detected!'
    : '⚠️ Suspicious Email Detected'

  const message = `Risk Score: ${score}% | ${r.mal_url_count || 0} malicious URLs | From: ${r.sender || 'Unknown'}`

  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icon128.png',
    title: title,
    message: message,
    priority: v === 'malicious' ? 2 : 1
  })
}

function updateStats(r) {
  const v = r?.verdict || 'safe'
  scanStats.total++
  if (v === 'malicious') scanStats.malicious++
  else if (v === 'suspicious') scanStats.suspicious++
  else scanStats.safe++

  // Keep last 50 scans
  scanStats.recentScans.unshift({
    scan_id: r.scan_id,
    verdict: v,
    risk_score: Math.round(r.risk_score || 0),
    sender: r.sender,
    subject: r.subject,
    timestamp: Date.now()
  })

  if (scanStats.recentScans.length > 50) {
    scanStats.recentScans = scanStats.recentScans.slice(0, 50)
  }

  // Persist stats
  chrome.storage.local.set({ eta_scan_stats: scanStats })
}

async function generatePDFReport(scanId) {
  // This would need to be handled by the popup to trigger the API
  chrome.runtime.sendMessage({ action: 'generatePDF', scanId: scanId })
}

// Load stats from storage on startup
chrome.storage.local.get(['eta_scan_stats'], (result) => {
  if (result.eta_scan_stats) {
    scanStats = result.eta_scan_stats
  }
})

// Keep service worker alive - wake every minute
chrome.alarms.create('keepAlive', { periodInMinutes: 1 })
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    chrome.storage.local.get(['eta_token'], () => {})
  }
})