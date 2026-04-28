// popup.js - Enhanced with login flow, stats, PDF report
const show = id => ['idle','loading','result','errState','stats'].forEach(s =>
  document.getElementById(s).style.display = s===id?'block':'none')

const STAGES = ['Extracting content...','Analyzing headers...','Checking URLs...','ML scoring...','Building report...']

let API = 'http://127.0.0.1:8001'
let WEB_URL = 'http://localhost:3000'
let scanStats = { total: 0, malicious: 0, suspicious: 0, safe: 0, recentScans: [] }
let settings = { notifications: true }

chrome.storage.local.get(['api_url'], r => {
  if (r.api_url) {
    API = r.api_url
    WEB_URL = API.replace('/api','')
  }
})

// Load stats on init
chrome.storage.local.get(['eta_scan_stats', 'eta_settings'], r => {
  if (r.eta_scan_stats) scanStats = r.eta_scan_stats
  if (r.eta_settings) settings = r.eta_settings
})

document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('scanBtn').onclick = startScan
  document.getElementById('retryBtn').onclick = startScan
  document.getElementById('setLink').onclick = () => chrome.tabs.create({ url: WEB_URL })
  document.getElementById('statsBtn').onclick = showStats
  document.getElementById('pdfBtn').onclick = generatePDF
  document.getElementById('clearBtn').onclick = clearStats
  document.getElementById('notifToggle').onchange = toggleNotifications
  document.getElementById('backBtn').onclick = () => show('idle')

  // Update notification toggle
  document.getElementById('notifToggle').checked = settings.notifications

  const cached = await getCached()
  if (cached) render(cached)
})

async function startScan() {
  show('loading')
  let si = 0
  const iv = setInterval(() => {
    document.getElementById('stage').textContent = STAGES[Math.min(si++, STAGES.length-1)]
  }, 700)

  try {
    const [tab] = await chrome.tabs.query({ active:true, currentWindow:true })
    if (!tab?.url?.includes('mail.google.com'))
      throw new Error('Please open a Gmail email first')

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractGmail,
    })
    const data = results[0]?.result
    if (!data) throw new Error('No email found. Open an email in Gmail and retry.')

    const token = await getToken()
    const res = await fetch(`${API}/api/extension-scan`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
      body: JSON.stringify({
        email_content: data.body || '',
        subject: data.subject || '',
        sender: data.sender || '',
        gmail_message_id: data.msgId,
      })
    })

    if (res.status === 401) {
      chrome.storage.local.removeItem('eta_token')
      clearInterval(iv)
      const result = await res.json()
      chrome.storage.local.set({ lastResult:result, lastResultTime:Date.now() })
      renderWithLoginPrompt(result)
      return
    }

    if (!res.ok) {
      const e = await res.json().catch(() => ({}))
      throw new Error(e.detail || `Server error ${res.status}`)
    }

    const result = await res.json()
    clearInterval(iv)
    chrome.storage.local.set({ lastResult:result, lastResultTime:Date.now() })
    render(result)
  } catch(e) {
    clearInterval(iv)
    document.getElementById('errMsg').textContent = e.message || 'Unknown error'
    show('errState')
  }
}

function render(r) {
  show('result')
  const v = r.verdict || 'safe'
  const score = Math.round(r.risk_score || 0)
  const cfg = {
    malicious:  { cls:'ban-mal', col:'#ef4444', em:'&#x26D4;' },
    suspicious: { cls:'ban-sus', col:'#f59e0b', em:'&#x26A0;' },
    safe:       { cls:'ban-safe', col:'#10b981', em:'&#x2713;' },
  }[v] || { cls:'ban-safe', col:'#10b981', em:'?' }

  const auth = r.auth || {}
  const abadge = (l, val) => {
    const cls = val==='pass'?'apass':val==='fail'?'afail':'aunk'
    return `<div class="abadge ${cls}"><div>${l}</div><div>${(val||'N/A').toUpperCase()}</div></div>`
  }

  const urls = (r.malicious_urls||[]).slice(0,3)
    .map(u=>`<div class="url-i">${u.slice(0,60)}${u.length>60?'...':''}</div>`).join('')||
    '<div class="no-data">No malicious URLs detected</div>'

  const inds = (r.indicators||[]).slice(0,4)
    .map(i=>`<div class="ind-i"><span class="sev-${(i.severity||'l')[0]}">[${(i.severity||'info').toUpperCase()}]</span> ${(i.desc||'').slice(0,50)}</div>`)
    .join('')||'<div class="no-data">No significant indicators found</div>'

  document.getElementById('result').innerHTML = `
    <div class="result">
      <div class="banner ${cfg.cls}">
        <div class="score-c" style="color:${cfg.col};border-color:${cfg.col}">${score}</div>
        <div style="color:${cfg.col}">
          <div class="vl">${cfg.em} ${v.toUpperCase()}</div>
          <div class="vs">${Math.round((r.phishing_prob||0)*100)}% phishing probability</div>
          <div class="vs">${r.mal_url_count||0} malicious URLs found</div>
          <div class="vs">Scan time: ${(r.duration||0).toFixed(2)}s</div>
        </div>
      </div>
      <div class="sec"><div class="sec-h">Email Authentication</div><div class="sec-b">
        <div class="auth-row">${abadge('SPF',auth.spf)}${abadge('DKIM',auth.dkim)}${abadge('DMARC',auth.dmarc)}</div>
      </div></div>
      <div class="sec"><div class="sec-h">Detected Malicious URLs (${r.mal_url_count||0})</div>
        <div class="sec-b">${urls}</div></div>
      <div class="sec"><div class="sec-h">Risk Indicators</div>
        <div class="sec-b">${inds}</div></div>
      <div class="act-row">
        <button class="act-btn btn-p" id="dashBtn">View Full Report</button>
        <button class="act-btn btn-p" id="pdfBtn">PDF Report</button>
        <button class="act-btn btn-s" id="rescanBtn">Rescan</button>
      </div>
    </div>`

  document.getElementById('dashBtn').onclick = () => openFullReport(r.scan_id)
  document.getElementById('pdfBtn').onclick = () => downloadPDF(r.scan_id)
  document.getElementById('rescanBtn').onclick = startScan
}

function renderWithLoginPrompt(r) {
  show('result')
  const v = r.verdict || 'safe'
  const score = Math.round(r.risk_score || 0)
  const cfg = {
    malicious:  { cls:'ban-mal', col:'#ef4444', em:'&#x26D4;' },
    suspicious: { cls:'ban-sus', col:'#f59e0b', em:'&#x26A0;' },
    safe:       { cls:'ban-safe', col:'#10b981', em:'&#x2713;' },
  }[v] || { cls:'ban-safe', col:'#10b981', em:'?' }

  const urls = (r.malicious_urls||[]).slice(0,3)
    .map(u=>`<div class="url-i">${u.slice(0,60)}${u.length>60?'...':''}</div>`).join('')||
    '<div class="no-data">No malicious URLs detected</div>'

  document.getElementById('result').innerHTML = `
    <div class="result">
      <div class="banner ${cfg.cls}">
        <div class="score-c" style="color:${cfg.col};border-color:${cfg.col}">${score}</div>
        <div style="color:${cfg.col}">
          <div class="vl">${cfg.em} ${v.toUpperCase()}</div>
          <div class="vs">${Math.round((r.phishing_prob||0)*100)}% phishing probability</div>
          <div class="vs">${r.mal_url_count||0} malicious URLs found</div>
        </div>
      </div>
      <div class="sec"><div class="sec-h">Detected Malicious URLs</div>
        <div class="sec-b">${urls}</div></div>
      <div class="sec" style="border-color:rgba(6,182,212,0.3);background:rgba(6,182,212,0.05)">
        <div class="sec-h" style="color:#06B6D4">Login Required</div>
        <div class="sec-b">
          <div class="no-data" style="font-size:11px;line-height:1.6;padding:8px;">
            To view the full report with all details, please log in or register.
            <br><br>
            <strong>New users:</strong> Account requires admin approval.
          </div>
        </div>
      </div>
      <div class="act-row">
        <button class="act-btn btn-p" id="dashBtn">Login / Register</button>
        <button class="act-btn btn-s" id="rescanBtn">Rescan</button>
      </div>
    </div>`

  document.getElementById('dashBtn').onclick = () => openLoginAndRedirect(r.scan_id)
  document.getElementById('rescanBtn').onclick = startScan
}

function showStats() {
  show('stats')

  const pct = (val) => scanStats.total > 0 ? Math.round(val/scanStats.total*100) : 0

  document.getElementById('statsContent').innerHTML = `
    <div class="stats-summary">
      <div class="stats-card total">
        <div class="stats-num">${scanStats.total}</div>
        <div class="stats-label">Total Scans</div>
      </div>
      <div class="stats-card malicious">
        <div class="stats-num">${scanStats.malicious}</div>
        <div class="stats-label">Malicious (${pct(scanStats.malicious)}%)</div>
      </div>
      <div class="stats-card suspicious">
        <div class="stats-num">${scanStats.suspicious}</div>
        <div class="stats-label">Suspicious (${pct(scanStats.suspicious)}%)</div>
      </div>
      <div class="stats-card safe">
        <div class="stats-num">${scanStats.safe}</div>
        <div class="stats-label">Safe (${pct(scanStats.safe)}%)</div>
      </div>
    </div>
    <div class="stats-settings">
      <label class="toggle-label">
        <input type="checkbox" id="notifToggle" ${settings.notifications?'checked':''}>
        <span>Enable threat notifications</span>
      </label>
    </div>
  `
}

function toggleNotifications(e) {
  settings.notifications = e.target.checked
  chrome.storage.local.set({ eta_settings: settings })
}

function clearStats() {
  scanStats = { total: 0, malicious: 0, suspicious: 0, safe: 0, recentScans: [] }
  chrome.storage.local.set({ eta_scan_stats: scanStats })
  showStats()
}

async function openFullReport(scanId) {
  const token = await getToken()
  if (token) {
    chrome.tabs.create({ url: `${WEB_URL}/report/${scanId}` })
  } else {
    openLoginAndRedirect(scanId)
  }
}

async function downloadPDF(scanId) {
  try {
    const token = await getToken()
    if (!token) {
      openLoginAndRedirect(scanId)
      return
    }

    const res = await fetch(`${API}/api/reports/report/${scanId}/pdf`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
    })

    if (res.ok) {
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      chrome.tabs.create({ url: url })
    }
  } catch(e) {
    document.getElementById('errMsg').textContent = 'Failed to generate PDF'
    show('errState')
  }
}

function openLoginAndRedirect(scanId) {
  chrome.storage.local.set({ redirect_after_login: scanId })
  chrome.tabs.create({ url: `${WEB_URL}/login` })
}

async function generatePDF() {
  const cached = await getCached()
  if (cached) {
    await downloadPDF(cached.scan_id)
  }
}

async function getCached() {
  return new Promise(res => chrome.storage.local.get(['lastResult','lastResultTime'], d => {
    const age = Date.now() - (d.lastResultTime||0)
    res(d.lastResult && age < 5*60*1000 ? d.lastResult : null)
  }))
}

async function getToken() {
  return new Promise(res => chrome.storage.local.get(['eta_token'], d => res(d.eta_token||null)))
}

function extractGmail() {
  try {
    const tryQ = sels => { for (const s of sels) { const e=document.querySelector(s); if (e) return e.innerText||e.textContent||e.getAttribute('email')||'' } return '' }
    const subject = tryQ(['h2.hP','.hP','[data-thread-perm-id]']) || document.title.replace(/ - Gmail$/,'')
    const senderEl = document.querySelector('.gD[email]') || document.querySelector('[data-hovercard-id]')
    const sender = senderEl?.getAttribute('email') || senderEl?.innerText || ''
    const body = tryQ(['.a3s.aiL','.ii.gt .a3s','.gs .a3s'])
    const msgId = window.location.href.match(/[#/]([a-f0-9]{16})/)?.[1]
    if (!subject && !sender && !body) return null
    return { subject, sender, body: body.slice(0,5000), msgId }
  } catch { return null }
}