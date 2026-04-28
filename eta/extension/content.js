// content.js — Gmail injection
;(function(){
  'use strict'
  let lastId = null, scanning = false
  const ob = new MutationObserver(debounce(check, 900))
  ob.observe(document.body, { childList:true, subtree:true })

  chrome.runtime.onMessage.addListener((m,_,reply) => {
    if (m.action==='extract') reply(extract())
    if (m.action==='ping') reply({ok:true})
  })

  function check() {
    const id = window.location.href.match(/[#/]([a-f0-9]{16})/)?.[1]
    if (!id || id===lastId || scanning) return
    lastId = id; scan()
  }

  async function scan() {
    const d = extract(); if (!d || !d.subject) return
    scanning = true
    try {
      const t = await getToken()
      const API = await getAPI()
      const r = await fetch(`${API}/api/extension-scan`, {
        method:'POST', headers:{'Content-Type':'application/json',...(t?{Authorization:`Bearer ${t}`}:{})},
        body: JSON.stringify({ email_content:d.body||'', subject:d.subject||'', sender:d.sender||'', gmail_message_id:d.msgId })
      })
      if (r.ok) {
        const res = await r.json()
        badge(res)
        chrome.runtime.sendMessage({ action:'scanDone', result:res })
      }
    } catch {} finally { scanning=false }
  }

  function extract() {
    const q = sels => { for (const s of sels) { const e=document.querySelector(s); if (e) return e.innerText||e.textContent||'' } return '' }
    const subject = q(['h2.hP','.hP']) || document.title.replace(/ - Gmail$/,'')
    const sEl = document.querySelector('.gD[email]')
    const sender = sEl?.getAttribute('email') || sEl?.innerText || ''
    const body = q(['.a3s.aiL','.ii.gt .a3s','.gs .a3s'])
    const msgId = window.location.href.match(/[#/]([a-f0-9]{16})/)?.[1]
    return { subject, sender, body:body.slice(0,5000), msgId }
  }

  function badge(r) {
    document.getElementById('eta-badge')?.remove()
    const v = r.verdict||'safe'
    const C = { malicious:['rgba(239,68,68,.12)','rgba(239,68,68,.4)','#ef4444','⛔'],
                suspicious:['rgba(245,158,11,.12)','rgba(245,158,11,.4)','#f59e0b','⚠️'],
                safe:['rgba(16,185,129,.12)','rgba(16,185,129,.4)','#10b981','✓'] }[v]||['rgba(100,116,139,.12)','rgba(100,116,139,.4)','#888','?']
    const b = document.createElement('div')
    b.id='eta-badge'
    b.style.cssText=`position:fixed;top:72px;right:18px;z-index:9999;background:${C[0]};border:1px solid ${C[1]};
      border-radius:10px;padding:9px 12px;font-family:monospace;font-size:11px;color:${C[2]};cursor:pointer;
      box-shadow:0 4px 20px rgba(0,0,0,.3);backdrop-filter:blur(8px);min-width:150px`
    b.innerHTML=`<div style="display:flex;align-items:center;gap:7px;margin-bottom:3px">
      <span style="font-size:13px">${C[3]}</span>
      <span style="font-weight:700">${v.toUpperCase()}</span>
      <span style="margin-left:auto;font-size:15px;font-weight:700">${Math.round(r.risk_score||0)}</span>
    </div>
    <div style="font-size:8px;opacity:.7">${r.mal_url_count||0} malicious URLs · ${Math.round((r.phishing_prob||0)*100)}% phish</div>
    <span style="position:absolute;top:4px;right:7px;cursor:pointer;font-size:13px;opacity:.5" id="eta-close">×</span>`
    b.onclick = () => { const API=window.__etaAPI||'http://localhost:3000'; window.open(`${API}/report/${r.scan_id}`,'_blank') }
    document.getElementById('eta-close')?.remove()
    document.body.appendChild(b)
    document.getElementById('eta-close').onclick = e => { e.stopPropagation(); b.remove() }
    if (v==='safe') { setTimeout(()=>b.style.opacity='0',10000); setTimeout(()=>b.remove(),12000) }
  }

  function getToken() { return new Promise(r=>chrome.storage.local.get(['eta_token'],d=>r(d.eta_token||null))) }
  function getAPI()   { return new Promise(r=>chrome.storage.local.get(['api_url'],d=>r(d.api_url||'http://127.0.0.1:8001'))) }
  function debounce(fn,ms) { let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a),ms) } }
})()
