import { useState, useRef, useEffect, useCallback } from 'react'
import { useAuth } from '../../hooks/useAuth'
import { getChatWsUrl, getChatMessages, markChatRead } from '../../services/api'

const SUPPORT_TOPICS = [
  { id: 'technical', label: 'Technical Issue' },
  { id: 'bug',       label: 'Bug Report' },
  { id: 'feature',   label: 'Feature Request' },
  { id: 'account',   label: 'Account Help' },
  { id: 'guide',     label: 'User Guide' },
  { id: 'other',     label: 'Other' },
]

const APP_GUIDE = [
  { title: 'Getting Started', content: `1. Upload an email file (.eml, .msg) or paste email text\n2. Click "Analyze" to scan for threats\n3. View the detailed report with risk score\n4. Add important scans to favorites` },
  { title: 'Understanding Results', content: `• Risk Score (0-100): Higher = more dangerous\n• Verdict: Safe / Suspicious / Malicious\n• Detected IOCs: URLs, links, attachments\n• Threat indicators: Phishing, malware, BEC markers` },
  { title: 'Using Dashboard', content: `• Overview stats (scans performed)\n• Recent scan history\n• Threat distribution charts\n• Quick access to all features\n\nUse "Customize" to reorder widgets!` },
  { title: 'Reports & Export', content: `• PDF reports for stakeholders\n• JSON for API integration\n• Compare two scans side-by-side\n• Share results via secure link` },
  { title: 'Security Tips', content: `• Always verify sender addresses\n• Check URLs before clicking\n• Be wary of urgent requests\n• Enable 2FA in Settings\n• Review scan history regularly` },
]

const WS_RECONNECT_DELAY = 3000

function UploadBar({ imageInputRef, imagePreview, setImagePreview, onSelect }) {
  return (
    <div style={{ marginTop: '0.75rem', padding: '0.625rem 0.75rem', borderRadius: 10, border: '1px dashed var(--border)', display: 'flex', alignItems: 'center', gap: '0.625rem', background: 'var(--surface)' }}>
      <input type="file" ref={imageInputRef} accept="image/*" style={{ display: 'none' }} onChange={onSelect} />
      <button
        onClick={() => imageInputRef.current?.click()}
        style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', background: 'none', border: 'none', color: 'var(--sub)', cursor: 'pointer', fontSize: '0.75rem', padding: 0 }}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/>
          <polyline points="21 15 16 10 5 21"/>
        </svg>
        Attach screenshot
      </button>
      {imagePreview && (
        <>
          <img src={imagePreview} alt="preview" style={{ width: 36, height: 36, objectFit: 'cover', borderRadius: 6, border: '1px solid var(--border)' }} />
          <button onClick={() => setImagePreview(null)} style={{ background: 'none', border: 'none', color: 'var(--sub)', cursor: 'pointer', fontSize: '0.875rem', padding: 0, marginLeft: 'auto' }}>✕</button>
        </>
      )}
    </div>
  )
}

export default function SupportChat({ onClose }) {
  const { user } = useAuth()
  const [step, setStep] = useState('menu')
  const [selectedTopic, setSelectedTopic] = useState(null)
  const [selectedGuide, setSelectedGuide] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [adminOnline, setAdminOnline] = useState(false)
  const [wsReady, setWsReady] = useState(false)
  const [imagePreview, setImagePreview] = useState(null)
  const wsRef = useRef(null)
  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)
  const imageInputRef = useRef(null)
  const reconnectTimer = useRef(null)
  const mountedRef = useRef(true)

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    if (step === 'chat') setTimeout(() => inputRef.current?.focus(), 100)
  }, [step])

  // Load chat history when entering chat step
  const loadHistory = useCallback(async () => {
    try {
      const { data } = await getChatMessages()
      if (data?.length) {
        setMessages(data.map(m => ({
          type: m.sender_role === 'user' ? 'user' : m.sender_role === 'admin' ? 'support' : 'system',
          text: m.message,
          id: m.id,
          time: m.created_at,
        })))
      }
      await markChatRead()
    } catch {}
  }, [])

  // Connect WebSocket when entering chat
  const connectWS = useCallback(() => {
    if (!mountedRef.current) return
    const url = getChatWsUrl('user')
    // Retry if token is absent (URL ends with "token=" and nothing after)
    if (url.endsWith('token=')) {
      reconnectTimer.current = setTimeout(connectWS, 1000)
      return
    }

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => { if (mountedRef.current) setWsReady(true) }

    ws.onmessage = (e) => {
      if (!mountedRef.current) return
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'status') {
          setAdminOnline(data.admin_online)
        } else if (data.type === 'message' && data.sender_role === 'admin') {
          setMessages(prev => [...prev, {
            type: 'support',
            text: data.message,
            id: data.id,
            time: data.created_at,
            name: data.sender_name,
          }])
        }
      } catch {}
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      setWsReady(false)
      reconnectTimer.current = setTimeout(connectWS, WS_RECONNECT_DELAY)
    }

    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    mountedRef.current = true
    if (step === 'chat') {
      loadHistory()
      connectWS()
    }
    return () => {
      if (step === 'chat') {
        mountedRef.current = false
        clearTimeout(reconnectTimer.current)
        wsRef.current?.close()
      }
    }
  }, [step])

  const handleTopicSelect = (topic) => {
    if (topic.id === 'guide') {
      setSelectedTopic(topic)
      setStep('guide')
    } else {
      setSelectedTopic(topic)
      setMessages([{ type: 'system', text: `You're chatting about "${topic.label}". Describe your issue and we'll help you.` }])
      setStep('chat')
    }
  }

  const handleBackToMenu = () => {
    setStep('menu')
    setSelectedTopic(null)
    setSelectedGuide(null)
    setMessages([])
    setInput('')
    setImagePreview(null)
    mountedRef.current = false
    clearTimeout(reconnectTimer.current)
    wsRef.current?.close()
    mountedRef.current = true
  }

  const handleImageSelect = (e) => {
    const file = e.target.files?.[0]
    if (!file || !file.type.startsWith('image/')) return
    const reader = new FileReader()
    reader.onload = (ev) => setImagePreview(ev.target.result)
    reader.readAsDataURL(file)
    if (imageInputRef.current) imageInputRef.current.value = ''
  }

  const handleSend = () => {
    if (!input.trim() && !imagePreview || sending) return
    const text = input.trim()
    const topic = selectedTopic?.id || 'general'

    setMessages(prev => [...prev, {
      type: 'user', text: text || null, image: imagePreview || null, time: new Date().toISOString(),
    }])
    setInput('')
    setImagePreview(null)
    setSending(true)

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ message: text || '[Image]', topic }))
    }
    setSending(false)
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
  }

  const formatTime = (iso) => {
    if (!iso) return ''
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  return (
    <div className="support-chat-container">
      {/* Header */}
      <div className="support-chat-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {(step === 'chat' || (step === 'guide' && selectedGuide)) && (
            <button onClick={step === 'guide' && selectedGuide ? () => setSelectedGuide(null) : handleBackToMenu}
              style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer', padding: '0.25rem', fontSize: '1rem' }}>←</button>
          )}
          <div>
            <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text)' }}>Support</h3>
            <p style={{ margin: 0, fontSize: '0.6875rem', color: adminOnline ? 'var(--green)' : 'var(--sub)' }}>
              {adminOnline ? '● Admin online' : '○ We\'ll reply soon'}
            </p>
          </div>
        </div>
        <button onClick={onClose} className="support-chat-close" aria-label="Close support chat">✕</button>
      </div>

      {/* Menu */}
      {step === 'menu' && (
        <div className="support-chat-menu">
          <p className="support-chat-intro">How can we help you today?</p>
          <div className="support-topic-grid">
            {SUPPORT_TOPICS.map(topic => (
              <button key={topic.id} className="support-topic-btn" onClick={() => handleTopicSelect(topic)}>
                <span>{topic.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Guide list */}
      {step === 'guide' && !selectedGuide && (
        <div className="support-chat-menu">
          <p className="support-chat-intro">Select a topic to learn more:</p>
          <div className="support-topic-grid">
            {APP_GUIDE.map((guide, idx) => (
              <button key={idx} className="support-topic-btn" onClick={() => setSelectedGuide(guide)}>
                <span>{guide.title}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Guide detail */}
      {step === 'guide' && selectedGuide && (
        <div className="support-guide-detail">
          <div className="support-guide-content">
            <h4 style={{ margin: '0 0 0.75rem', color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>
              {selectedGuide.title}
            </h4>
            <pre style={{ margin: 0, fontFamily: 'inherit', fontSize: '0.75rem', color: 'var(--text)', whiteSpace: 'pre-wrap', lineHeight: 1.5, background: 'var(--surface)', padding: '0.75rem', borderRadius: 8 }}>
              {selectedGuide.content}
            </pre>
          </div>
        </div>
      )}

      {/* Chat */}
      {step === 'chat' && (
        <>
          <div className="support-chat-messages">
            {messages.map((msg, idx) => (
              <div key={idx} className={`support-message support-message-${msg.type}`}>
                <div className="support-message-content">
                  <div>
                    {msg.text && <p style={{ margin: 0 }}>{msg.text}</p>}
                    {msg.image && (
                      <img
                        src={msg.image}
                        alt="attachment"
                        style={{ maxWidth: '100%', maxHeight: 180, borderRadius: 8, marginTop: msg.text ? 6 : 0, display: 'block' }}
                      />
                    )}
                    {msg.time && <p style={{ margin: '2px 0 0', fontSize: '0.6rem', opacity: 0.6 }}>{formatTime(msg.time)}</p>}
                  </div>
                </div>
              </div>
            ))}
            {!wsReady && step === 'chat' && (
              <div style={{ textAlign: 'center', padding: '0.5rem', fontSize: '0.7rem', color: 'var(--sub)' }}>
                Connecting…
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Image preview strip */}
          {imagePreview && (
            <div className="support-image-preview">
              <img src={imagePreview} alt="preview" />
              <span style={{ fontSize: '0.75rem', color: 'var(--sub)', flex: 1 }}>Image ready to send</span>
              <button onClick={() => setImagePreview(null)} title="Remove image">✕</button>
            </div>
          )}

          <div className="support-chat-input">
            <input
              type="file"
              ref={imageInputRef}
              accept="image/*"
              style={{ display: 'none' }}
              onChange={handleImageSelect}
            />
            <button
              className="support-upload-btn"
              onClick={() => imageInputRef.current?.click()}
              title="Upload image"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/>
                <polyline points="21 15 16 10 5 21"/>
              </svg>
            </button>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Type your message…"
              disabled={sending}
            />
            <button onClick={handleSend} disabled={(!input.trim() && !imagePreview) || sending} className="support-send-btn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M2 21l21-9L2 3v7l15 2-15 2z"/>
              </svg>
            </button>
          </div>
        </>
      )}

      <div className="support-chat-footer">
        <p>Logged in as: <strong>{user?.username}</strong></p>
        <p style={{ fontSize: '0.625rem', color: 'var(--sub)' }}>Messages are delivered in real-time when admin is online.</p>
      </div>
    </div>
  )
}
