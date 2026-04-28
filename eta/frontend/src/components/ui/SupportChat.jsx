import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../../hooks/useAuth'

const SUPPORT_TOPICS = [
  { id: 'technical', label: 'Technical Issue', icon: '🔧' },
  { id: 'bug', label: 'Bug Report', icon: '🐛' },
  { id: 'feature', label: 'Feature Request', icon: '💡' },
  { id: 'account', label: 'Account Help', icon: '👤' },
  { id: 'guide', label: 'User Guide', icon: '📖' },
  { id: 'other', label: 'Other', icon: '💬' },
]

const APP_GUIDE = [
  {
    title: 'Getting Started',
    icon: '🚀',
    content: `Welcome to ETA - Email Threat Analyzer! Here's how to get started:

1. Upload an email file (.eml, .msg) or paste email text
2. Click "Analyze" to scan for threats
3. View the detailed report with risk score
4. Add important scans to favorites`
  },
  {
    title: 'Understanding Results',
    icon: '📊',
    content: `The analyzer provides:

• Risk Score (0-100): Higher = more dangerous
• Verdict: Safe / Suspicious / Malicious
• Detected IOCs: URLs, links, attachments
• Threat indicators: Phishing, malware, BEC markers`
  },
  {
    title: 'Using Dashboard',
    icon: '📈',
    content: `Your dashboard shows:

• Overview stats (scans performed)
• Recent scan history
• Threat distribution charts
• Quick access to all features

Use "Customize" to reorder widgets!`
  },
  {
    title: 'Reports & Export',
    icon: '📄',
    content: `Generate detailed reports:

• PDF reports for stakeholders
• JSON for API integration
• Compare two scans side-by-side
• Share results via secure link`
  },
  {
    title: 'Batch Analysis',
    icon: '📦',
    content: `Analyze multiple emails at once:

• Upload up to 20 email files
• Get summary statistics
• Export results to CSV/Excel
• Identify campaign patterns`
  },
  {
    title: 'Security Tips',
    icon: '🛡️',
    content: `Best practices:

• Always verify sender addresses
• Check URLs before clicking
• Be wary of urgent requests
• Enable 2FA in Settings
• Review scan history regularly`
  },
]

export default function SupportChat({ onClose }) {
  const { user } = useAuth()
  const [step, setStep] = useState('menu') // menu, topic, chat, guide
  const [selectedTopic, setSelectedTopic] = useState(null)
  const [selectedGuide, setSelectedGuide] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Focus input when chat opens
  useEffect(() => {
    if (step === 'chat') {
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }, [step])

  const handleTopicSelect = (topic) => {
    if (topic.id === 'guide') {
      // Show guide list
      setSelectedTopic(topic)
      setStep('guide')
    } else {
      setSelectedTopic(topic)
      setMessages([{
        type: 'system',
        text: `You're now chatting with our support team about "${topic.label}". Describe your issue and we'll help you.`
      }])
      setStep('chat')
    }
  }

  const handleGuideSelect = (guide) => {
    setSelectedGuide(guide)
  }

  const handleBackToMenu = () => {
    setStep('menu')
    setSelectedTopic(null)
    setSelectedGuide(null)
    setMessages([])
    setInput('')
  }

  const handleBackFromGuide = () => {
    setStep('menu')
    setSelectedTopic(null)
    setSelectedGuide(null)
  }

  const handleSend = async () => {
    if (!input.trim() || sending) return

    const userMsg = { type: 'user', text: input.trim() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setSending(true)

    // Simulate response (in production, this would connect to backend)
    setTimeout(() => {
      setMessages(prev => [...prev, {
        type: 'support',
        text: 'Thank you for reaching out! Our team has received your message. A support ticket has been created and our team will respond within 24 hours. For urgent issues, please contact admin directly.'
      }])
      setSending(false)
    }, 1000)
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="support-chat-container">
      <div className="support-chat-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {(step === 'chat' || (step === 'guide' && selectedGuide)) && (
            <button
              onClick={() => {
                if (step === 'guide' && selectedGuide) {
                  handleBackFromGuide()
                } else {
                  handleBackToMenu()
                }
              }}
              className="support-back-btn-header"
              aria-label="Go back to menu"
              style={{
                background: 'none', border: 'none', color: 'white', cursor: 'pointer',
                padding: '0.25rem', marginRight: '0.25rem', fontSize: '1rem'
              }}
            >
              ←
            </button>
          )}
          <span style={{ fontSize: '1.25rem' }}>🛟</span>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text)' }}>Support</h3>
            <p style={{ margin: 0, fontSize: '0.6875rem', color: 'var(--green)' }}>Online • Response within 24h</p>
          </div>
        </div>
        <button onClick={onClose} className="support-chat-close" aria-label="Close support chat">
          ✕
        </button>
      </div>

      {step === 'menu' && (
        <div className="support-chat-menu">
          <p className="support-chat-intro">How can we help you today?</p>
          <div className="support-topic-grid">
            {SUPPORT_TOPICS.map(topic => (
              <button
                key={topic.id}
                className="support-topic-btn"
                onClick={() => handleTopicSelect(topic)}
              >
                <span className="support-topic-icon">{topic.icon}</span>
                <span>{topic.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 'topic' && (
        <div className="support-chat-topic">
          <button className="support-back-btn" onClick={() => setStep('menu')}>
            ← Back
          </button>
          <h4>Selected: {selectedTopic?.label}</h4>
          <button className="support-start-btn" onClick={() => setStep('chat')}>
            Start Chat
          </button>
        </div>
      )}

      {step === 'guide' && !selectedGuide && (
        <div className="support-chat-menu">
          <p className="support-chat-intro">Select a topic to learn more:</p>
          <div className="support-topic-grid">
            {APP_GUIDE.map((guide, idx) => (
              <button
                key={idx}
                className="support-topic-btn"
                onClick={() => handleGuideSelect(guide)}
              >
                <span className="support-topic-icon">{guide.icon}</span>
                <span>{guide.title}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 'guide' && selectedGuide && (
        <div className="support-guide-detail">
          <div className="support-guide-content">
            <h4 style={{ margin: '0 0 0.75rem', color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600 }}>
              {selectedGuide.icon} {selectedGuide.title}
            </h4>
            <pre style={{
              margin: 0, fontFamily: 'inherit', fontSize: '0.75rem', color: 'var(--text)',
              whiteSpace: 'pre-wrap', lineHeight: 1.5, background: 'var(--surface)',
              padding: '0.75rem', borderRadius: 8
            }}>
              {selectedGuide.content}
            </pre>
          </div>
        </div>
      )}

      {step === 'chat' && (
        <>
          <div className="support-chat-messages">
            {messages.map((msg, idx) => (
              <div key={idx} className={`support-message support-message-${msg.type}`}>
                <div className="support-message-content">
                  {msg.type === 'system' && <span style={{ fontSize: '0.625rem' }}>ℹ️</span>}
                  {msg.type === 'support' && <span style={{ fontSize: '0.625rem' }}>🛟</span>}
                  <p>{msg.text}</p>
                </div>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          <div className="support-chat-input">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Type your message..."
              disabled={sending}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || sending}
              className="support-send-btn"
            >
              {sending ? '...' : '➤'}
            </button>
          </div>
        </>
      )}

      <div className="support-chat-footer">
        <p>Logged in as: <strong>{user?.username}</strong></p>
        <p style={{ fontSize: '0.625rem', color: 'var(--sub)' }}>For immediate help, contact admin directly.</p>
      </div>
    </div>
  )
}