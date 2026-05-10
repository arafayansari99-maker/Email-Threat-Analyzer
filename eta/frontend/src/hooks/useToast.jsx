import { createContext, useContext, useState, useCallback, useRef } from 'react'

const ToastContext = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const counterRef = useRef(0)

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t))
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 280)
  }, [])

  const addToast = useCallback(({ title, message, type = 'info', duration = 5000 }) => {
    const id = ++counterRef.current
    setToasts(prev => [...prev, { id, title, message, type, exiting: false }])
    if (duration > 0) {
      setTimeout(() => dismiss(id), duration)
    }
    return id
  }, [dismiss])

  const success = useCallback((msg, title = 'Success') => addToast({ title, message: msg, type: 'success' }), [addToast])
  const error   = useCallback((msg, title = 'Error')     => addToast({ title, message: msg, type: 'error',   duration: 8000 }), [addToast])
  const info    = useCallback((msg, title = 'Info')      => addToast({ title, message: msg, type: 'info' }), [addToast])
  const warn    = useCallback((msg, title = 'Warning')   => addToast({ title, message: msg, type: 'warning', duration: 7000 }), [addToast])

  return (
    <ToastContext.Provider value={{ toasts, dismiss, addToast, success, error, info, warn }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)

const TOAST_ICONS = {
  success: '✓',
  error:   '✕',
  warning: '!',
  info:    'i',
}

function ToastContainer({ toasts, onDismiss }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast${t.exiting ? ' toast-exit' : ''}`}>
          <span className="toast-icon">{TOAST_ICONS[t.type] || 'i'}</span>
          <div className="toast-body">
            <p className="toast-title">{t.title}</p>
            {t.message && <p className="toast-msg">{t.message}</p>}
          </div>
          <button className="toast-close" onClick={() => onDismiss(t.id)} aria-label="Dismiss">×</button>
        </div>
      ))}
    </div>
  )
}