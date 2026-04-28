import { useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'

const SHORTCUTS = [
  { key: 'k',   ctrl: true,  label: 'Ctrl+K',    desc: 'Quick Search' },
  { key: 'Enter', ctrl: true, label: 'Ctrl+Enter', desc: 'Analyze' },
  { key: 'e',   ctrl: false, label: 'E',          desc: 'Export Report' },
  { key: '/',   ctrl: false, label: '/',           desc: 'Focus Search' },
]

export function useKeyboardShortcuts({ onSearch, onAnalyze, onExport }) {
  const navigate = useNavigate()

  useEffect(() => {
    const handler = (e) => {
      const ctrl = e.ctrlKey || e.metaKey

      if (ctrl && e.key === 'k') {
        e.preventDefault()
        onSearch?.()
      }

      if (ctrl && e.key === 'Enter') {
        e.preventDefault()
        onAnalyze?.()
      }

      if (!ctrl && e.key && e.key.toLowerCase() === 'e' && !['INPUT','TEXTAREA','SELECT'].includes(e.target?.tagName)) {
        const path = window.location.pathname
        if (path.startsWith('/reports')) {
          e.preventDefault()
          onExport?.()
        }
      }

      if (e.key === '/' && !['INPUT','TEXTAREA'].includes(e.target.tagName)) {
        e.preventDefault()
        onSearch?.()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onSearch, onAnalyze, onExport])

  return SHORTCUTS
}

export { SHORTCUTS }