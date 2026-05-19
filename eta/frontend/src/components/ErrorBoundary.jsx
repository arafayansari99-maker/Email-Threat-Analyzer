import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children

    const { fallback } = this.props
    if (fallback) return fallback(this.state.error, () => this.setState({ error: null }))

    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', minHeight: '50vh', padding: '2rem', textAlign: 'center',
      }}>
        <div style={{
          background: 'var(--card)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 12, padding: '2rem', maxWidth: 480, width: '100%',
        }}>
          <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 0.75rem', color: '#EF4444', fontWeight: 700, fontSize: '1.25rem' }}>!</div>
          <h2 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Something went wrong
          </h2>
          <p style={{ color: 'var(--sub)', fontSize: '0.875rem', marginBottom: '1.25rem', lineHeight: 1.6 }}>
            {this.state.error?.message || 'An unexpected error occurred in this section.'}
          </p>
          <button
            onClick={() => this.setState({ error: null })}
            style={{
              padding: '0.625rem 1.25rem', borderRadius: 8, border: 'none',
              background: 'var(--cyan)', color: '#fff', cursor: 'pointer',
              fontSize: '0.875rem', fontWeight: 600,
            }}
          >
            Try again
          </button>
        </div>
      </div>
    )
  }
}
