// Shared UI primitives

// ── Verdict colour helpers — single source of truth used by all pages ─────────
const VERDICT_COLOR  = { malicious: 'var(--red)', suspicious: 'var(--amber)', safe: '#10B981' }
const VERDICT_BG     = { malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }
export const verdictColor  = v => VERDICT_COLOR[v]  || '#64748B'
export const verdictBgColor = v => VERDICT_BG[v]    || 'rgba(100,116,139,0.15)'

export function VerdictBadge({ verdict, size = 'sm' }) {
  const cfg = {
    malicious:  'text-red-400 bg-red-500/10 border-red-500/30',
    suspicious: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    safe:       'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  }
  const sz = size === 'lg' ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-xs'
  return (
    <span className={`rounded border font-mono font-bold uppercase ${sz} ${cfg[verdict] || 'text-gray-500 bg-gray-800 border-gray-700'}`}>
      {verdict || 'unknown'}
    </span>
  )
}

export function ScoreRing({ score, size = 100 }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981'
  const r = (size / 2) - 8
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - Math.min(score, 100) / 100)
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1E2D40" strokeWidth={size > 80 ? 8 : 6}/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color}
        strokeWidth={size > 80 ? 8 : 6} strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transform:`rotate(-90deg)`, transformOrigin:`${size/2}px ${size/2}px`, transition:'stroke-dashoffset 1s ease' }}/>
      <text x={size/2} y={size/2} textAnchor="middle" dominantBaseline="central"
        fill={color} style={{ fontSize: size > 80 ? 18 : 13, fontFamily:'Share Tech Mono,monospace', fontWeight:700 }}>
        {Math.round(score)}
      </text>
    </svg>
  )
}

export function Spinner({ size = 24, color = '#06B6D4' }) {
  return (
    <div style={{ width: size, height: size, borderRadius: '50%',
      border: `2px solid rgba(30,45,64,0.8)`, borderTopColor: color,
      animation: 'spin 0.7s linear infinite', flexShrink: 0 }}/>
  )
}

export function AuthBadge({ label, value }) {
  const cfg = {
    pass:     'text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
    fail:     'text-red-400 bg-red-500/10 border-red-500/25',
    softfail: 'text-amber-400 bg-amber-500/10 border-amber-500/25',
  }
  const cls = cfg[value?.toLowerCase()] || 'text-gray-500 bg-gray-800/50 border-gray-700'
  return (
    <div className="flex flex-col items-center gap-1 flex-1">
      <span className="text-[10px] uppercase tracking-widest mono" style={{color:'var(--sub)'}}>{label}</span>
      <span className={`px-2 py-1 rounded border mono text-xs font-bold ${cls}`}>
        {value?.toUpperCase() || 'N/A'}
      </span>
    </div>
  )
}

export function KPICard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className="card p-4 flex flex-col gap-2 hover:border-gray-700 transition-colors">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-widest font-medium" style={{color:'var(--sub)'}}>{label}</span>
        {Icon && <Icon size={15} style={{color}}/>}
      </div>
      <div className="mono text-3xl font-bold" style={{color}}>{value}</div>
      {sub && <div className="text-xs" style={{color:'var(--sub)'}}>{sub}</div>}
    </div>
  )
}

export function Section({ title, children, action }) {
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b" style={{borderColor:'var(--border)'}}>
        <h3 className="mono text-[11px] uppercase tracking-widest font-bold" style={{color:'var(--sub)'}}>{title}</h3>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

export function Empty({ message, cta }) {
  return (
    <div className="flex flex-col items-center gap-3 py-14 text-center px-4">
      <div className="w-12 h-12 rounded-full flex items-center justify-center"
           style={{background:'var(--muted)'}}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{color:'var(--sub)'}}>
          <path d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-8 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4z"/>
        </svg>
      </div>
      <p className="text-sm" style={{color:'var(--sub)'}}>{message}</p>
      {cta}
    </div>
  )
}

export function ErrorBanner({ message }) {
  if (!message) return null
  return (
    <div className="p-3 rounded-xl text-sm text-red-400 flex items-start gap-2"
         style={{background:'rgba(239,68,68,0.08)',border:'1px solid rgba(239,68,68,0.25)'}}>
      <span className="flex-shrink-0 mt-0.5" style={{fontWeight:700}}>!</span>
      <span>{message}</span>
    </div>
  )
}

export function Skeleton({ className = '' }) {
  return <div className={`shimmer rounded-lg ${className}`}/>
}

export function IOCTypePill({ type }) {
  const cfg = {
    url:    'bg-blue-500/10 text-blue-400 border-blue-500/25',
    domain: 'bg-purple-500/10 text-purple-400 border-purple-500/25',
    ip:     'bg-orange-500/10 text-orange-400 border-orange-500/25',
    hash:   'bg-pink-500/10 text-pink-400 border-pink-500/25',
  }
  return (
    <span className={`px-1.5 py-0.5 rounded border mono text-[10px] font-bold uppercase flex-shrink-0 ${cfg[type]||'bg-gray-800 text-gray-500 border-gray-700'}`}>
      {type}
    </span>
  )
}
