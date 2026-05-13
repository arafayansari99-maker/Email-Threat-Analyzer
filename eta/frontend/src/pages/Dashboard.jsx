import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import api, { getStats, getHistory, getWidgetOrder, saveWidgetOrder, getScanTrends, getIOCStats, cachedGet } from '../services/api'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, AreaChart, Area } from 'recharts'

const WIDGET_REGISTRY = {
  overview: { title: 'Overview', label: 'overview', component: 'stats' },
  recent_scans: { title: 'Recent Scans', label: 'recent_scans', component: 'recentScans' },
  verdict_chart: { title: 'Verdict Chart', label: 'verdict_chart', component: 'pieChart' },
  quick_access: { title: 'Quick Access', label: 'quick_access', component: 'quickAccess' },
  threat_news: { title: 'Threat News', label: 'threat_news', component: 'threatNews' },
  malicious_domains: { title: 'Malicious Domains', label: 'malicious_domains', component: 'maliciousDomains' },
  detected_urls: { title: 'Top Detected URLs', label: 'detected_urls', component: 'detectedUrls' },
  malicious_senders: { title: 'Top Malicious Senders', label: 'malicious_senders', component: 'maliciousSenders' },
  threat_breakdown: { title: 'Threat Type Breakdown', label: 'threat_breakdown', component: 'threatBreakdown' },
  scan_volume: { title: 'Scan Volume', label: 'scan_volume', component: 'scanVolume' },
}

const DEFAULT_WIDGET_ORDER = ['overview', 'verdict_chart', 'threat_breakdown', 'scan_volume', 'recent_scans', 'detected_urls', 'malicious_senders', 'malicious_domains', 'threat_news', 'quick_access']

export default function Dashboard() {
  const { user } = useAuth()
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [widgetOrder, setWidgetOrder] = useState(DEFAULT_WIDGET_ORDER)
  const [editMode, setEditMode] = useState(false)
  const [trends, setTrends] = useState([])
  const [iocStats, setIocStats] = useState({ urls: [], senders: [] })
  const location = useLocation()
  const hasLoadedOnce = useRef(false)

  useEffect(() => {
    loadData()
  }, [location.key])

  const saveOrder = async (newOrder) => {
    try { await saveWidgetOrder(newOrder) } catch {}
  }

  const loadData = async () => {
    const isFirstLoad = !hasLoadedOnce.current
    if (isFirstLoad) setLoading(true)

    try {
      const [s, h, t, ioc, wo] = await Promise.all([
        cachedGet('/api/history/stats', { cacheKey: 'dash_stats', ttl: 60000 }),
        cachedGet('/api/history/scan-history', { cacheKey: 'dash_history', ttl: 60000, page: 1, limit: 10 }),
        cachedGet('/api/analytics/trends', { cacheKey: 'dash_trends', ttl: 60000, days: 7 }).catch(() => ({ daily: [] })),
        cachedGet('/api/analytics/ioc-stats', { cacheKey: 'dash_ioc', ttl: 60000, limit: 10 }).catch(() => ({ urls: [], senders: [] })),
        cachedGet('/api/settings/widget-order', { cacheKey: 'dash_widget_order', ttl: 300000 }).catch(() => null),
      ])
      setStats(s || {})
      setHistory(h?.records || [])
      setTrends(t?.daily || t?.trend || [])
      setIocStats(ioc || { urls: [], senders: [] })
      if (wo?.order && Array.isArray(wo.order)) {
        const allWidgetKeys = Object.keys(WIDGET_REGISTRY)
        const mergedOrder = [...wo.order]
        allWidgetKeys.forEach(key => { if (!mergedOrder.includes(key)) mergedOrder.push(key) })
        setWidgetOrder(mergedOrder)
      }
      hasLoadedOnce.current = true
    } catch (e) {
      console.error(e)
      if (isFirstLoad) setError('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const getColor = (v) => ({ malicious: 'var(--red)', suspicious: 'var(--amber)', safe: 'var(--green)' }[v] || 'var(--sub)')
  const getBgColor = (v) => ({ malicious: 'rgba(239,68,68,0.15)', suspicious: 'rgba(245,158,11,0.15)', safe: 'rgba(16,185,129,0.15)' }[v] || 'rgba(100,116,139,0.15)')

  // Memoize expensive computations
  const statCards = useMemo(() => [
    { label: 'Total Scans', value: stats?.total || 0, color: 'var(--cyan)' },
    { label: 'Malicious', value: stats?.malicious || 0, color: 'var(--red)' },
    { label: 'Suspicious', value: stats?.suspicious || 0, color: 'var(--amber)' },
    { label: 'Safe', value: stats?.safe || 0, color: 'var(--green)' },
  ], [stats?.total, stats?.malicious, stats?.suspicious, stats?.safe])

  const features = useMemo(() => [
    { to: '/analyze', label: 'Email Analyzer', desc: 'Upload and analyze email files for threats', color: 'var(--cyan)' },
    { to: '/history', label: 'Scan History', desc: 'View all your scanned emails and results', color: 'var(--purple)' },
    { to: '/analytics', label: 'Analytics', desc: 'Visualize threat statistics and trends', color: 'var(--pink)' },
    { to: '/reports', label: 'Reports', desc: 'Generate detailed threat reports', color: 'var(--amber)' },
    { to: '/graph', label: 'IOC Graph', desc: 'Interactive threat indicator visualization', color: 'var(--green)' },
    { to: '/privacy', label: 'Privacy', desc: 'Manage your data and privacy settings', color: 'var(--sub)' },
    { to: '/settings', label: 'Settings', desc: 'Update profile and preferences', color: 'var(--sub)' },
  ], [])

  const threatNews = [
    {
      title: 'AI-Powered Spear Phishing Surge in 2026',
      source: 'Dark Reading',
      website: 'https://darkreading.com',
      time: '2 hours ago',
      severity: 'critical',
      tag: 'Phishing',
      excerpt: 'Threat actors leverage AI to craft highly personalized spear-phishing emails that bypass traditional filters with 85% success rates.',
    },
    {
      title: 'Critical OAuth Flaw Grants Full Account Access',
      source: 'The Hacker News',
      website: 'https://thehackernews.com',
      time: '5 hours ago',
      severity: 'critical',
      tag: 'Vulnerability',
      excerpt: 'A newly discovered flaw in OAuth 2.0 implementations allows attackers to bypass MFA and gain persistent access to enterprise accounts.',
    },
    {
      title: 'New Ransomware Strain Targets Cloud Backups',
      source: 'Bleeping Computer',
      website: 'https://bleepingcomputer.com',
      time: '8 hours ago',
      severity: 'high',
      tag: 'Ransomware',
      excerpt: 'A sophisticated ransomware group targets cloud backup services, encrypting snapshots before demanding ransom.',
    },
    {
      title: 'BEC Scams Cost Businesses $2.9B in 2025',
      source: 'CISA Alerts',
      website: 'https://cisa.gov/news-events',
      time: '1 day ago',
      severity: 'medium',
      tag: 'BEC',
      excerpt: 'Business Email Compromise remains the most financially damaging cyber threat, with average losses exceeding $240K per incident.',
    },
  ]

  const maliciousDomains = [
    { domain: 'secure-paypa1-login.com', type: 'Phishing', risk: 98 },
    { domain: 'amazon-verify-account.net', type: 'Phishing', risk: 97 },
    { domain: 'mail-update-center.io', type: 'Credential Theft', risk: 95 },
    { domain: 'apple-id-verify.co', type: 'Phishing', risk: 94 },
    { domain: 'bank-login-portal.org', type: 'Credential Theft', risk: 92 },
  ]

  // Move widget up
  const moveUp = (idx) => {
    if (idx <= 0) return
    const n = [...widgetOrder]
    const temp = n[idx]
    n[idx] = n[idx - 1]
    n[idx - 1] = temp
    setWidgetOrder(n)
  }

  // Move widget down
  const moveDown = (idx) => {
    if (idx >= widgetOrder.length - 1) return
    const n = [...widgetOrder]
    const temp = n[idx]
    n[idx] = n[idx + 1]
    n[idx + 1] = temp
    setWidgetOrder(n)
  }

  // Stats Component - Memoized for performance
  const StatsWidget = useMemo(() => () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Overview</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        {statCards.map((card, idx) => (
          <div key={card.label} style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
            <p style={{ fontSize: '0.75rem', color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>{card.label}</p>
            <p style={{ fontSize: '2rem', fontWeight: 'bold', color: card.color }}>{card.value}</p>
          </div>
        ))}
      </div>
    </div>
  ), [statCards])

  // Skeleton for Stats
  const StatsSkeleton = () => (
    <div style={{ marginBottom: '2rem' }}>
      <div className="skeleton skeleton-title" style={{ width: '30%' }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="skeleton skeleton-card" />
        ))}
      </div>
    </div>
  )

  // Quick Access Component
  const QuickAccessWidget = () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Quick Access</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        {features.map(f => (
          <Link key={f.to} to={f.to} style={{ textDecoration: 'none', display: 'flex', minHeight: '100px' }}>
            <div style={{
              background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)',
              padding: '1.25rem', transition: 'all 0.25s ease', cursor: 'pointer',
              flex: 1, display: 'flex', flexDirection: 'column', gap: '0.5rem',
              minHeight: '100px',
            }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = f.color + '99'
                e.currentTarget.style.background = f.color + '14'
                e.currentTarget.style.transform = 'translateY(-3px)'
                e.currentTarget.style.boxShadow = `0 8px 24px ${f.color}22`
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--border)'
                e.currentTarget.style.background = 'var(--card)'
                e.currentTarget.style.transform = 'translateY(0)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            >
              <p style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text)', margin: 0 }}>{f.label}</p>
              <p style={{ fontSize: '0.8125rem', color: 'var(--sub)', margin: 0, lineHeight: 1.4 }}>{f.desc}</p>
            </div>
          </Link>
        ))}
      </div>
    </div>
  )

  // Recent Scans Component
  const RecentScansWidget = () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Recent Scans</h2>
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
        {history.length > 0 ? (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>File</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Verdict</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Score</th>
                <th style={{ padding: '0.875rem', textAlign: 'left', color: 'var(--sub)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {history.map(r => (
                <tr key={r.scan_id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '0.875rem', color: 'var(--text)', fontSize: '0.875rem' }}>{r.filename}</td>
                  <td style={{ padding: '0.875rem' }}>
                    <span style={{
                      display: 'inline-block', padding: '0.25rem 0.625rem', borderRadius: 6,
                      fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase',
                      background: getBgColor(r.verdict), color: getColor(r.verdict),
                    }}>
                      {r.verdict}
                    </span>
                  </td>
                  <td style={{ padding: '0.875rem', color: getColor(r.verdict), fontSize: '0.875rem', fontWeight: 600 }}>{r.risk_score}</td>
                  <td style={{ padding: '0.875rem', color: 'var(--sub)', fontSize: '0.8125rem' }}>{new Date(r.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--sub)' }}>No scans yet</div>
        )}
      </div>
      <Link to="/history" style={{ fontSize: '0.8125rem', color: 'var(--cyan)', textDecoration: 'none', marginTop: '0.5rem', display: 'inline-block' }}>View All</Link>
    </div>
  )

  // Pie Chart Component
  const PieChartWidget = () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>Threat Distribution</h2>
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={[
                { name: 'Safe', value: stats?.safe || 0 },
                { name: 'Suspicious', value: stats?.suspicious || 0 },
                { name: 'Malicious', value: stats?.malicious || 0 },
              ]}
              cx="50%" cy="50%"
              innerRadius={55} outerRadius={88}
              paddingAngle={4}
              dataKey="value"
              animationBegin={200}
              animationDuration={1200}
              animationEasing="ease-out"
              isAnimationActive={true}
            >
              {[
                { name: 'Safe', color: 'var(--green)' },
                { name: 'Suspicious', color: 'var(--amber)' },
                { name: 'Malicious', color: 'var(--red)' },
              ].map((entry) => (
                <Cell key={entry.name} fill={entry.color} stroke="transparent" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: 'var(--muted)', border: '1px solid var(--sub)', borderRadius: 8, color: '#fff', fontSize: '0.8125rem' }}
              itemStyle={{ color: 'var(--text)' }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '1.25rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
          {[
            { label: 'Safe', color: 'var(--green)', value: stats?.safe || 0 },
            { label: 'Suspicious', color: 'var(--amber)', value: stats?.suspicious || 0 },
            { label: 'Malicious', color: 'var(--red)', value: stats?.malicious || 0 },
          ].map(item => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: item.color }} />
              <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>{item.label}: <strong style={{ color: item.color }}>{item.value}</strong></span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )

  // Threat News Component
  const ThreatNewsWidget = () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
        Latest Threat Intelligence
      </h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {threatNews.map((news, idx) => (
          <div key={idx} style={{
            background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)',
            padding: '1rem 1.25rem', transition: 'all 0.2s ease', cursor: 'pointer',
          }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--cyan)44'
              e.currentTarget.style.background = 'var(--surface)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--border)'
              e.currentTarget.style.background = 'var(--card)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
              <span style={{
                fontSize: '0.6875rem', fontWeight: 700, padding: '0.2rem 0.5rem', borderRadius: 4,
                textTransform: 'uppercase',
                background: news.severity === 'critical' ? 'rgba(239,68,68,0.2)' : news.severity === 'high' ? 'rgba(245,158,11,0.2)' : 'rgba(100,116,139,0.2)',
                color: news.severity === 'critical' ? 'var(--red)' : news.severity === 'high' ? 'var(--amber)' : 'var(--sub)',
                letterSpacing: '0.05em',
              }}>
                {news.severity}
              </span>
              <span style={{ fontSize: '0.6875rem', padding: '0.2rem 0.4rem', borderRadius: 4, background: 'var(--muted)', color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {news.tag}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--sub)', marginLeft: 'auto' }}>{news.time}</span>
            </div>
            <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text)', marginBottom: '0.3rem' }}>{news.title}</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--sub)', lineHeight: 1.4 }}>{news.excerpt}</p>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.4rem' }}>
              <p style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>
                <span style={{ color: 'var(--cyan)' }}>Source:</span> {news.source}
              </p>
              {news.website && (
                <a href={news.website} target="_blank" rel="noopener noreferrer" style={{ fontSize: '0.7rem', color: 'var(--cyan)', textDecoration: 'none' }}>
                  Visit →
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  // Malicious Domains Component
  const MaliciousDomainsWidget = () => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
        Top Malicious Domains
      </h2>
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart layout="vertical" data={maliciousDomains} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
            <XAxis type="number" domain={[0, 100]} tick={{ fill: 'var(--sub)', fontSize: 11 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
            <YAxis type="category" dataKey="domain" tick={{ fill: 'var(--sub)', fontSize: 10 }} width={150} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: 'var(--muted)', border: '1px solid var(--sub)', borderRadius: 8, color: '#fff', fontSize: '0.8125rem' }}
              formatter={(value) => [`${value}%`, 'Risk Score']}
              cursor={{ fill: 'rgba(6,182,212,0.05)' }}
            />
            <Bar dataKey="risk" radius={[0, 6, 6, 0]} animationDuration={1400} animationEasing="ease-out" isAnimationActive={true}>
              {maliciousDomains.map((entry, index) => {
                const color = entry.risk >= 95 ? 'var(--red)' : 'var(--amber)'
                return <Cell key={index} fill={color} />
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '1rem' }}>
          {maliciousDomains.map((d, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', background: 'var(--muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: d.risk >= 95 ? 'var(--red)' : 'var(--amber)', minWidth: 32 }}>#{i + 1}</span>
              <span style={{ fontSize: '0.8rem', color: 'var(--sub)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.domain}</span>
              <span style={{ fontSize: '0.75rem', background: 'var(--muted)', padding: '0.15rem 0.4rem', borderRadius: 4, color: 'var(--sub)' }}>{d.type}</span>
              <span style={{ fontSize: '0.8rem', fontWeight: 700, color: d.risk >= 95 ? 'var(--red)' : 'var(--amber)' }}>{d.risk}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )

  // Detected URLs Widget
  const DetectedURLsWidget = ({ urls }) => {
    const displayUrls = urls.length > 0 ? urls : [
      { url: 'secure-paypa1-login.com/verify', type: 'Phishing', risk: 96 },
      { url: 'amazon-verify-account.net/login', type: 'Phishing', risk: 94 },
      { url: 'bank-login-portal.org/secure', type: 'Credential Theft', risk: 91 },
      { url: 'apple-id-verify.co/auth', type: 'Phishing', risk: 88 },
      { url: 'mail-update-center.io/account', type: 'Credential Theft', risk: 85 },
    ]
    return (
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
          Top Detected URLs
        </h2>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {displayUrls.slice(0, 5).map((d, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', background: 'var(--muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--cyan)', minWidth: 24 }}>#{i + 1}</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--sub)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.url}</span>
                <span style={{ fontSize: '0.75rem', background: 'var(--muted)', padding: '0.15rem 0.4rem', borderRadius: 4, color: 'var(--amber)' }}>{d.type}</span>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: d.risk >= 90 ? 'var(--red)' : 'var(--amber)' }}>{d.risk}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  // Malicious Senders Widget
  const MaliciousSendersWidget = ({ senders }) => {
    const displaySenders = senders.length > 0 ? senders : [
      { email: 'security@paypa1-verify.com', count: 47, verdict: 'malicious' },
      { email: 'support@amazon-account.net', count: 32, verdict: 'malicious' },
      { email: 'admin@bank-login-portal.org', count: 28, verdict: 'suspicious' },
      { email: 'noreply@mail-update.io', count: 19, verdict: 'suspicious' },
      { email: 'help@apple-id-verify.co', count: 15, verdict: 'malicious' },
    ]
    return (
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
          Top Malicious Senders
        </h2>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {displaySenders.slice(0, 5).map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', background: 'var(--muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--red)', minWidth: 24 }}>#{i + 1}</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.email}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>{s.count}x</span>
                <span style={{
                  fontSize: '0.7rem', fontWeight: 600, padding: '0.2rem 0.5rem', borderRadius: 4,
                  background: s.verdict === 'malicious' ? 'rgba(239,68,68,0.2)' : 'rgba(245,158,11,0.2)',
                  color: s.verdict === 'malicious' ? 'var(--red)' : 'var(--amber)',
                  textTransform: 'uppercase'
                }}>{s.verdict}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  // Threat Type Breakdown Widget
  const ThreatBreakdownWidget = ({ stats }) => {
    const threatData = [
      { name: 'Phishing', value: stats?.phishing || 42 },
      { name: 'Malware', value: stats?.malware || 18 },
      { name: 'BEC', value: stats?.bec || 12 },
      { name: 'Ransomware', value: stats?.ransomware || 8 },
    ]
    return (
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
          Threat Type Breakdown
        </h2>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={threatData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: 'var(--sub)', fontSize: 11 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
              <YAxis tick={{ fill: 'var(--sub)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--muted)', border: '1px solid var(--sub)', borderRadius: 8, color: '#fff', fontSize: '0.8125rem' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]} animationDuration={1200} animationEasing="ease-out">
                {threatData.map((entry, index) => {
                  const colors = ['var(--red)', 'var(--amber)', 'var(--purple)', 'var(--cyan)']
                  return <Cell key={index} fill={colors[index % colors.length]} />
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
            {threatData.map(item => (
              <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--sub)' }}>{item.name}: <strong style={{ color: 'var(--text)' }}>{item.value}</strong></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  // Scan Volume Widget
  const ScanVolumeWidget = ({ trends }) => {
    const displayTrends = trends.length > 0 ? trends : [
      { date: '2026-04-22', scans: 12 },
      { date: '2026-04-23', scans: 18 },
      { date: '2026-04-24', scans: 15 },
      { date: '2026-04-25', scans: 22 },
      { date: '2026-04-26', scans: 19 },
      { date: '2026-04-27', scans: 14 },
      { date: '2026-04-28', scans: 8 },
    ]
    return (
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--sub)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
          Scan Volume (Last 7 Days)
        </h2>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={displayTrends} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--cyan)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: 'var(--sub)', fontSize: 10 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} tickFormatter={(v) => v?.slice(5) || ''} />
              <YAxis tick={{ fill: 'var(--sub)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--muted)', border: '1px solid var(--sub)', borderRadius: 8, color: '#fff', fontSize: '0.8125rem' }}
                formatter={(value) => [value, 'Scans']}
              />
              <Area type="monotone" dataKey="scans" stroke="var(--cyan)" fillOpacity={1} fill="url(#colorScans)" strokeWidth={2} animationDuration={1200} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    )
  }

  // Widget mapping
  const renderWidget = (widgetKey) => {
    switch (widgetKey) {
      case 'overview':
        return <StatsWidget key="overview" />
      case 'quick_access':
        return <QuickAccessWidget key="quick_access" />
      case 'recent_scans':
        return <RecentScansWidget key="recent_scans" />
      case 'verdict_chart':
        return <PieChartWidget key="verdict_chart" />
      case 'threat_news':
        return <ThreatNewsWidget key="threat_news" />
      case 'malicious_domains':
        return <MaliciousDomainsWidget key="malicious_domains" />
      case 'detected_urls':
        return <DetectedURLsWidget key="detected_urls" urls={iocStats.urls || []} />
      case 'malicious_senders':
        return <MaliciousSendersWidget key="malicious_senders" senders={iocStats.senders || []} />
      case 'threat_breakdown':
        return <ThreatBreakdownWidget key="threat_breakdown" stats={stats} />
      case 'scan_volume':
        return <ScanVolumeWidget key="scan_volume" trends={trends} />
      default:
        return null
    }
  }

  return (
    <div style={{ padding: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Dashboard</h1>
          <p style={{ color: 'var(--sub)', fontSize: '0.9375rem' }}>Welcome back, <span style={{ color: 'var(--cyan)', fontWeight: 600 }}>{user?.username}</span></p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={loadData}
            disabled={loading}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.375rem',
              padding: '0.5rem 1rem', borderRadius: 8,
              border: '1px solid var(--border)', background: 'var(--surface)',
              color: loading ? 'var(--sub)' : 'var(--text)',
              fontSize: '0.8125rem', fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s',
            }}
          >
            <span style={{ display: 'inline-block', transition: 'transform 0.4s', transform: loading ? 'rotate(360deg)' : 'none' }}>↻</span>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
          <Link to="/analyze" style={{ padding: '0.625rem 1.25rem', borderRadius: 8, background: 'var(--cyan)', color: '#fff', textDecoration: 'none', fontSize: '0.875rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>+</span> Quick Scan
          </Link>
          <button onClick={() => setEditMode(!editMode)} style={{ padding: '0.5rem 1rem', borderRadius: 8, border: '1px solid var(--border)', background: editMode ? 'var(--cyan)' : 'var(--surface)', color: editMode ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 500 }}>
            {editMode ? 'Done' : 'Customize'}
          </button>
        </div>
      </div>

      {/* Widget Reorder UI */}
      {editMode && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem', marginBottom: '1.5rem' }}>
          <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '1rem' }}>Reorder Dashboard Widgets</h3>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {widgetOrder.map((wid, idx) => (
              <div key={wid} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '0.375rem 0.625rem' }}>
                <button disabled={idx === 0} onClick={() => moveUp(idx)}
                  style={{ background: 'none', border: 'none', color: idx === 0 ? 'var(--sub)' : 'var(--text)', cursor: idx === 0 ? 'not-allowed' : 'pointer', fontSize: '0.75rem', padding: '0 0.25rem' }}>⬆</button>
                <span style={{ fontSize: '0.8125rem', color: 'var(--text)' }}>{WIDGET_REGISTRY[wid]?.title}</span>
                <button disabled={idx === widgetOrder.length - 1} onClick={() => moveDown(idx)}
                  style={{ background: 'none', border: 'none', color: idx === widgetOrder.length - 1 ? 'var(--sub)' : 'var(--text)', cursor: idx === widgetOrder.length - 1 ? 'not-allowed' : 'pointer', fontSize: '0.75rem', padding: '0 0.25rem' }}>⬇</button>
              </div>
            ))}
          </div>
          <button onClick={() => { saveOrder(widgetOrder); setEditMode(false) }}
            style={{ marginTop: '1rem', padding: '0.5rem 1rem', borderRadius: 8, background: 'var(--cyan)', color: '#fff', border: 'none', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
            Save & Exit
          </button>
        </div>
      )}

      {loading ? (
        <>
          <StatsSkeleton />
          <div style={{ marginBottom: '2rem' }}>
            <div className="skeleton skeleton-title" style={{ width: '40%' }} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
              {[1, 2, 3, 4].map(i => (
                <div key={i} className="skeleton skeleton-card" style={{ minHeight: '100px' }} />
              ))}
            </div>
          </div>
        </>
      ) : (
        // Render widgets in the order specified by widgetOrder
        <>{widgetOrder.map(wid => renderWidget(wid))}</>
      )}
    </div>
  )
}