import { useState, useEffect } from 'react'
import { getStats, getScanTrends, getIOCStats, getRiskDistribution, getTimeAnalysis } from '../services/api'

export default function Analytics() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [animReady, setAnimReady] = useState(false)

  // Analytics data
  const [trends, setTrends] = useState([])
  const [trendDays, setTrendDays] = useState(14)
  const [iocData, setIocData] = useState({ top_domains: [], top_ips: [], top_senders: [] })
  const [riskData, setRiskData] = useState({ buckets: [], average: 0 })
  const [timeData, setTimeData] = useState({ hourly: [], daily: [] })

  useEffect(() => {
    loadData()
    // Trigger animations after mount
    setTimeout(() => setAnimReady(true), 100)
  }, [])

  useEffect(() => {
    if (!loading) {
      setTimeout(() => setAnimReady(true), 50)
    }
  }, [loading])

  const loadData = () => {
    let unblocked = false
    const unblock = () => { if (!unblocked) { unblocked = true; setLoading(false) } }
    const go = (p, cb) => p.then(r => cb(r.data ?? r)).catch(() => {})

    // Stats resolves fastest (single SQL query) — unblocks the page immediately
    go(getStats(), data => { setStats(data); unblock() })
    go(getScanTrends(14), data => setTrends(data ?? []))
    go(getIOCStats(10), data => setIocData(data ?? { top_domains: [], top_ips: [], top_senders: [] }))
    go(getRiskDistribution(), data => setRiskData(data ?? { buckets: [], average: 0 }))
    go(getTimeAnalysis(), data => setTimeData(data ?? { hourly: [], daily: [] }))
    // Fallback: never hang the page longer than 3s if stats fails
    setTimeout(unblock, 3000)
  }

  const getPercent = (val) => {
    if (!stats?.total || stats.total === 0) return 0
    return Math.round((val / stats.total) * 100)
  }

  const statCards = [
    { label: 'Total Scans', value: stats?.total || 0, color: '#06B6D4' },
    { label: 'Malicious', value: (stats?.malicious || stats?.verdict_counts?.malicious) || 0, color: '#EF4444' },
    { label: 'Suspicious', value: (stats?.suspicious || stats?.verdict_counts?.suspicious) || 0, color: '#F59E0B' },
    { label: 'Safe', value: (stats?.safe || stats?.verdict_counts?.safe) || 0, color: '#10B981' },
  ]

  const maxTrend = trends.length > 0 ? Math.max(...trends.map(t => t.total || 0), 1) : 1
  const maxRisk = riskData.buckets.length > 0 ? Math.max(...riskData.buckets.map(b => b.count || 0), 1) : 1
  const maxHour = timeData.hourly.length > 0 ? Math.max(...timeData.hourly.map(h => h.total || 0), 1) : 1

  if (loading) return <div style={{ padding: '1.5rem', color: '#64748B' }}>Loading...</div>

  return (
    <div style={{ padding: '1.5rem' }}>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.5rem' }}>Analytics</h1>
      <p style={{ color: '#64748B', fontSize: '0.9375rem', marginBottom: '2rem' }}>Overview of your threat analysis statistics</p>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        {statCards.map((card, idx) => (
          <div key={card.label} style={{ background: 'var(--card)', padding: '1.5rem', borderRadius: 12, border: '1px solid var(--border)', opacity: animReady ? 1 : 0, transform: animReady ? 'none' : 'translateY(20px)', transition: 'all 0.5s ease-out', transitionDelay: (idx * 0.1) + 's' }}>
            <p style={{ color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>{card.label}</p>
            <p style={{ fontSize: '2.5rem', fontWeight: 'bold', color: card.color, opacity: animReady ? 1 : 0, transform: animReady ? 'none' : 'translateY(10px)', transition: 'all 0.5s ease-out', transitionDelay: ((idx * 0.1) + 0.2) + 's' }}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Threat Distribution Bar */}
      {stats?.total > 0 && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Threat Distribution</h2>
          <div style={{ display: 'flex', height: 32, borderRadius: 8, overflow: 'hidden', marginBottom: '1rem' }}>
            {(stats?.malicious || stats?.verdict_counts?.malicious || 0) > 0 && (
              <div style={{ width: `${getPercent(stats?.malicious || stats?.verdict_counts?.malicious || 0)}%`, background: '#EF4444' }} />
            )}
            {(stats?.suspicious || stats?.verdict_counts?.suspicious || 0) > 0 && (
              <div style={{ width: `${getPercent(stats?.suspicious || stats?.verdict_counts?.suspicious || 0)}%`, background: '#F59E0B' }} />
            )}
            {(stats?.safe || stats?.verdict_counts?.safe || 0) > 0 && (
              <div style={{ width: `${getPercent(stats?.safe || stats?.verdict_counts?.safe || 0)}%`, background: '#10B981' }} />
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: 12, height: 12, borderRadius: 3, background: '#EF4444' }} />
              <span style={{ color: '#EF4444', fontSize: '0.875rem', fontWeight: 500 }}>Malicious ({(stats?.malicious || stats?.verdict_counts?.malicious) || 0})</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: 12, height: 12, borderRadius: 3, background: '#F59E0B' }} />
              <span style={{ color: '#F59E0B', fontSize: '0.875rem', fontWeight: 500 }}>Suspicious ({(stats?.suspicious || stats?.verdict_counts?.suspicious) || 0})</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: 12, height: 12, borderRadius: 3, background: '#10B981' }} />
              <span style={{ color: '#10B981', fontSize: '0.875rem', fontWeight: 500 }}>Safe ({(stats?.safe || stats?.verdict_counts?.safe) || 0})</span>
            </div>
          </div>
        </div>
      )}

      {/* ── 1. TREND VISUALIZATION ── */}
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1.5rem', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>Scan Trends Over Time</h2>
            <span style={{ background: '#06B6D4' + '20', color: '#06B6D4', padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.625rem', fontWeight: 600 }}>{trendDays} Days</span>
          </div>
          <div style={{ display: 'flex', gap: '0.25rem' }}>
            {[7, 14, 30, 90].map(d => (
              <button key={d} onClick={() => {
                setTrendDays(d)
                getScanTrends(d).then(r => setTrends(r.data || [])).catch(() => {})
              }}
                style={{
                  padding: '0.25rem 0.625rem', borderRadius: 6, border: '1px solid',
                  borderColor: trendDays === d ? 'var(--cyan)' : 'var(--border)',
                  background: trendDays === d ? 'var(--cyan)' : 'transparent',
                  color: trendDays === d ? 'var(--text)' : 'var(--sub)',
                  cursor: 'pointer', fontSize: '0.6875rem', fontWeight: trendDays === d ? 600 : 400
                }}>
                {d}d
              </button>
            ))}
          </div>
        </div>

        {/* Fixed 180px chart — percentage heights inside flex:1 with no fixed ancestor collapse to 0 */}
        <div style={{ position: 'relative', height: 180, marginBottom: 6 }}>
          {/* Gridlines */}
          {[25, 50, 75, 100].map(p => (
            <div key={p} style={{ position: 'absolute', left: 0, right: 0, bottom: p + '%', borderTop: '1px dashed rgba(100,116,139,0.15)', pointerEvents: 'none' }} />
          ))}
          {/* Bars */}
          <div style={{ display: 'flex', alignItems: 'flex-end', height: '100%', gap: '3px' }}>
            {trends.length === 0
              ? Array.from({ length: Math.min(trendDays, 14) }, (_, i) => (
                  <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%', opacity: 0.35 }}>
                    <div style={{ width: '100%', height: (30 + (i * 17) % 120) + 'px', background: 'rgba(6,182,212,0.4)', borderRadius: '3px 3px 0 0' }} />
                  </div>
                ))
              : trends.map((t, i) => {
                  const CHART_H = 180
                  const safe = Math.max(t.safe || 0, 0)
                  const sus  = Math.max(t.suspicious || 0, 0)
                  const mal  = Math.max(t.malicious || 0, 0)
                  const safeH = maxTrend > 0 ? (safe / maxTrend) * CHART_H : 0
                  const susH  = maxTrend > 0 ? (sus  / maxTrend) * CHART_H : 0
                  const malH  = maxTrend > 0 ? (mal  / maxTrend) * CHART_H : 0
                  const hasAny = (t.total || 0) > 0
                  return (
                    <div
                      key={i}
                      title={`${t.date} — ${t.total || 0} scan${(t.total || 0) !== 1 ? 's' : ''} (${safe} safe, ${sus} suspicious, ${mal} malicious)`}
                      style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%', opacity: animReady ? 1 : 0, transform: animReady ? 'none' : 'scaleY(0)', transformOrigin: 'bottom center', transition: 'all 0.4s ease-out', transitionDelay: (i * 0.04) + 's' }}
                    >
                      {hasAny ? (
                        <>
                          {mal > 0 && <div style={{ width: '100%', height: Math.max(malH, 3), background: '#EF4444', borderRadius: sus === 0 && safe === 0 ? '3px 3px 0 0' : '3px 3px 0 0' }} />}
                          {sus > 0 && <div style={{ width: '100%', height: Math.max(susH, 3), background: '#F59E0B', borderRadius: mal === 0 ? '3px 3px 0 0' : 0 }} />}
                          {safe > 0 && <div style={{ width: '100%', height: Math.max(safeH, 3), background: '#10B981', borderRadius: mal === 0 && sus === 0 ? '3px 3px 0 0' : 0 }} />}
                        </>
                      ) : (
                        <div style={{ width: '100%', height: 2, background: 'rgba(100,116,139,0.15)', borderRadius: 1 }} />
                      )}
                    </div>
                  )
                })
            }
          </div>
        </div>
        {/* Date labels */}
        {trends.length > 0 && (
          <div style={{ display: 'flex', paddingTop: 4, borderTop: '1px solid var(--border)', marginBottom: '0.5rem' }}>
            {trends.map((t, i) => (
              <span key={i} style={{ flex: 1, fontSize: '0.5rem', color: 'var(--sub)', textAlign: 'center' }}>{(t.date || '').slice(5)}</span>
            ))}
          </div>
        )}
        {/* Legend */}
        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.6875rem' }}>
          {[['#10B981', 'Safe'], ['#F59E0B', 'Suspicious'], ['#EF4444', 'Malicious']].map(([c, l]) => (
            <span key={l} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: c }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: c, display: 'inline-block', flexShrink: 0 }} />{l}
            </span>
          ))}
        </div>
      </div>

      {/* ── 2. IOC ANALYTICS + RISK DISTRIBUTION SIDE BY SIDE ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>

        {/* IOC Analytics */}
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem' }}>
          <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>🎯 IOC Analytics</h2>

          {/* Top Malicious Domains */}
          <div style={{ marginBottom: '1rem' }}>
            <p style={{ color: '#EF4444', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.5rem', textTransform: 'uppercase' }}>Top Malicious Domains</p>
            {iocData.top_domains.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>No malicious domains detected</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {iocData.top_domains.slice(0, 5).map((d, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface)', padding: '0.375rem 0.5rem', borderRadius: 6 }}>
                    <span style={{ color: 'var(--text)', fontSize: '0.75rem', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 160 }}>{d.domain}</span>
                    <span style={{ background: 'var(--red)', color: 'var(--text)', padding: '0.125rem 0.5rem', borderRadius: 10, fontSize: '0.6875rem', fontWeight: 600, flexShrink: 0 }}>{d.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Top Attacker IPs */}
          <div style={{ marginBottom: '1rem' }}>
            <p style={{ color: '#EF4444', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.5rem', textTransform: 'uppercase' }}>Top Attacker IPs</p>
            {iocData.top_ips.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>No malicious IPs detected</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {iocData.top_ips.slice(0, 5).map((ip, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface)', padding: '0.375rem 0.5rem', borderRadius: 6 }}>
                    <span style={{ color: 'var(--text)', fontSize: '0.75rem', fontFamily: 'monospace' }}>{ip.ip}</span>
                    <span style={{ background: 'var(--red)', color: 'var(--text)', padding: '0.125rem 0.5rem', borderRadius: 10, fontSize: '0.6875rem', fontWeight: 600, flexShrink: 0 }}>{ip.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Suspicious Senders */}
          <div>
            <p style={{ color: '#F59E0B', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.5rem', textTransform: 'uppercase' }}>Suspicious Senders</p>
            {iocData.top_senders.length === 0 ? (
              <p style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>No suspicious senders detected</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {iocData.top_senders.slice(0, 5).map((s, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface)', padding: '0.375rem 0.5rem', borderRadius: 6 }}>
                    <span style={{ color: 'var(--amber)', fontSize: '0.6875rem', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 160 }}>{s.email}</span>
                    <span style={{ background: 'var(--amber)', color: 'var(--text)', padding: '0.125rem 0.5rem', borderRadius: 10, fontSize: '0.6875rem', fontWeight: 600, flexShrink: 0 }}>{s.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Risk Distribution */}
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.25rem', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexShrink: 0 }}>
            <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600 }}>⚠️ Risk Score Distribution</h2>
            <div style={{ background: 'var(--cyan)', padding: '0.25rem 0.625rem', borderRadius: 8 }}>
              <span style={{ color: 'var(--text)', fontSize: '0.6875rem' }}>Avg: </span>
              <span style={{ color: 'var(--text)', fontWeight: 700, fontSize: '0.875rem' }}>{riskData.average}</span>
            </div>
          </div>

          {riskData.buckets.length === 0 || riskData.buckets.every(b => b.count === 0) ? (
            <p style={{ color: 'var(--sub)', padding: '2rem', textAlign: 'center', fontSize: '0.8125rem' }}>No scan data to show distribution</p>
          ) : (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
              <div style={{ position: 'relative', height: 140 }}>
                {[25, 50, 75, 100].map(p => (
                  <div key={p} style={{ position: 'absolute', left: 0, right: 0, bottom: p + '%', borderTop: '1px dashed rgba(100,116,139,0.15)', pointerEvents: 'none' }} />
                ))}
                <div style={{ display: 'flex', alignItems: 'flex-end', height: '100%', gap: '4px' }}>
                  {riskData.buckets.map((b, i) => {
                    const h = (b.count / maxRisk) * 140
                    const color = i >= 7 ? '#EF4444' : i >= 4 ? '#F59E0B' : '#10B981'
                    return (
                      <div key={i} title={`${b.range}: ${b.count}`} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%' }}>
                        <div style={{ width: '100%', height: Math.max(h, b.count > 0 ? 3 : 0), background: color, borderRadius: '3px 3px 0 0', transition: 'height 0.3s' }} />
                      </div>
                    )
                  })}
                </div>
              </div>
              <div style={{ display: 'flex', marginTop: '0.375rem', paddingTop: 4, borderTop: '1px solid var(--border)' }}>
                {riskData.buckets.map((b, i) => (
                  <div key={i} style={{ flex: 1, textAlign: 'center' }}>
                    <span style={{ fontSize: '0.5rem', color: 'var(--sub)' }}>{b.range.split('-')[0]}</span>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.6875rem' }}>
                {[['#10B981', 'Low (0-40)'], ['#F59E0B', 'Medium (40-70)'], ['#EF4444', 'High (70-100)']].map(([c, l]) => (
                  <span key={l} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: c }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: c, display: 'inline-block', flexShrink: 0 }} />{l}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── 3. TIME-BASED ANALYSIS ── */}
      <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
          <span style={{ background: '#8B5CF620', color: '#8B5CF6', padding: '0.375rem', borderRadius: 6, fontSize: '1rem' }}>⏱</span>
          <h2 style={{ color: 'var(--text)', fontSize: '1rem', fontWeight: 600, margin: 0 }}>Time-Based Analysis</h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>

          {/* Scans by Hour */}
          <div style={{ background: 'var(--surface)', borderRadius: 10, padding: '1.25rem', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, margin: 0 }}>Scans by Hour</p>
              <span style={{ background: '#06B6D420', color: '#06B6D4', padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.625rem', fontWeight: 700 }}>24H</span>
            </div>

            {/* flex:1 pushes chart+axis+legend to the bottom of the card */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
              {/* Fixed 180px container — % heights inside flex:1 with no fixed ancestor collapse to 0 */}
              <div style={{ position: 'relative', height: 180 }}>
                {[25, 50, 75, 100].map(pct => (
                  <div key={pct} style={{ position: 'absolute', left: 0, right: 0, bottom: pct + '%', borderTop: '1px dashed rgba(100,116,139,0.18)', pointerEvents: 'none' }} />
                ))}
                <div style={{ display: 'flex', alignItems: 'flex-end', height: '100%', gap: '3px' }}>
                  {timeData.hourly.map((h, i) => {
                    const CHART_H = 180
                    const safeH = maxHour > 0 ? (h.safe       / maxHour) * CHART_H : 0
                    const susH  = maxHour > 0 ? (h.suspicious / maxHour) * CHART_H : 0
                    const malH  = maxHour > 0 ? (h.malicious  / maxHour) * CHART_H : 0
                    const isPeak = h.total > 0 && h.total === maxHour
                    const hasMal = h.malicious > 0, hasSus = h.suspicious > 0, hasSafe = h.safe > 0
                    return (
                      <div
                        key={i}
                        title={`${String(i).padStart(2, '0')}:00 — ${h.total} scans (${h.safe} safe · ${h.suspicious} susp · ${h.malicious} mal)`}
                        style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%', cursor: 'default' }}
                      >
                        {h.total > 0 ? (
                          <>
                            {hasMal && <div style={{ width: '100%', height: Math.max(malH, 3), background: '#EF4444', borderRadius: '3px 3px 0 0', boxShadow: isPeak ? '0 0 6px #EF444480' : 'none' }} />}
                            {hasSus && <div style={{ width: '100%', height: Math.max(susH, 3), background: '#F59E0B', borderRadius: !hasMal ? '3px 3px 0 0' : 0 }} />}
                            {hasSafe && <div style={{ width: '100%', height: Math.max(safeH, 3), background: isPeak ? '#06B6D4' : '#10B981', borderRadius: !hasMal && !hasSus ? '3px 3px 0 0' : 0, boxShadow: isPeak ? '0 0 8px #06B6D460' : 'none' }} />}
                          </>
                        ) : (
                          <div style={{ width: '100%', height: 2, background: 'rgba(100,116,139,0.2)', borderRadius: 1 }} />
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* X-axis */}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px', paddingTop: '6px', borderTop: '1px solid var(--border)' }}>
                {[0, 4, 8, 12, 16, 20, 23].map(h => (
                  <span key={h} style={{ fontSize: '0.5625rem', color: 'var(--sub)' }}>
                    {String(h).padStart(2, '0')}h
                  </span>
                ))}
              </div>

              {/* Legend */}
              <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
                {[['#10B981','Safe'],['#F59E0B','Suspicious'],['#EF4444','Malicious']].map(([c, l]) => (
                  <span key={l} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.6875rem', color: c }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0, display: 'inline-block' }} />{l}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Scans by Day */}
          <div style={{ background: 'var(--surface)', borderRadius: 10, padding: '1.25rem', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <p style={{ color: 'var(--text)', fontSize: '0.8125rem', fontWeight: 600, margin: 0 }}>Scans by Day</p>
              <span style={{ background: '#8B5CF620', color: '#8B5CF6', padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.625rem', fontWeight: 700 }}>7 Days</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', flex: 1, justifyContent: 'space-between' }}>
              {(() => {
                const maxDay = Math.max(...timeData.daily.map(d => d.total), 1)
                return timeData.daily.map((d, i) => {
                  const totalPct = (d.total / maxDay) * 100
                  const isPeak   = d.total > 0 && d.total === maxDay
                  return (
                    <div key={i}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontSize: '0.8125rem', fontWeight: isPeak ? 700 : 400,
                            color: isPeak ? 'var(--text)' : 'var(--sub)', minWidth: 76 }}>{d.day}</span>
                          {isPeak && (
                            <span style={{ background: '#8B5CF6', color: '#fff', padding: '1px 6px',
                              borderRadius: 3, fontSize: '0.5rem', fontWeight: 700, letterSpacing: '0.04em' }}>PEAK</span>
                          )}
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: isPeak ? 700 : 400,
                          color: isPeak ? 'var(--text)' : 'var(--sub)' }}>{d.total}</span>
                      </div>
                      {/* Track */}
                      <div style={{ height: 10, background: 'rgba(100,116,139,0.12)', borderRadius: 5, overflow: 'hidden' }}>
                        {d.total > 0 ? (
                          /* Width = proportion of peak; inner flex splits into safe/sus/mal */
                          <div style={{ display: 'flex', height: '100%', width: `${totalPct}%`,
                            borderRadius: 5, overflow: 'hidden',
                            transition: 'width 0.4s ease-out' }}>
                            <div style={{ flex: d.safe,       minWidth: d.safe       > 0 ? 2 : 0, background: '#10B981' }} />
                            <div style={{ flex: d.suspicious, minWidth: d.suspicious > 0 ? 2 : 0, background: '#F59E0B' }} />
                            <div style={{ flex: d.malicious,  minWidth: d.malicious  > 0 ? 2 : 0, background: '#EF4444' }} />
                          </div>
                        ) : null}
                      </div>
                    </div>
                  )
                })
              })()}
            </div>

            {/* Legend */}
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.25rem', flexWrap: 'wrap' }}>
              {[['#10B981','Safe'],['#F59E0B','Suspicious'],['#EF4444','Malicious']].map(([c, l]) => (
                <span key={l} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.6875rem', color: c }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0, display: 'inline-block' }} />{l}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Empty State */}
      {stats?.total === 0 && (
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '3rem', textAlign: 'center' }}>
          <p style={{ color: '#64748B', marginBottom: '0.5rem' }}>No analytics data yet</p>
          <p style={{ color: '#64748B', fontSize: '0.8125rem' }}>Start analyzing emails to see your threat statistics here</p>
        </div>
      )}
    </div>
  )
}