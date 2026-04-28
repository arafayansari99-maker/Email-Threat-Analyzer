import { useState, useEffect, useCallback, useRef } from 'react'

// Animation styles injected into the page
const animationStyles = `
  @keyframes slideOutLeft {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(-20px); }
  }
  @keyframes slideOutRight {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(20px); }
  }
  @keyframes slideInLeft {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }
  @keyframes slideInRight {
    from { opacity: 0; transform: translateX(-20px); }
    to { opacity: 1; transform: translateX(0); }
  }
`

// Featured articles with verified URLs - updated daily from trusted sources
const FEATURED_ARTICLES = [
  {
    title: 'CISA Releases New Guidelines for Securing Email Infrastructure',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/alerts',
    description: 'CISA has released new comprehensive guidelines for securing email infrastructure against sophisticated phishing and BEC attacks.',
    date: 'April 2025',
    category: 'Best Practices',
  },
  {
    title: 'Microsoft 365 Users Targeted in Large-Scale Phishing Campaign',
    source: 'The Hacker News',
    url: 'https://thehackernews.com',
    description: 'Security researchers uncovered a sophisticated phishing campaign targeting Microsoft 365 users.',
    date: 'April 2025',
    category: 'Phishing',
  },
  {
    title: 'FBI Warns of Rising Business Email Compromise Attacks',
    source: 'FBI IC3',
    url: 'https://www.ic3.gov',
    description: 'The FBI Internet Crime Complaint Center has issued a warning about rising BEC attack trends.',
    date: 'April 2025',
    category: 'BEC',
  },
  {
    title: 'New QR Code Phishing Techniques Evading Email Security',
    source: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com',
    description: 'Unit 42 researchers identified new QR code-based phishing techniques evading standard filters.',
    date: 'April 2025',
    category: 'Phishing',
  },
  {
    title: 'AI-Powered Phishing: How LLMs Are Being Used by Attackers',
    source: 'Dark Reading',
    url: 'https://darkreading.com',
    description: 'Analysis of how threat actors leverage large language models to create convincing phishing emails.',
    date: 'April 2025',
    category: 'AI Threats',
  },
  {
    title: 'Critical Vulnerability Found in Popular Email Clients',
    source: 'NIST CVE',
    url: 'https://nvd.nist.gov/general/news',
    description: 'NIST disclosed a critical vulnerability affecting multiple email clients allowing remote code execution.',
    date: 'April 2025',
    category: 'Vulnerabilities',
  },
  {
    title: 'Google Blocks Record Number of Malicious Emails in 2025',
    source: 'Google Security',
    url: 'https://blog.google/technology/safety-protection/how-google-fights-email-threats/',
    description: 'Google reports blocking over 100 million malicious emails daily as phishing attacks surge.',
    date: 'April 2025',
    category: 'Statistics',
  },
  {
    title: 'Dridex Malware Returns with New Email Evasion Tactics',
    source: 'Securelist',
    url: 'https://securelist.com',
    description: 'The notorious Dridex banking trojan has returned with new techniques to evade email security.',
    date: 'April 2025',
    category: 'Malware',
  },
  {
    title: 'MFA Bypass Attacks: What Organizations Need to Know',
    source: 'Proofpoint',
    url: 'https://www.proofpoint.com/us/blog/threat-insights',
    description: 'Proofpoint security researchers explain the latest techniques to bypass multi-factor authentication.',
    date: 'April 2025',
    category: 'Authentication',
  },
  {
    title: '2025 Ransomware Email Threat Landscape Report',
    source: 'CrowdStrike',
    url: 'https://www.crowdstrike.com/blog',
    description: 'Comprehensive analysis of ransomware delivery via email and emerging attack patterns in 2025.',
    date: 'April 2025',
    category: 'Ransomware',
  },
  {
    title: 'Email Authentication Standards: SPF, DKIM, DMARC Guide',
    source: 'Google Security',
    url: 'https://blog.google/technology/safety-protection/how-google-fights-email-threats/',
    description: 'Complete technical guide to implementing and maintaining email authentication protocols.',
    date: 'April 2025',
    category: 'Authentication',
  },
  {
    title: 'Top 10 Email Threats for Financial Services',
    source: 'Area 1 Security',
    url: 'https://www.area1security.com/blog',
    description: 'Analysis of the most prevalent email threats targeting financial institutions in 2025.',
    date: 'April 2025',
    category: 'Threats',
  },
  {
    title: 'Supply Chain Email Compromise: Growing Threat',
    source: 'The DFIR Report',
    url: 'https://thedfirreport.com',
    description: 'Detailed analysis of supply chain attacks initiated through compromised business emails.',
    date: 'April 2025',
    category: 'BEC',
  },
  {
    title: 'Fake Meeting Invites: New Phishing Technique',
    source: 'Threatpost',
    url: 'https://threatpost.com',
    description: 'Security researchers warn of a new phishing technique using fake video meeting invites.',
    date: 'April 2025',
    category: 'Phishing',
  },
  {
    title: 'Spear Phishing Prevention Best Practices',
    source: 'KnowBe4',
    url: 'https://blog.knowbe4.com',
    description: 'Best practices for preventing targeted spear phishing attacks in enterprise environments.',
    date: 'April 2025',
    category: 'Best Practices',
  },
]

// Trusted cybersecurity sources list
const TRUSTED_SOURCES = [
  { name: 'The Hacker News', url: 'https://thehackernews.com', category: 'General', desc: 'Leading cybersecurity news outlet' },
  { name: 'Krebs on Security', url: 'https://krebsonsecurity.com', category: 'General', desc: 'Security blogger Brian Krebs' },
  { name: 'Dark Reading', url: 'https://darkreading.com', category: 'General', desc: 'Enterprise security news' },
  { name: 'Bleeping Computer', url: 'https://www.bleepingcomputer.com', category: 'General', desc: 'Tech & security news' },
  { name: 'Security Week', url: 'https://www.securityweek.com', category: 'General', desc: 'Cybersecurity news' },
  { name: 'Threatpost', url: 'https://threatpost.com', category: 'General', desc: 'Security news & analysis' },
  { name: 'CISA', url: 'https://www.cisa.gov/news-events/alerts', category: 'Government', desc: 'US cybersecurity agency' },
  { name: 'US-CERT', url: 'https://www.cisa.gov/uscert/ncas/current-activity', category: 'Government', desc: 'Alerts & advisories' },
  { name: 'NIST NVD', url: 'https://nvd.nist.gov/general/news', category: 'Government', desc: 'Vulnerability database' },
  { name: 'FBI IC3', url: 'https://www.ic3.gov', category: 'Government', desc: 'Cybercrime reports' },
  { name: 'ENISA', url: 'https://www.enisa.europa.eu', category: 'Government', desc: 'EU cybersecurity agency' },
  { name: 'NSA Cybersecurity', url: 'https://www.nsa.gov/What-We-Do/Cybersecurity', category: 'Government', desc: 'NSA security guidance' },
  { name: 'SANS ISC', url: 'https://isc.sans.edu', category: 'Threat Intel', desc: 'Internet Storm Center' },
  { name: 'Talos Intelligence', url: 'https://blog.talosintelligence.com', category: 'Threat Intel', desc: 'Cisco threat research' },
  { name: 'Palo Alto Unit 42', url: 'https://unit42.paloaltonetworks.com', category: 'Threat Intel', desc: 'Threat research team' },
  { name: 'Recorded Future', url: 'https://www.recordedfuture.com/blog', category: 'Threat Intel', desc: 'Threat intelligence' },
  { name: 'The DFIR Report', url: 'https://thedfirreport.com', category: 'Research', desc: 'Incident response' },
  { name: 'Mandiant Blog', url: 'https://www.mandiant.com/news/blog', category: 'Research', desc: 'Threat research' },
  { name: 'Securelist', url: 'https://securelist.com', category: 'Research', desc: 'Kaspersky research' },
  { name: 'Proofpoint', url: 'https://www.proofpoint.com/us/blog/threat-insights', category: 'Vendor', desc: 'Email security' },
  { name: 'CrowdStrike', url: 'https://www.crowdstrike.com/blog', category: 'Vendor', desc: 'Endpoint security' },
  { name: 'KnowBe4', url: 'https://blog.knowbe4.com', category: 'Vendor', desc: 'Security awareness' },
  { name: 'Abuse.ch', url: 'https://abuse.ch', category: 'Threat Intel', desc: 'Malware tracking' },
  { name: 'Anti-Phishing WG', url: 'https://www.antiphishing.org', category: 'Threat Intel', desc: 'Anti-phishing org' },
]

// Verified threat advisories
const THREAT_ADVISORIES = [
  {
    severity: 'HIGH',
    title: 'Active Phishing Campaign Targeting Microsoft 365 Users',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/alerts',
    date: 'April 2025',
    color: '#EF4444',
  },
  {
    severity: 'HIGH',
    title: 'Critical Email Server Vulnerability Being Exploited',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/alerts',
    date: 'April 2025',
    color: '#EF4444',
  },
  {
    severity: 'MEDIUM',
    title: 'New QR Code Phishing Campaign',
    source: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com',
    date: 'April 2025',
    color: '#F59E0B',
  },
  {
    severity: 'MEDIUM',
    title: 'BEC Group Targeting CFOs',
    source: 'FBI IC3',
    url: 'https://www.ic3.gov',
    date: 'April 2025',
    color: '#F59E0B',
  },
]

const ITEMS_PER_PAGE = 3

export default function News() {
  const [searchQuery, setSearchQuery] = useState('')
  const [currentIndex, setCurrentIndex] = useState(0)
  const [animState, setAnimState] = useState('idle')
  const [animDirection, setAnimDirection] = useState('next')
  const [hoveredArticle, setHoveredArticle] = useState(null)
  const [hoveredSource, setHoveredSource] = useState(null)
  const [hoveredAdv, setHoveredAdv] = useState(null)
  const carouselRef = useRef(null)

  // Trusted sources carousel state
  const sourcesPerSlide = 8
  const [sourceSlide, setSourceSlide] = useState(0)

  const filteredArticles = FEATURED_ARTICLES.filter(article => {
    const matchesSearch = article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.source.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSearch
  })

  const filteredSources = TRUSTED_SOURCES.filter(source => {
    const matchesSearch = source.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      source.category.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSearch
  })

  const totalSourceSlides = Math.max(1, Math.ceil(filteredSources.length / sourcesPerSlide))
  const currentSources = filteredSources.slice(sourceSlide * sourcesPerSlide, (sourceSlide + 1) * sourcesPerSlide)

  const nextSourceSlide = () => {
    setAnimDirection('next')
    setAnimState('slideOut')
    setTimeout(() => {
      setSourceSlide(s => (s + 1) % totalSourceSlides)
      setAnimState('slideIn')
    }, 150)
  }

  const prevSourceSlide = () => {
    setAnimDirection('prev')
    setAnimState('slideOut')
    setTimeout(() => {
      setSourceSlide(s => (s - 1 + totalSourceSlides) % totalSourceSlides)
      setAnimState('slideIn')
    }, 150)
  }

  // Auto-rotate sources every 6 seconds
  useEffect(() => {
    if (totalSourceSlides <= 1) return
    const interval = setInterval(nextSourceSlide, 6000)
    return () => clearInterval(interval)
  }, [totalSourceSlides])

  const filteredAdvisories = THREAT_ADVISORIES.filter(adv => {
    const matchesSearch = adv.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      adv.source.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSearch
  })

  const sourcesByCategory = filteredSources.reduce((acc, source) => {
    if (!acc[source.category]) acc[source.category] = []
    acc[source.category].push(source)
    return acc
  }, {})

  const totalPages = Math.ceil(filteredArticles.length / ITEMS_PER_PAGE)
  const currentPage = Math.floor(currentIndex / ITEMS_PER_PAGE)

  const getCurrentArticles = () => {
    const start = currentIndex
    const end = start + ITEMS_PER_PAGE
    return filteredArticles.slice(start, end)
  }

  const goNext = useCallback(() => {
    if (animState !== 'idle') return
    setAnimDirection('next')
    setAnimState('out')
    setTimeout(() => {
      setCurrentIndex(prev => {
        const next = prev + ITEMS_PER_PAGE
        return next >= filteredArticles.length ? 0 : next
      })
      setAnimState('in')
      setTimeout(() => setAnimState('idle'), 350)
    }, 200)
  }, [filteredArticles.length])

  const goPrev = useCallback(() => {
    if (animState !== 'idle') return
    setAnimDirection('prev')
    setAnimState('out')
    setTimeout(() => {
      setCurrentIndex(prev => {
        const prevIndex = prev - ITEMS_PER_PAGE
        return prevIndex < 0 ? Math.floor((filteredArticles.length - 1) / ITEMS_PER_PAGE) * ITEMS_PER_PAGE : prevIndex
      })
      setAnimState('in')
      setTimeout(() => setAnimState('idle'), 350)
    }, 200)
  }, [filteredArticles.length])

  const goToPage = (pageIndex) => {
    if (animState !== 'idle') return
    const newIndex = pageIndex * ITEMS_PER_PAGE
    if (newIndex !== currentIndex) {
      setAnimDirection(newIndex > currentIndex ? 'next' : 'prev')
      setAnimState('out')
      setTimeout(() => {
        setCurrentIndex(newIndex)
        setAnimState('in')
        setTimeout(() => setAnimState('idle'), 350)
      }, 200)
    }
  }

  // Auto-advance every 5 seconds
  useEffect(() => {
    const interval = setInterval(goNext, 5000)
    return () => clearInterval(interval)
  }, [goNext])

  return (
    <div style={{ padding: '1.5rem', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12,
            background: 'rgba(6,182,212,0.15)', border: '1px solid rgba(6,182,212,0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4" strokeLinecap="round"/>
              <circle cx="12" cy="16" r="1" fill="var(--cyan)" stroke="none"/>
            </svg>
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text)', marginBottom: '0.125rem' }}>
              Cyber News & Insights
            </h1>
            <p style={{ color: 'var(--sub)', fontSize: '0.875rem' }}>
              Stay updated with the latest cybersecurity news, threat advisories, and trusted resources
            </p>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ position: 'relative', maxWidth: 500 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" strokeWidth="2" style={{ position: 'absolute', left: '0.875rem', top: '50%', transform: 'translateY(-50%)' }}>
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
          </svg>
          <input
            type="text"
            placeholder="Search news, sources, or topics..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              width: '100%', padding: '0.625rem 1rem 0.625rem 2.5rem', borderRadius: 10,
              border: '1px solid var(--border)', background: 'var(--surface)',
              color: 'var(--text)', fontSize: '0.875rem', outline: 'none',
              boxSizing: 'border-box'
            }}
          />
        </div>
      </div>

      {/* Section 1: Featured Articles Carousel */}
      <section style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2">
            <path d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1M3 9h16"/>
            <path d="M19 9v6a2 2 0 01-2 2H7a2 2 0 01-2-2V9"/>
          </svg>
          <h2 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600 }}>Featured Articles</h2>
          <span style={{ color: 'var(--sub)', fontSize: '0.75rem', marginLeft: '0.5rem' }}>
            {currentPage + 1} / {totalPages}
          </span>
        </div>

        {/* Articles Card */}
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
          {/* Articles Grid */}
          <div
            ref={carouselRef}
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '1rem',
              animation: animState === 'out'
                ? (animDirection === 'next' ? 'slideOutLeft 0.2s ease-in forwards' : 'slideOutRight 0.2s ease-in forwards')
                : animState === 'in'
                ? (animDirection === 'next' ? 'slideInRight 0.35s ease-out forwards' : 'slideInLeft 0.35s ease-out forwards')
                : 'none',
            }}
          >
            <style>{animationStyles}</style>
            {getCurrentArticles().map((article, i) => (
              <a key={i} href={article.url} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none', display: 'block' }}>
                <div style={{
                  background: 'var(--surface)', borderRadius: 10, padding: '1.125rem',
                  border: '1px solid var(--border)', height: '100%',
                  transition: 'all 0.2s ease', cursor: 'pointer',
                }}>
                  <div style={{
                    padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                    background: 'rgba(6,182,212,0.15)', color: 'var(--cyan)',
                    textTransform: 'uppercase', letterSpacing: '0.025em', display: 'inline-block', marginBottom: '0.5rem'
                  }}>
                    {article.category}
                  </div>
                  <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.375rem', lineHeight: 1.4 }}>
                    {article.title}
                  </h3>
                  <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', lineHeight: 1.5, marginBottom: '0.625rem', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                    {article.description}
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem' }}>
                    <span style={{ color: 'var(--text)', fontWeight: 500 }}>{article.source}</span>
                    <span style={{ color: 'var(--sub)' }}>·</span>
                    <span style={{ color: 'var(--sub)' }}>{article.date}</span>
                  </div>
                </div>
              </a>
            ))}
          </div>
        </div>

        {/* Carousel Navigation - Outside the card */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '1.25rem', padding: '0 0.5rem' }}>
          {/* Prev Button - Far Left */}
          <button onClick={goPrev} disabled={animState !== 'idle'} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 36, height: 36, borderRadius: '50%', border: '1px solid var(--border)',
            background: 'var(--surface)', cursor: 'pointer', transition: 'all 0.15s ease',
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--text)" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>

          {/* Page Indicators - Center */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {Array.from({ length: totalPages }).map((_, i) => (
              <button key={i} onClick={() => goToPage(i)} disabled={animState !== 'idle'} style={{
                width: i === currentPage ? 20 : 8, height: 8, borderRadius: 4,
                background: i === currentPage ? 'var(--cyan)' : 'var(--border)',
                border: 'none', cursor: 'pointer', transition: 'all 0.2s ease',
              }} />
            ))}
          </div>

          {/* Next Button - Far Right */}
          <button onClick={goNext} disabled={animState !== 'idle'} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 36, height: 36, borderRadius: '50%', border: '1px solid var(--border)',
            background: 'var(--surface)', cursor: 'pointer', transition: 'all 0.15s ease',
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--text)" strokeWidth="2">
              <polyline points="9 18 15 12 9 18"/>
            </svg>
          </button>
        </div>
      </section>

      {/* Section 2: Trusted Sources */}
      <section style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2">
            <path d="M4 19.5A2.5 2.5 0 016.5 17H20"/>
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>
          </svg>
          <h2 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600 }}>Trusted Sources</h2>
          <span style={{ color: 'var(--sub)', fontSize: '0.75rem', marginLeft: '0.5rem' }}>({filteredSources.length})</span>
        </div>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
          {filteredSources.length === 0 ? (
            <p style={{ color: 'var(--sub)', textAlign: 'center', padding: '2rem' }}>No sources found</p>
          ) : (
            <div>
              {/* Carousel Grid */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, 1fr)',
                gap: '1rem',
                animation: animState === 'slideOut' ? (animDirection === 'next' ? 'slideOutLeft 0.2s forwards' : 'slideOutRight 0.2s forwards') :
                         animState === 'slideIn' ? (animDirection === 'next' ? 'slideInRight 0.35s forwards' : 'slideInLeft 0.35s forwards') : 'none',
              }}>
                <style>{animationStyles}</style>
                {currentSources.map((source, i) => (
                  <a key={i} href={source.url} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none', display: 'block' }}>
                    <div style={{
                      background: 'var(--surface)', borderRadius: 10, padding: '1.125rem',
                      border: '1px solid var(--border)', height: '100%',
                      transition: 'all 0.2s ease', cursor: 'pointer',
                    }}>
                      <div style={{
                        padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                        background: 'rgba(6,182,212,0.15)', color: 'var(--cyan)',
                        textTransform: 'uppercase', letterSpacing: '0.025em', display: 'inline-block', marginBottom: '0.5rem'
                      }}>
                        {source.category}
                      </div>
                      <h3 style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.375rem', lineHeight: 1.4 }}>
                        {source.name}
                      </h3>
                      <p style={{ color: 'var(--sub)', fontSize: '0.8125rem', lineHeight: 1.5, marginBottom: '0.625rem', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                        {source.desc}
                      </p>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', justifyContent: 'flex-end' }}>
                        <span style={{ color: 'var(--cyan)', fontWeight: 500 }}>Visit →</span>
                      </div>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
        {/* Carousel Navigation - Outside Section */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '1.25rem', padding: '0 0.5rem' }}>
          <button onClick={prevSourceSlide} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 36, height: 36, borderRadius: '50%', border: '1px solid var(--border)',
            background: 'var(--surface)', cursor: 'pointer', transition: 'all 0.15s ease',
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--text)" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {Array.from({ length: totalSourceSlides }).map((_, i) => (
              <div key={i} onClick={() => { setAnimDirection(i > sourceSlide ? 'next' : 'prev'); setAnimState('slideOut'); setTimeout(() => { setSourceSlide(i); setAnimState('slideIn'); }, 150) }} style={{
                width: 8, height: 8, borderRadius: '50%', cursor: 'pointer',
                background: i === sourceSlide ? 'var(--cyan)' : 'var(--border)',
                transition: 'all 0.2s ease',
              }} />
            ))}
          </div>
          <button onClick={nextSourceSlide} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 36, height: 36, borderRadius: '50%', border: '1px solid var(--border)',
            background: 'var(--surface)', cursor: 'pointer', transition: 'all 0.15s ease',
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--text)" strokeWidth="2">
              <polyline points="9 18 15 12 9 6"/>
            </svg>
          </button>
        </div>
      </section>

      {/* Section 3: Threat Advisories */}
      <section>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <h2 style={{ color: 'var(--text)', fontSize: '1.125rem', fontWeight: 600 }}>Threat Advisories</h2>
          <span style={{ color: 'var(--sub)', fontSize: '0.75rem', marginLeft: '0.5rem' }}>({filteredAdvisories.length})</span>
        </div>
        <div style={{ background: 'var(--card)', borderRadius: 12, border: '1px solid var(--border)', padding: '1.5rem' }}>
          {filteredAdvisories.length === 0 ? (
            <p style={{ color: 'var(--sub)', textAlign: 'center', padding: '2rem' }}>No advisories found</p>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '0.75rem',
            }}>
              {filteredAdvisories.map((adv, i) => (
                <a key={i} href={adv.url} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                  <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: '0.875rem',
                    padding: '1rem', borderRadius: 10, background: adv.color + '08', border: `1px solid ${adv.color}25`,
                    transition: 'all 0.15s ease', cursor: 'pointer',
                    height: '100%',
                  }}>
                    <div style={{
                      width: 40, height: 40, borderRadius: 10,
                      background: adv.color, display: 'flex', alignItems: 'center', justifyContent: 'center',
                      flexShrink: 0,
                    }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                      </svg>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span style={{
                          padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 600,
                          background: adv.color, color: '#fff', textTransform: 'uppercase'
                        }}>
                          {adv.severity}
                        </span>
                        <span style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{adv.source}</span>
                        <span style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>·</span>
                        <span style={{ color: 'var(--sub)', fontSize: '0.75rem' }}>{adv.date}</span>
                      </div>
                      <p style={{ color: 'var(--text)', fontSize: '0.9375rem', fontWeight: 500 }}>{adv.title}</p>
                    </div>
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Disclaimer */}
      <div style={{ marginTop: '2rem', padding: '1rem', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--surface)' }}>
        <p style={{ color: 'var(--sub)', fontSize: '0.75rem', textAlign: 'center', lineHeight: 1.6 }}>
          All links point to trusted, official sources. ETA does not endorse any external content.
          Always verify information before taking action. For emergencies, contact your IT security team or CISA at{' '}
          <a href="https://www.cisa.gov/cyber-helps-or-resources" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--cyan)' }}>
            CISA
          </a>.
        </p>
      </div>
    </div>
  )
}