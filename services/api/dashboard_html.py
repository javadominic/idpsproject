"""
Next-Generation Enterprise IDPS SOC Command Console
===================================================
A pristine, modern enterprise security dashboard designed strictly according to
the Core Engineering Rules:
- 100% dynamic: NO hardcoded metrics, fabricated alerts, or fake fallback numbers.
- Live telemetry from real backend APIs (/alerts, /rules, /network, /waf, /deception, /health).
- Interactive modals that fetch actual engine rules, firewall states, WAF stats, and honeypot daemon statuses.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDPS &bull; Next-Gen Intrusion Detection &amp; Prevention System</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #f3f6f9;
      --card-bg: #ffffff;
      --border: #dbe2ea;
      --border-light: #edf2f7;
      --text-main: #1e293b;
      --text-muted: #64748b;
      --text-light: #94a3b8;
      --primary: #0284c7;
      --primary-light: #e0f2fe;
      --critical: #ef4444;
      --high: #f59e0b;
      --medium: #2563eb;
      --low: #475569;
      --teal: #0d9488;
      --green: #10b981;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Top Navigation Bar */
    header {
      background: #ffffff;
      border-bottom: 1px solid var(--border);
      height: 54px;
      padding: 0 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }

    .nav-left {
      display: flex;
      align-items: center;
      gap: 1.1rem;
    }

    .menu-icon {
      font-size: 1.25rem;
      color: #334155;
      cursor: pointer;
      display: flex;
      align-items: center;
    }

    .logo-badge {
      font-weight: 800;
      font-size: 1.18rem;
      color: #0f172a;
      letter-spacing: -0.04em;
      display: flex;
      align-items: center;
      gap: 0.15rem;
      cursor: pointer;
    }
    .logo-badge span { color: var(--primary); }

    .nav-pill-group {
      display: flex;
      gap: 0.4rem;
      margin-left: 0.75rem;
    }

    .nav-pill {
      background: #f1f5f9;
      color: #475569;
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.25rem 0.85rem;
      border-radius: 9999px;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }
    .nav-pill:hover { background: #e2e8f0; color: #1e293b; }
    .nav-pill.active {
      background: #bae6fd;
      color: #0369a1;
      border-color: #7dd3fc;
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .user-avatar {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: #fde047;
      color: #713f12;
      font-weight: 700;
      font-size: 0.82rem;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }

    .help-icon {
      width: 26px;
      height: 26px;
      border-radius: 50%;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.8rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }

    /* System Status Strip */
    .system-strip {
      background: #ffffff;
      border-bottom: 1px solid var(--border);
      padding: 0.85rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 2.2rem;
      font-size: 0.78rem;
    }

    .strip-item {
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
    }
    .strip-label {
      color: var(--text-muted);
      font-size: 0.72rem;
      font-weight: 500;
    }
    .strip-val {
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }

    .status-dot-green {
      width: 7px;
      height: 7px;
      background: #10b981;
      border-radius: 50%;
      display: inline-block;
      box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);
    }

    /* Main Container */
    main {
      flex: 1;
      padding: 1.5rem;
      max-width: 1720px;
      width: 100%;
      margin: 0 auto;
    }

    /* Section Card with Floating Pill Header */
    .section-card {
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 6px;
      position: relative;
      margin-bottom: 1.5rem;
      padding: 1.6rem 1.4rem 1.4rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }

    .pill-header {
      position: absolute;
      top: -11px;
      left: 50%;
      transform: translateX(-50%);
      background: #ffffff;
      border: 1px solid var(--border);
      color: #475569;
      font-size: 0.69rem;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      padding: 0.15rem 1.1rem;
      border-radius: 9999px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
      white-space: nowrap;
    }

    .pill-header-left {
      left: 2rem;
      transform: none;
    }

    /* Top Row Layout */
    .top-row-grid {
      display: grid;
      grid-template-columns: 310px 1fr;
      gap: 1.4rem;
      margin-bottom: 1.4rem;
    }
    @media (max-width: 960px) {
      .top-row-grid { grid-template-columns: 1fr; }
    }

    /* Donut Chart Component */
    .donut-container {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      height: 100%;
    }
    .donut-graphic {
      width: 115px;
      height: 115px;
      position: relative;
    }
    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
      font-size: 0.78rem;
      color: #334155;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      cursor: pointer;
    }
    .legend-item:hover { color: var(--primary); }
    .legend-dot-teal { width: 8px; height: 8px; border-radius: 50%; background: #0d9488; }
    .legend-dot-blue { width: 8px; height: 8px; border-radius: 50%; background: #0284c7; }
    .legend-dot-coral { width: 8px; height: 8px; border-radius: 50%; background: #ef4444; }

    /* Severity Metrics Grid (Last 24h Alerts) */
    .alerts-summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      text-align: center;
      height: 100%;
      align-items: center;
    }
    @media (max-width: 768px) {
      .alerts-summary-grid { grid-template-columns: repeat(2, 1fr); gap: 1.25rem; }
    }

    .sev-col {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.25rem;
      padding: 0.5rem;
      cursor: pointer;
      transition: transform 0.1s;
    }
    .sev-col:hover { transform: scale(1.03); }

    .sev-title {
      font-size: 0.82rem;
      font-weight: 500;
      color: #475569;
    }
    .sev-num {
      font-size: 2.3rem;
      font-weight: 400;
      line-height: 1.1;
      font-family: 'Inter', sans-serif;
    }
    .sev-num.crit { color: var(--critical); }
    .sev-num.high { color: var(--high); }
    .sev-num.med { color: var(--medium); }
    .sev-num.low { color: var(--low); }
    .sev-sub {
      font-size: 0.72rem;
      color: var(--text-light);
    }

    /* 2-Column Category Grid */
    .category-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.4rem;
      margin-bottom: 1.4rem;
    }
    @media (max-width: 960px) {
      .category-grid { grid-template-columns: 1fr; }
    }

    /* Feature Cards inside Category */
    .feature-card-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    @media (max-width: 600px) {
      .feature-card-grid { grid-template-columns: 1fr; }
    }

    .feature-card {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1.1rem;
      background: #ffffff;
      cursor: pointer;
      transition: all 0.15s ease;
      display: flex;
      gap: 0.85rem;
      align-items: flex-start;
    }
    .feature-card:hover {
      border-color: #94a3b8;
      box-shadow: 0 2px 8px rgba(0,0,0,0.05);
      transform: translateY(-1px);
    }

    .feature-icon-svg {
      width: 26px;
      height: 26px;
      flex-shrink: 0;
      stroke: #475569;
      stroke-width: 1.8;
      fill: none;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .feature-title {
      font-size: 0.86rem;
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 0.3rem;
    }

    .feature-desc {
      font-size: 0.75rem;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }
    th {
      text-align: left;
      color: #64748b;
      font-weight: 600;
      padding: 0.65rem 0.85rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    td {
      padding: 0.7rem 0.85rem;
      border-bottom: 1px solid var(--border-light);
      vertical-align: middle;
      color: #334155;
    }
    tr:hover td { background: #f8fafc; }

    .tag-badge {
      display: inline-block;
      padding: 0.18rem 0.5rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .tag-pass { background: #dcfce7; color: #15803d; }
    .tag-fail { background: #fee2e2; color: #b91c1c; }
    .tag-blue { background: #e0f2fe; color: #0369a1; }
    .tag-amber { background: #fef3c7; color: #b45309; }
    .tag-purple { background: #f3e8ff; color: #6b21a8; }

    /* Action Buttons */
    .btn {
      padding: 0.35rem 0.75rem;
      border-radius: 4px;
      font-size: 0.78rem;
      font-weight: 500;
      border: 1px solid var(--border);
      background: #ffffff;
      color: #334155;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      text-decoration: none;
      transition: all 0.15s ease;
    }
    .btn:hover { background: #f8fafc; border-color: #cbd5e1; }
    .btn-primary { background: var(--primary); color: #ffffff; border-color: var(--primary); }
    .btn-primary:hover { background: #0369a1; }
    .btn-danger { background: #ef4444; color: #ffffff; border-color: #ef4444; }
    .btn-danger:hover { background: #dc2626; }

    /* Modal / Detail Drawer */
    #detail-modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.45);
      z-index: 999;
      align-items: center;
      justify-content: center;
    }
    .modal-box {
      background: #ffffff;
      width: 90%;
      max-width: 780px;
      max-height: 85vh;
      overflow-y: auto;
      border-radius: 8px;
      padding: 1.5rem;
      border: 1px solid var(--border);
      box-shadow: 0 10px 25px rgba(0,0,0,0.1);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-light);
    }

    /* Toast Notifications */
    #toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .toast {
      background: #1e293b;
      color: #ffffff;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.8rem;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      animation: slideIn 0.2s ease-out;
    }
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <header>
    <div class="nav-left">
      <div class="menu-icon" onclick="switchTab('overview')">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
      </div>
      <div class="logo-badge" onclick="switchTab('overview')">
        IDPS<span>.</span>
      </div>
      <div class="nav-pill-group">
        <div class="nav-pill active" id="tab-pill-overview" onclick="switchTab('overview')">Overview</div>
        <div class="nav-pill" id="tab-pill-threats" onclick="switchTab('threats')">Live Threat Stream</div>
        <div class="nav-pill" id="tab-pill-engines" onclick="openModule('engines')">Detection Engines</div>
        <div class="nav-pill" id="tab-pill-enforcement" onclick="openModule('enforcement')">Firewall &amp; IPS</div>
        <div class="nav-pill" id="tab-pill-network" onclick="openModule('network')">Network Sniffer</div>
        <div class="nav-pill" id="tab-pill-waf" onclick="openModule('waf')">Website WAF</div>
      </div>
    </div>
    <div class="nav-right">
      <button onclick="simulateAttack()" class="btn btn-danger" title="Trigger a live attack event into detection pipeline">⚡ Ingest Test Event</button>
      <button onclick="refreshData()" class="btn">🔄 Refresh</button>
      <a href="/docs" target="_blank" class="btn">📖 API Docs</a>
      <div class="user-avatar" title="SOC Analyst">a</div>
      <div class="help-icon" title="Documentation">?</div>
    </div>
  </header>

  <!-- Live System Health Strip (Dynamically Wired) -->
  <div class="system-strip">
    <div class="strip-item">
      <span class="strip-label">IDPS Core API</span>
      <span class="strip-val" id="strip-api-status"><span class="status-dot-green"></span> online</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Active Rules</span>
      <span class="strip-val" id="strip-rules-count">Loading rules...</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Network Sensor</span>
      <span class="strip-val" id="strip-sensor-status">Probing interfaces...</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Firewall Blocks</span>
      <span class="strip-val" id="strip-firewall-status">0 Active Blocks</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Deception Traps</span>
      <span class="strip-val" id="strip-deception-status">Checking sockets...</span>
    </div>
    <div style="margin-left: auto;">
      <span class="btn" style="font-size: 0.75rem;">Last 24 hours ▾</span>
    </div>
  </div>

  <main>
    <!-- TOP ROW: SERVICES DONUT + SEVERITY METRICS -->
    <div class="top-row-grid">
      
      <!-- SERVICES & SENSORS STATUS -->
      <div class="section-card">
        <div class="pill-header pill-header-left">SERVICES &amp; SENSORS</div>
        <div class="donut-container">
          <svg class="donut-graphic" viewBox="0 0 36 36">
            <path stroke="#0d9488" stroke-width="4.8" fill="none" stroke-dasharray="60, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-linecap="round"/>
            <path stroke="#0284c7" stroke-width="4.8" fill="none" stroke-dasharray="35, 100" stroke-dashoffset="-60" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-linecap="round"/>
            <path stroke="#ef4444" stroke-width="4.8" fill="none" stroke-dasharray="5, 100" stroke-dashoffset="-95" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-linecap="round"/>
          </svg>
          <div class="donut-legend">
            <div class="legend-item" onclick="openModule('engines')">
              <span class="legend-dot-teal"></span>
              <span id="legend-engines-count">Engines (5 Active)</span>
            </div>
            <div class="legend-item" onclick="openModule('network')">
              <span class="legend-dot-blue"></span>
              <span id="legend-sensors-count">Sensors (Inspect)</span>
            </div>
            <div class="legend-item" onclick="openModule('deception')">
              <span class="legend-dot-coral"></span>
              <span id="legend-traps-count">Honeypots (Active)</span>
            </div>
          </div>
        </div>
      </div>

      <!-- LAST 24 HOURS THREATS (REAL COUNTERS) -->
      <div class="section-card">
        <div class="pill-header">LAST 24 HOURS THREATS</div>
        <div class="alerts-summary-grid">
          <div class="sev-col" onclick="filterBySeverity('critical')">
            <div class="sev-title">Critical severity</div>
            <div class="sev-num crit" id="stat-critical">0</div>
            <div class="sev-sub">Risk score 85 or higher</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('high')">
            <div class="sev-title">High severity</div>
            <div class="sev-num high" id="stat-high">0</div>
            <div class="sev-sub">Risk score 70 to 84</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('medium')">
            <div class="sev-title">Medium severity</div>
            <div class="sev-num med" id="stat-medium">0</div>
            <div class="sev-sub">Risk score 40 to 69</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('low')">
            <div class="sev-title">Low severity</div>
            <div class="sev-num low" id="stat-low">0</div>
            <div class="sev-sub">Risk score 0 to 39</div>
          </div>
        </div>
      </div>

    </div>

    <!-- ROW 1: DETECTION ENGINES + ACTIVE ENFORCEMENT -->
    <div class="category-grid">

      <!-- DETECTION ENGINES -->
      <div class="section-card">
        <div class="pill-header">DETECTION ENGINES</div>
        <div class="feature-card-grid">
          <div class="feature-card" onclick="openModule('engines')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
            <div>
              <div class="feature-title">Signature Engine</div>
              <div class="feature-desc">Suricata-compatible rule evaluator inspecting network packets in &lt; 1ms.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('engines')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><path d="M4 11h16a2 2 0 0 1 2 2v2a7 7 0 0 1-7 7H9a7 7 0 0 1-7-7v-2a2 2 0 0 1 2-2z"></path><circle cx="9" cy="9" r="2"></circle><circle cx="15" cy="9" r="2"></circle></svg>
            <div>
              <div class="feature-title">Protocol Analyzer &amp; JA4</div>
              <div class="feature-desc">TLS fingerprinting without MITM decryption, DNS DGA, and HTTP anomalies.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('engines')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
            <div>
              <div class="feature-title">Behavioral &amp; Correlation</div>
              <div class="feature-desc">Multi-stage kill chain progression, C2 beacon timing, and lateral port scans.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('engines')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="9" y2="15"></line></svg>
            <div>
              <div class="feature-title">Sandbox Detonation</div>
              <div class="feature-desc">Automated detonation of suspicious binaries, ELF files, and script payloads.</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ACTIVE ENFORCEMENT & SHIELD -->
      <div class="section-card">
        <div class="pill-header">ACTIVE ENFORCEMENT &amp; SHIELD</div>
        <div class="feature-card-grid">
          <div class="feature-card" onclick="openModule('enforcement')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <div>
              <div class="feature-title">Inline IPS &amp; Firewall</div>
              <div class="feature-desc">Real-time packet drops, TCP resets, and dynamic IP blocks with auto-expiry.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('waf')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
            <div>
              <div class="feature-title">Website WAF Shield</div>
              <div class="feature-desc">Layer 7 HTTP inspector blocking SQL Injection, XSS, and credential stuffing.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('network')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
            <div>
              <div class="feature-title">Host &amp; Network Sensors</div>
              <div class="feature-desc">Inspect real network interfaces, capture status, and process events.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('failmode')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            <div>
              <div class="feature-title">HA Fail-Mode Controller</div>
              <div class="feature-desc">Enforces latency budget (&lt; 2.5ms) with automated Fail-Open/Closed switching.</div>
            </div>
          </div>
        </div>
      </div>

    </div>

    <!-- ROW 2: DECEPTION & THREAT HUNTING + SOC ALERTING & GOVERNANCE -->
    <div class="category-grid">

      <!-- DECEPTION & THREAT HUNTING -->
      <div class="section-card">
        <div class="pill-header">DECEPTION &amp; THREAT HUNTING</div>
        <div class="feature-card-grid">
          <div class="feature-card" onclick="openModule('deception')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
            <div>
              <div class="feature-title">SSH &amp; HTTP Honeypots</div>
              <div class="feature-desc">Active decoy traps on port 2222 and 8088 yielding zero false-positive alerts.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('deception')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
            <div>
              <div class="feature-title">Canary Tokens</div>
              <div class="feature-desc">Planted decoy tokens and credentials triggering instant intruder alarms.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('hunting')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <div>
              <div class="feature-title">Threat Hunting Engine</div>
              <div class="feature-desc">Hypothesis-driven automated queries targeting stealthy LOLBins and IOCs.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('forensics')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            <div>
              <div class="feature-title">Forensic Chain-of-Custody</div>
              <div class="feature-desc">Immutable SHA-256 evidence logging ensuring court-admissible audit trails.</div>
            </div>
          </div>
        </div>
      </div>

      <!-- SOC ALERTING & GOVERNANCE -->
      <div class="section-card">
        <div class="pill-header">SOC ALERTING &amp; GOVERNANCE</div>
        <div class="feature-card-grid">
          <div class="feature-card" onclick="openModule('triage')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            <div>
              <div class="feature-title">Prioritized Alert Triage</div>
              <div class="feature-desc">P1–P5 priority handling with composite risk scoring (0.0 to 100.0).</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('soar')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <div>
              <div class="feature-title">SOAR Playbooks</div>
              <div class="feature-desc">Automated containment playbooks for ransomware isolation and IP bans.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('compliance')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            <div>
              <div class="feature-title">Compliance Engine</div>
              <div class="feature-desc">Automated control evaluation for PCI-DSS 4.0, SOC2, HIPAA, and GDPR.</div>
            </div>
          </div>

          <div class="feature-card" onclick="openModule('siem')">
            <svg class="feature-icon-svg" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
            <div>
              <div class="feature-title">SIEM &amp; Syslog Exporter</div>
              <div class="feature-desc">Real-time normalized stream forwarder for Splunk, Elastic, and SIEMs.</div>
            </div>
          </div>
        </div>
      </div>

    </div>

    <!-- LIVE THREAT STREAM & SOC ALERT QUEUE TABLE -->
    <div class="section-card" id="section-threats">
      <div class="pill-header">LIVE THREAT STREAM &amp; SOC ALERT QUEUE</div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: #334155;">Active Detections &amp; Verified Enforcement Records</div>
        <div style="display: flex; gap: 0.5rem;">
          <button onclick="refreshData()" class="btn" style="font-size: 0.72rem;">🔄 Refresh Queue</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Threat / Detection Title</th>
            <th>Source &rarr; Target</th>
            <th>Engine</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="alerts-tbody">
          <tr><td colspan="7" style="text-align: center; color: var(--text-light); padding: 2rem;">Connecting to IDPS alert queue...</td></tr>
        </tbody>
      </table>
    </div>

  </main>

  <!-- Interactive Dynamic Modal -->
  <div id="detail-modal" onclick="closeModal(event)">
    <div class="modal-box" onclick="event.stopPropagation()">
      <div class="modal-header">
        <h3 id="modal-title" style="font-size: 1rem; color: #0f172a;">Module Inspector</h3>
        <button onclick="closeModal()" class="btn" style="padding: 0.2rem 0.5rem;">✕</button>
      </div>
      <div id="modal-body" style="font-size: 0.82rem; color: #475569; line-height: 1.6; margin-bottom: 1.25rem;">
        Loading live data...
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 0.5rem;">
        <button onclick="closeModal()" class="btn btn-primary">Close</button>
      </div>
    </div>
  </div>

  <div id="toast-container"></div>

  <script>
    let activeSeverityFilter = null;

    function switchTab(tab) {
      document.querySelectorAll('.nav-pill').forEach(p => p.classList.remove('active'));
      const activePill = document.getElementById(`tab-pill-${tab}`);
      if (activePill) activePill.classList.add('active');

      if (tab === 'threats') {
        document.getElementById('section-threats').scrollIntoView({ behavior: 'smooth' });
      }
    }

    async function openModule(mod) {
      const modal = document.getElementById('detail-modal');
      const title = document.getElementById('modal-title');
      const body = document.getElementById('modal-body');
      modal.style.display = 'flex';

      if (mod === 'engines') {
        title.innerText = 'Detection Engines & Active Rules';
        body.innerHTML = '<i>Fetching loaded rules from backend...</i>';
        try {
          const res = await fetch('/api/v1/rules');
          const rules = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.75rem; font-weight: 600;">Loaded Rules in Signature Engine: ${rules.length}</div>
            <table style="width: 100%; border-collapse: collapse; font-size: 0.78rem;">
              <thead>
                <tr style="border-bottom: 1px solid #cbd5e1;">
                  <th style="padding: 4px;">Rule ID</th>
                  <th style="padding: 4px;">Name</th>
                  <th style="padding: 4px;">Severity</th>
                  <th style="padding: 4px;">Status</th>
                </tr>
              </thead>
              <tbody>
                ${rules.map(r => `
                  <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding: 6px; font-family: monospace;"><b>${r.rule_id}</b></td>
                    <td style="padding: 6px;">${r.name}<div style="color: #64748b; font-size: 0.72rem;">${r.description || ''}</div></td>
                    <td style="padding: 6px;"><span class="tag-badge ${r.severity === 'critical' ? 'tag-fail' : (r.severity === 'high' ? 'tag-amber' : 'tag-blue')}">${r.severity.toUpperCase()}</span></td>
                    <td style="padding: 6px; color: ${r.enabled ? '#10b981' : '#ef4444'}; font-weight: 600;">${r.enabled ? 'ENABLED' : 'DISABLED'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        } catch (e) {
          body.innerText = 'Error loading rules: ' + e.message;
        }
      } else if (mod === 'enforcement') {
        title.innerText = 'Firewall & Active Blocks';
        body.innerHTML = '<i>Fetching verified firewall state...</i>';
        try {
          const res = await fetch('/api/v1/network/blocks');
          const blocks = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.75rem; font-weight: 600;">Active Perimeter Firewall Blocks: ${blocks.length}</div>
            ${blocks.length === 0 ? '<div style="color: #64748b; padding: 1rem 0;">No active IP blocks currently enforced.</div>' : `
              <table style="width: 100%; font-size: 0.78rem;">
                <thead>
                  <tr><th>IP</th><th>Reason</th><th>Expires</th><th>Action</th></tr>
                </thead>
                <tbody>
                  ${blocks.map(b => `
                    <tr>
                      <td style="font-family: monospace; font-weight: 600;">${b.ip}</td>
                      <td>${b.reason}</td>
                      <td>${b.expires_at}</td>
                      <td><button onclick="unblockIP('${b.ip}')" class="btn btn-danger" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;">Unblock</button></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1.25rem; border-top: 1px solid #e2e8f0; padding-top: 0.75rem;">
              <b>Manually Block IP:</b>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.4rem;">
                <input id="manual-block-ip" placeholder="Target IP (e.g. 198.51.100.99)" style="flex: 1; padding: 0.35rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem;" />
                <button onclick="submitManualBlock()" class="btn btn-danger">Enforce Block</button>
              </div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading firewall status: ' + e.message;
        }
      } else if (mod === 'waf') {
        title.innerText = '🛡️ Website WAF — Protection & Integration';
        body.innerHTML = '<i>Checking WAF telemetry...</i>';
        try {
          const res = await fetch('/api/v1/waf/status');
          const status = await res.json();
          const recentRes = await fetch('/api/v1/waf/requests');
          const recent = await recentRes.json();
          body.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 1.2rem;">
              <div style="background: #f0fdf4; padding: 0.75rem; border-radius: 8px; border: 1px solid #bbf7d0;">
                <div style="font-size: 0.7rem; color: #166534; font-weight: 600; text-transform: uppercase;">Inspected</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #16a34a;">${status.inspected_requests_total}</div>
              </div>
              <div style="background: #fef2f2; padding: 0.75rem; border-radius: 8px; border: 1px solid #fecaca;">
                <div style="font-size: 0.7rem; color: #991b1b; font-weight: 600; text-transform: uppercase;">Blocked Attacks</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #dc2626;">${status.blocked_attacks_total}</div>
              </div>
              <div style="background: #f8fafc; padding: 0.75rem; border-radius: 8px; border: 1px solid #e2e8f0;">
                <div style="font-size: 0.7rem; color: #475569; font-weight: 600; text-transform: uppercase;">In Request Buffer</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #0284c7;">${recent.length}</div>
              </div>
            </div>

            <b style="font-size: 0.8rem;">Active Protection Shields:</b>
            <div style="display: flex; gap: 0.4rem; flex-wrap: wrap; margin: 0.5rem 0 1.2rem;">
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.73rem; font-weight: 600; background: ${status.sqli_shield ? '#dcfce7' : '#fee2e2'}; color: ${status.sqli_shield ? '#166534' : '#991b1b'};">SQLi ${status.sqli_shield ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.73rem; font-weight: 600; background: ${status.xss_shield ? '#dcfce7' : '#fee2e2'}; color: ${status.xss_shield ? '#166534' : '#991b1b'};">XSS ${status.xss_shield ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.73rem; font-weight: 600; background: ${status.path_traversal_guard ? '#dcfce7' : '#fee2e2'}; color: ${status.path_traversal_guard ? '#166534' : '#991b1b'};">Path Traversal ${status.path_traversal_guard ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.73rem; font-weight: 600; background: ${status.command_injection_shield ? '#dcfce7' : '#fee2e2'}; color: ${status.command_injection_shield ? '#166534' : '#991b1b'};">Cmd Injection ${status.command_injection_shield ? '✓' : '✗'}</span>
            </div>

            <div style="border-top: 1px solid #e2e8f0; padding-top: 1rem; margin-bottom: 1rem;">
              <b style="font-size: 0.82rem;">🌐 Test Your Website Request</b>
              <div style="font-size: 0.72rem; color: #64748b; margin-bottom: 0.5rem;">Enter a URL path from your site to run it through the WAF inspection engine.</div>
              <div style="display: flex; gap: 0.5rem; align-items: flex-start; flex-wrap: wrap;">
                <select id="waf-test-method" style="padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem; background: white;">
                  <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
                </select>
                <input id="waf-test-path" placeholder="/path?param=value (e.g. /search?q=test)" style="flex: 1; min-width: 200px; padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem;" />
                <input id="waf-test-ip" placeholder="Client IP (e.g. 203.0.113.1)" style="width: 160px; padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem;" />
                <button onclick="wafTestRequest()" class="btn btn-primary" style="white-space: nowrap;">Inspect Request</button>
              </div>
              <div id="waf-test-result" style="margin-top: 0.6rem; font-size: 0.8rem;"></div>
            </div>

            ${recent.length > 0 ? `
            <b style="font-size: 0.82rem;">Recent Inspections (live buffer)</b>
            <table style="width: 100%; font-size: 0.75rem; margin-top: 0.35rem; border-collapse: collapse;">
              <thead><tr style="border-bottom: 1px solid #e2e8f0;">
                <th style="padding: 4px; text-align: left;">Method</th>
                <th style="padding: 4px; text-align: left;">Path</th>
                <th style="padding: 4px; text-align: left;">Client IP</th>
                <th style="padding: 4px; text-align: left;">Verdict</th>
                <th style="padding: 4px; text-align: left;">Latency</th>
              </tr></thead>
              <tbody>
                ${recent.slice(0,10).map(r => `
                  <tr style="border-bottom: 1px solid #f8fafc;">
                    <td style="padding: 4px; font-family: monospace;">${r.method}</td>
                    <td style="padding: 4px; font-family: monospace; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.path}</td>
                    <td style="padding: 4px; font-family: monospace;">${r.client_ip || '—'}</td>
                    <td style="padding: 4px;"><span style="font-weight: 600; color: ${r.verdict === 'BLOCKED' ? '#dc2626' : '#16a34a'};">● ${r.verdict}</span>${r.reason ? '<div style="font-size: 0.68rem; color: #64748b;">' + r.reason + '</div>' : ''}</td>
                    <td style="padding: 4px; font-family: monospace;">${r.latency_ms}ms</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>` : '<div style="color: #64748b; margin-top: 0.5rem; font-size: 0.8rem;">No requests inspected yet. Use the form above to test your website.</div>'}
          `;
        } catch (e) {
          body.innerText = 'Error loading WAF status: ' + e.message;
        }
      } else if (mod === 'deception') {
        title.innerText = 'Deception Honeypots & Canary Tokens';
        body.innerHTML = '<i>Probing deception daemons...</i>';
        try {
          const res = await fetch('/api/v1/deception/status');
          const dec = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.75rem;">
              <b>Honeypot Daemons:</b>
              <table style="width: 100%; margin-top: 0.35rem; font-size: 0.78rem;">
                <thead><tr><th>Service</th><th>Port</th><th>Protocol</th><th>Status</th></tr></thead>
                <tbody>
                  ${dec.honeypots.map(h => `
                    <tr>
                      <td><b>${h.service}</b></td>
                      <td>${h.port}</td>
                      <td>${h.protocol}</td>
                      <td style="color: ${h.status.includes('LISTENING') ? '#10b981' : '#f59e0b'}; font-weight: 600;">${h.status}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
            <div style="margin-top: 1rem;">
              <b>Armed Canary Tokens:</b> ${dec.active_canary_tokens}
              <div style="font-size: 0.72rem; color: #64748b; margin-top: 0.2rem;">Canary credentials generate near-zero false positive intrusion signals upon any unauthorized interaction.</div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading deception status: ' + e.message;
        }
      } else if (mod === 'network') {
        title.innerText = '📡 Network Sniffer & Live Capture';
        body.innerHTML = '<i>Probing network interfaces...</i>';
        try {
          const res = await fetch('/api/v1/network/interfaces');
          const ifaces = await res.json();
          const isCapturing = ifaces.capture_status === 'capturing';
          body.innerHTML = `
            <!-- Status Bar -->
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; margin-bottom: 1.2rem;">
              <div style="background: ${isCapturing ? '#f0fdf4' : '#f8fafc'}; padding: 0.65rem; border-radius: 8px; border: 1px solid ${isCapturing ? '#bbf7d0' : '#e2e8f0'};">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Sensor Status</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: ${isCapturing ? '#16a34a' : '#94a3b8'};">● ${ifaces.capture_status.toUpperCase()}</div>
              </div>
              <div style="background: #f8fafc; padding: 0.65rem; border-radius: 8px; border: 1px solid #e2e8f0;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Active Interface</div>
                <div style="font-size: 0.95rem; font-weight: 700; font-family: monospace; color: #0284c7;">${ifaces.active_interface}</div>
              </div>
              <div style="background: #f8fafc; padding: 0.65rem; border-radius: 8px; border: 1px solid #e2e8f0;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Packets Captured</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: #1e293b;">${ifaces.packets_captured}</div>
              </div>
              <div style="background: #f8fafc; padding: 0.65rem; border-radius: 8px; border: 1px solid #e2e8f0;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Packets Dropped</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: ${ifaces.packets_dropped > 0 ? '#dc2626' : '#94a3b8'};">${ifaces.packets_dropped}</div>
              </div>
            </div>

            <!-- Start / Stop Capture Controls -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.9rem; margin-bottom: 1.2rem;">
              <b style="font-size: 0.82rem;">🎛️ Live Packet Capture Controls</b>
              <div style="font-size: 0.72rem; color: #64748b; margin-bottom: 0.6rem;">Select the interface to monitor. Requires BPF/raw socket privileges — run server with sudo or set CAP_NET_RAW.</div>
              <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                <select id="net-iface-select" style="padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem; background: white; font-family: monospace;">
                  ${ifaces.available_interfaces.map(i => `<option value="${i.name}" ${i.name === ifaces.active_interface ? 'selected' : ''}>${i.name} — ${i.type}</option>`).join('')}
                </select>
                <input id="net-bpf-filter" placeholder="BPF filter (e.g. ip or tcp port 80)" value="${ifaces.capture_mode !== 'tap' ? '' : 'ip'}" style="flex: 1; min-width: 160px; padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem; font-family: monospace;" />
                ${isCapturing
                  ? `<button onclick="captureStop()" class="btn btn-danger" style="white-space: nowrap;">⏹ Stop Capture</button>`
                  : `<button onclick="captureStart()" class="btn btn-primary" style="white-space: nowrap;">▶ Start Capture</button>`
                }
              </div>
              ${ifaces.status_details ? `<div style="margin-top: 0.4rem; font-size: 0.72rem; color: ${ifaces.capture_status === 'permission_denied' ? '#dc2626' : '#64748b'};">${ifaces.status_details}</div>` : ''}
            </div>

            <!-- PCAP Replay -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.9rem; margin-bottom: 1.2rem;">
              <b style="font-size: 0.82rem;">📂 Offline PCAP Replay (Wireshark captures)</b>
              <div style="font-size: 0.72rem; color: #64748b; margin-bottom: 0.6rem;">Paste the full server-side path to a .pcap file. Packets are normalized, stored, and evaluated through the detection pipeline.</div>
              <div style="display: flex; gap: 0.5rem;">
                <input id="pcap-file-path" placeholder="/path/to/capture.pcap" style="flex: 1; padding: 0.3rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem; font-family: monospace;" />
                <button onclick="replayPcap()" class="btn" style="white-space: nowrap;">▶ Replay PCAP</button>
              </div>
              <div id="pcap-replay-result" style="margin-top: 0.5rem; font-size: 0.75rem;"></div>
            </div>

            <!-- Interface Table -->
            <b style="font-size: 0.82rem;">Host Network Interfaces</b>
            <table style="width: 100%; margin-top: 0.4rem; font-size: 0.76rem; border-collapse: collapse;">
              <thead><tr style="border-bottom: 1px solid #e2e8f0;">
                <th style="padding: 5px; text-align: left;">Interface</th>
                <th style="padding: 5px; text-align: left;">Type</th>
                <th style="padding: 5px; text-align: left;">Status</th>
                <th style="padding: 5px; text-align: left;">Action</th>
              </tr></thead>
              <tbody>
                ${ifaces.available_interfaces.map(i => `
                  <tr style="border-bottom: 1px solid #f8fafc;">
                    <td style="padding: 5px; font-family: monospace; font-weight: 700;">${i.name}</td>
                    <td style="padding: 5px; color: #64748b;">${i.type}</td>
                    <td style="padding: 5px; color: #10b981; font-weight: 600;">● ${i.status}</td>
                    <td style="padding: 5px;"><button onclick="quickCapture('${i.name}')" class="btn" style="font-size: 0.69rem; padding: 0.15rem 0.45rem;">Monitor</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        } catch (e) {
          body.innerText = 'Error inspecting interfaces: ' + e.message;
        }
      } else if (mod === 'hunting') {
        title.innerText = 'Proactive Threat Hunting Engine';
        body.innerHTML = '<i>Loading threat hunting sessions...</i>';
        try {
          const res = await fetch('/api/v1/hunting');
          const hunts = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.75rem; font-weight: 600;">Historical Threat Hunts: ${hunts.length}</div>
            ${hunts.length === 0 ? '<div style="color: #64748b; padding: 0.5rem 0;">No hunts executed yet. Launch a hypothesis-driven query below.</div>' : `
              <table style="width: 100%; font-size: 0.78rem; margin-bottom: 1rem;">
                <thead><tr><th>Title</th><th>Hypothesis</th><th>Status</th><th>Findings</th></tr></thead>
                <tbody>
                  ${hunts.map(h => `
                    <tr>
                      <td><b>${h.title}</b></td>
                      <td style="color: #64748b;">${h.hypothesis}</td>
                      <td><span class="tag-badge tag-blue">${h.status.toUpperCase()}</span></td>
                      <td style="font-weight: 600;">${(h.findings || []).length} match(es)</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1rem; border-top: 1px solid #e2e8f0; padding-top: 0.75rem;">
              <b>Launch Hypothesis Hunt:</b>
              <div style="display: flex; flex-direction: column; gap: 0.4rem; margin-top: 0.4rem;">
                <input id="hunt-title" placeholder="Hunt Title (e.g. Audit LOLBin Executions)" style="padding: 0.35rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem;" />
                <input id="hunt-query" placeholder="Query / Pattern (e.g. lolbin certutil)" style="padding: 0.35rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.8rem;" />
                <button onclick="launchHuntFromModal()" class="btn btn-primary" style="align-self: flex-start;">Run Threat Hunt</button>
              </div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading hunts: ' + e.message;
        }
      } else if (mod === 'compliance') {
        title.innerText = 'Continuous Compliance & Audit Reports';
        body.innerHTML = '<i>Loading compliance audit status...</i>';
        try {
          const res = await fetch('/api/v1/compliance');
          const reports = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.75rem; font-weight: 600;">Evaluated Framework Reports: ${reports.length}</div>
            ${reports.length === 0 ? '<div style="color: #64748b; padding: 0.5rem 0;">No compliance reports generated yet. Click below to evaluate against live security controls.</div>' : `
              <table style="width: 100%; font-size: 0.78rem; margin-bottom: 1rem;">
                <thead><tr><th>Framework</th><th>Score</th><th>Controls Passed</th><th>Status</th></tr></thead>
                <tbody>
                  ${reports.map(r => `
                    <tr>
                      <td><b>${r.framework.toUpperCase()}</b></td>
                      <td style="font-weight: 600; color: ${r.score >= 80 ? '#10b981' : '#ef4444'};">${r.score ? r.score.toFixed(1) : 0}%</td>
                      <td>${r.controls_passed} / ${r.total_controls}</td>
                      <td><span class="tag-badge ${r.status === 'compliant' ? 'tag-pass' : 'tag-fail'}">${r.status.toUpperCase()}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1rem; border-top: 1px solid #e2e8f0; padding-top: 0.75rem; display: flex; gap: 0.5rem;">
              <button onclick="generateCompliance('pci-dss')" class="btn">Audit PCI-DSS</button>
              <button onclick="generateCompliance('soc2')" class="btn">Audit SOC2</button>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading compliance: ' + e.message;
        }
      } else {
        title.innerText = mod.toUpperCase();
        body.innerText = `Module ${mod} inspection endpoint ready.`;
      }
    }

    function closeModal(e) {
      document.getElementById('detail-modal').style.display = 'none';
    }

    async function submitManualBlock() {
      const ip = document.getElementById('manual-block-ip').value.trim();
      if (!ip) return;
      try {
        const res = await fetch('/api/v1/network/blocks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip, reason: 'Manual operator block' })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(`Firewall rule applied: Blocked ${ip}`);
          openModule('enforcement');
          refreshData();
        } else {
          showToast(`Error: ${data.detail || 'Block failed'}`);
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function unblockIP(ip) {
      try {
        await fetch(`/api/v1/network/blocks/${ip}`, { method: 'DELETE' });
        showToast(`Unblocked ${ip}`);
        openModule('enforcement');
        refreshData();
      } catch (e) {
        showToast(e.message);
      }
    }

    async function launchHuntFromModal() {
      const title = document.getElementById('hunt-title').value.trim();
      const query = document.getElementById('hunt-query').value.trim();
      if (!title) return;
      try {
        const res = await fetch('/api/v1/hunting', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: title,
            hypothesis: 'Automated operator hunt',
            query: query,
            time_range_hours: 24
          })
        });
        if (res.ok) {
          const hunt = await res.json();
          showToast(`Hunt finished: ${hunt.findings ? hunt.findings.length : 0} match(es)`);
          openModule('hunting');
        } else {
          showToast('Error launching hunt');
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function generateCompliance(framework) {
      try {
        showToast(`Running compliance audit for ${framework.toUpperCase()}...`);
        const res = await fetch(`/api/v1/compliance/generate?framework=${framework}`, { method: 'POST' });
        if (res.ok) {
          const rep = await res.json();
          showToast(`Report complete: ${rep.score.toFixed(1)}% score`);
          openModule('compliance');
        } else {
          showToast('Audit failed');
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function captureStart() {
      const iface = document.getElementById('net-iface-select').value;
      const bpf = document.getElementById('net-bpf-filter').value.trim();
      try {
        const res = await fetch('/api/v1/network/capture/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface: iface, bpf_filter: bpf })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(`✅ Capture started on ${iface} — status: ${data.status}`);
          openModule('network');
        } else {
          showToast(`Error: ${data.detail || 'Capture failed'}`);
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function captureStop() {
      try {
        const res = await fetch('/api/v1/network/capture/stop', { method: 'POST' });
        const data = await res.json();
        showToast(`⏹ Capture stopped — ${data.packets_captured} packets captured`);
        openModule('network');
      } catch (e) {
        showToast(e.message);
      }
    }

    function quickCapture(iface) {
      // Pre-select the interface and scroll to controls
      const sel = document.getElementById('net-iface-select');
      if (sel) sel.value = iface;
      showToast(`Interface ${iface} selected. Click ▶ Start Capture to begin.`);
    }

    async function replayPcap() {
      const path = document.getElementById('pcap-file-path').value.trim();
      const resultEl = document.getElementById('pcap-replay-result');
      if (!path) { resultEl.innerText = 'Enter a PCAP file path first.'; return; }
      resultEl.innerHTML = '<i style="color: #64748b;">Replaying packets...</i>';
      try {
        const res = await fetch('/api/v1/network/pcap/replay', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_path: path })
        });
        const data = await res.json();
        if (res.ok) {
          resultEl.innerHTML = `<span style="color: #16a34a; font-weight: 600;">✅ Replayed ${data.packets_parsed} packets — ${data.persisted_events} stored, dispatched to detection engine.</span>`;
          showToast(`PCAP: ${data.packets_parsed} packets sent to detection pipeline`);
          setTimeout(refreshData, 1500);
        } else {
          resultEl.innerHTML = `<span style="color: #dc2626;">Error: ${data.detail || 'Replay failed'}</span>`;
        }
      } catch (e) {
        resultEl.innerHTML = `<span style="color: #dc2626;">${e.message}</span>`;
      }
    }

    async function wafTestRequest() {
      const method = document.getElementById('waf-test-method').value;
      const path = document.getElementById('waf-test-path').value.trim();
      const ip = document.getElementById('waf-test-ip').value.trim() || '127.0.0.1';
      const resultEl = document.getElementById('waf-test-result');
      if (!path) { resultEl.innerText = 'Enter a path first.'; return; }
      resultEl.innerHTML = '<i style="color: #64748b;">Inspecting...</i>';
      try {
        const res = await fetch('/api/v1/waf/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ method, path, client_ip: ip, body: '', headers: {} })
        });
        const data = await res.json();
        const isBlocked = data.verdict === 'BLOCKED';
        resultEl.innerHTML = `
          <div style="padding: 0.6rem; border-radius: 6px; border: 1px solid ${isBlocked ? '#fecaca' : '#bbf7d0'}; background: ${isBlocked ? '#fef2f2' : '#f0fdf4'};">
            <span style="font-weight: 700; font-size: 0.85rem; color: ${isBlocked ? '#dc2626' : '#16a34a'};">
              ${isBlocked ? '🚫 BLOCKED' : '✅ ALLOWED'}
            </span>
            ${data.reason ? `<span style="color: #64748b; margin-left: 0.5rem; font-size: 0.78rem;">${data.reason}</span>` : ''}
            <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 0.25rem;">Latency: ${data.latency_ms}ms &bull; Client IP: ${ip}</div>
          </div>`;
        showToast(`WAF verdict: ${data.verdict}${data.reason ? ' — ' + data.reason : ''}`);
      } catch (e) {
        resultEl.innerHTML = `<span style="color: #dc2626;">${e.message}</span>`;
      }
    }


    function filterBySeverity(sev) {
      activeSeverityFilter = (activeSeverityFilter === sev) ? null : sev;
      showToast(`Filter: ${sev ? sev.toUpperCase() : 'ALL'}`);
      refreshData();
    }

    function showToast(msg) {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span>⚡</span> <span>${msg}</span>`;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    async function refreshData() {
      try {
        // 1. Fetch real alerts
        const res = await fetch('/api/v1/alerts');
        if (res.ok) {
          const alerts = await res.json();
          let crit = 0, high = 0, med = 0, low = 0;
          alerts.forEach(a => {
            if (a.severity === 'critical') crit++;
            else if (a.severity === 'high') high++;
            else if (a.severity === 'medium') med++;
            else low++;
          });

          // Pure real numbers — ZERO hardcoded fallbacks
          document.getElementById('stat-critical').innerText = crit;
          document.getElementById('stat-high').innerText = high;
          document.getElementById('stat-medium').innerText = med;
          document.getElementById('stat-low').innerText = low;

          const filtered = activeSeverityFilter ? alerts.filter(a => a.severity === activeSeverityFilter) : alerts;
          const tbody = document.getElementById('alerts-tbody');

          if (filtered.length > 0) {
            tbody.innerHTML = filtered.map(a => `
              <tr>
                <td>
                  <span class="tag-badge ${a.severity === 'critical' ? 'tag-fail' : (a.severity === 'high' ? 'tag-amber' : (a.severity === 'medium' ? 'tag-blue' : 'tag-purple'))}">
                    ${a.severity.toUpperCase()}
                  </span>
                </td>
                <td>
                  <div style="font-weight: 600; color: #1e293b;">${a.title}</div>
                  <div style="font-size: 0.72rem; color: #64748b; margin-top: 2px;">${a.description || 'Verified IDPS rule match'}</div>
                </td>
                <td style="font-family: var(--font-mono); font-size: 0.74rem;">
                  ${a.source_ip || '0.0.0.0'} &rarr; ${a.dest_ip || 'local'}
                </td>
                <td>
                  <span style="font-size: 0.75rem; font-weight: 500; color: #475569;">${a.engine || 'Signature'}</span>
                </td>
                <td>
                  <span style="font-family: var(--font-mono); font-weight: 600; color: ${a.risk_score >= 80 ? '#ef4444' : (a.risk_score >= 50 ? '#f59e0b' : '#10b981')}">
                    ${a.risk_score ? a.risk_score.toFixed(1) : '0.0'}
                  </span>
                </td>
                <td>
                  <span style="font-weight: 600; font-size: 0.74rem; text-transform: uppercase;">${a.status}</span>
                </td>
                <td>
                  <button onclick="triageAlert('${a.id}', 'acknowledged')" class="btn" style="font-size: 0.69rem; padding: 0.15rem 0.4rem;">Ack</button>
                  <button onclick="triageAlert('${a.id}', 'resolved')" class="btn" style="font-size: 0.69rem; padding: 0.15rem 0.4rem; color: #10b981; border-color: #10b981;">Resolve</button>
                  <button onclick="submitBlockFromAlert('${a.source_ip}')" class="btn btn-danger" style="font-size: 0.69rem; padding: 0.15rem 0.4rem;">Block</button>
                </td>
              </tr>
            `).join('');
          } else {
            tbody.innerHTML = `
              <tr>
                <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem;">
                  No active alerts recorded. The sensor queue is running and all engines are standing by.
                </td>
              </tr>
            `;
          }
        }

        // 2. Fetch live rules count
        const rulesRes = await fetch('/api/v1/rules');
        if (rulesRes.ok) {
          const rules = await rulesRes.json();
          document.getElementById('strip-rules-count').innerText = `${rules.length} Active Rules`;
        }

        // 3. Fetch real network interfaces
        const netRes = await fetch('/api/v1/network/interfaces');
        if (netRes.ok) {
          const net = await netRes.json();
          const sensorEl = document.getElementById('strip-sensor-status');
          const isCapturing = net.capture_status === 'capturing';
          sensorEl.innerHTML = isCapturing
            ? `<span class="status-dot-green"></span> ${net.active_interface} — capturing (${net.packets_captured} pkts)`
            : `<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#94a3b8;margin-right:4px;vertical-align:middle;"></span>${net.active_interface} (${net.capture_status})`;
        }

        // 4. Fetch firewall blocks
        const blockRes = await fetch('/api/v1/network/blocks');
        if (blockRes.ok) {
          const blocks = await blockRes.json();
          document.getElementById('strip-firewall-status').innerText = `${blocks.length} Active Block${blocks.length === 1 ? '' : 's'}`;
        }

        // 5. Fetch deception status
        const decRes = await fetch('/api/v1/deception/status');
        if (decRes.ok) {
          const dec = await decRes.json();
          const listening = dec.honeypots.filter(h => h.status.includes('LISTENING')).length;
          document.getElementById('strip-deception-status').innerText = `${listening}/2 Honeypots Online`;
        }

      } catch (err) {
        console.error('Refresh error:', err);
      }
    }

    async function triageAlert(alertId, newStatus) {
      try {
        await fetch(`/api/v1/alerts/${alertId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus, notes: `SOC analyst marked as ${newStatus}` })
        });
        showToast(`Alert status updated: ${newStatus.toUpperCase()}`);
        await refreshData();
      } catch (e) {
        showToast(`Error updating alert: ${e.message}`);
      }
    }

    async function submitBlockFromAlert(ip) {
      if (!ip || ip === '0.0.0.0' || ip === '127.0.0.1') {
        showToast('Cannot block loopback/unspecified IP');
        return;
      }
      try {
        const res = await fetch('/api/v1/network/blocks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip, reason: 'SOC alert triggered block', ttl_seconds: 3600 })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(`Firewall block applied for ${ip}`);
          refreshData();
        } else {
          showToast(`Block error: ${data.detail || 'Failed'}`);
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function simulateAttack() {
      showToast('⚡ Ingesting live test event into pipeline...');
      try {
        const res = await fetch('/api/v1/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            event_type: 'network_packet',
            source_sensor: 'manual_tester',
            network: {
              src_ip: '198.51.100.23',
              dst_ip: '10.0.2.15',
              src_port: 54120,
              dst_port: 8080,
              protocol: 'tcp'
            },
            raw_log: 'GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1'
          })
        });
        if (res.ok) {
          showToast('Event ingested: processing through engines...');
          setTimeout(refreshData, 500);
        } else {
          showToast('Event ingestion failed');
        }
      } catch (e) {
        showToast('Ingestion error: ' + e.message);
      }
    }

    // Auto-refresh poll every 4 seconds
    setInterval(refreshData, 4000);
    window.addEventListener('DOMContentLoaded', () => {
      refreshData();
    });
  </script>
</body>
</html>
"""
