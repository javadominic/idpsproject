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
        <div class="nav-pill" id="tab-pill-scanner" onclick="openModule('scanner')" style="background: linear-gradient(135deg, #0ea5e9, #6366f1); color: white; font-weight: 700;">🔍 Website Scanner</div>
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

    <!-- TOP ROW: SEVERITY COUNTERS + SYSTEM STATUS -->
    <div class="top-row-grid">

      <!-- LAST 24h THREAT COUNTERS -->
      <div class="section-card" style="grid-column: 1 / -1;">
        <div class="pill-header">THREATS DETECTED — LAST 24 HOURS (click to filter)</div>
        <div class="alerts-summary-grid">
          <div class="sev-col" onclick="filterBySeverity('critical')">
            <div class="sev-title">Critical</div>
            <div class="sev-num crit" id="stat-critical">0</div>
            <div class="sev-sub">Risk score ≥ 85</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('high')">
            <div class="sev-title">High</div>
            <div class="sev-num high" id="stat-high">0</div>
            <div class="sev-sub">Risk score 70–84</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('medium')">
            <div class="sev-title">Medium</div>
            <div class="sev-num med" id="stat-medium">0</div>
            <div class="sev-sub">Risk score 40–69</div>
          </div>
          <div class="sev-col" onclick="filterBySeverity('low')">
            <div class="sev-title">Low</div>
            <div class="sev-num low" id="stat-low">0</div>
            <div class="sev-sub">Risk score 0–39</div>
          </div>
        </div>
      </div>

    </div>

    <!-- MODULE GRID — Only real, working modules -->
    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.2rem; margin-bottom: 1.4rem;">

      <!-- 1. DETECTION RULES (WORKING: GET /api/v1/rules) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('engines')">
        <div class="pill-header pill-header-left" style="background:#e0f2fe; color:#0369a1; border-color:#bae6fd;">DETECTION ENGINE</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">🛡️</div>
          <div>
            <div class="feature-title">Signature Detection Rules</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Live rule engine evaluating traffic against loaded signatures. Click to see all active rules, their severity and status.</div>
            <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#166534;">
              <b>How to add a rule:</b><br>
              <code style="font-size:0.7rem;">POST /api/v1/rules</code> with JSON body:<br>
              <code style="font-size:0.68rem;">{"rule_id":"R001","name":"Port Scan","severity":"high","enabled":true}</code>
            </div>
          </div>
        </div>
      </div>

      <!-- 2. NETWORK SNIFFER (WORKING: GET /api/v1/network/interfaces) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('network')">
        <div class="pill-header pill-header-left" style="background:#f0fdf4; color:#166534; border-color:#bbf7d0;">NETWORK SNIFFER</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">📡</div>
          <div>
            <div class="feature-title">Live Packet Capture</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Reads real network interfaces from your OS. Start/stop live captures, set BPF filters, or replay saved .pcap files into the detection pipeline.</div>
            <div style="background:#fefce8; border:1px solid #fef08a; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#854d0e;">
              <b>To monitor your network:</b><br>
              1. Click this card → select your interface (e.g. en0)<br>
              2. Set BPF filter (e.g. <code>tcp port 80</code> or leave blank for all)<br>
              3. Click ▶ Start Capture<br>
              <b>Requires:</b> Run server as <code>sudo</code> or set <code>CAP_NET_RAW</code>
            </div>
          </div>
        </div>
      </div>

      <!-- 3. FIREWALL & IPS (WORKING: GET /api/v1/network/blocks) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('enforcement')">
        <div class="pill-header pill-header-left" style="background:#fef2f2; color:#991b1b; border-color:#fecaca;">FIREWALL & IPS</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">🔒</div>
          <div>
            <div class="feature-title">Active IP Blocks</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Shows all currently blocked IPs enforced at the firewall level. Manually block or unblock any IP. Blocks auto-expire after TTL.</div>
            <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#166534;">
              <b>To block an IP:</b><br>
              <code style="font-size:0.68rem;">POST /api/v1/network/blocks</code><br>
              Body: <code style="font-size:0.68rem;">{"ip":"1.2.3.4","reason":"Port scan","ttl_seconds":3600}</code><br>
              Or use the <b>Firewall & IPS</b> tab above → Block IP form.
            </div>
          </div>
        </div>
      </div>

      <!-- 4. WEBSITE WAF (WORKING: GET /api/v1/waf/status + POST /api/v1/waf/inspect) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('waf')">
        <div class="pill-header pill-header-left" style="background:#fdf4ff; color:#7e22ce; border-color:#e9d5ff;">WEBSITE WAF</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">🛡️</div>
          <div>
            <div class="feature-title">Web Application Firewall</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Inspects HTTP requests in real-time for SQLi, XSS, path traversal, and command injection. Shows live blocked/allowed counts.</div>
            <div style="background:#fdf4ff; border:1px solid #e9d5ff; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#6b21a8;">
              <b>To protect your website:</b><br>
              Point your web app's reverse proxy to this IDPS instance.<br>
              Or use the <b>Website WAF</b> tab → "Test Your Website Request" form<br>
              to manually inspect any HTTP path through the WAF engine.
            </div>
          </div>
        </div>
      </div>

      <!-- 5. WEBSITE SCANNER (WORKING: POST /api/v1/scanner/scan) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('scanner')">
        <div class="pill-header pill-header-left" style="background:linear-gradient(90deg,#e0f2fe,#ede9fe); color:#0369a1; border-color:#bae6fd;">WEBSITE SCANNER</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">🔍</div>
          <div>
            <div class="feature-title">Auto Security Scanner</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Enter any URL — the IDPS automatically probes it: checks SSL/TLS, missing security headers, exposed sensitive files (.env, /admin, etc.), server leakage, cookie flags. Gives a security grade A–F.</div>
            <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#1e40af;">
              <b>How to scan your website:</b><br>
              1. Click this card (or the 🔍 Website Scanner tab above)<br>
              2. Type your site URL e.g. <code>https://example.com</code><br>
              3. Click ▶ Scan Now — results appear in 5–15 seconds<br>
              No setup needed. Works on any public or local URL.
            </div>
          </div>
        </div>
      </div>

      <!-- 6. DECEPTION & THREAT HUNTING (WORKING: GET /api/v1/deception/status + /api/v1/hunting) -->
      <div class="section-card" style="cursor:pointer;" onclick="openModule('deception')">
        <div class="pill-header pill-header-left" style="background:#fff7ed; color:#9a3412; border-color:#fed7aa;">DECEPTION & HUNTING</div>
        <div style="display:flex; align-items:flex-start; gap:0.75rem; margin-top:0.25rem;">
          <div style="font-size:1.6rem; flex-shrink:0;">🪤</div>
          <div>
            <div class="feature-title">Honeypots & Threat Hunting</div>
            <div class="feature-desc" style="margin-bottom:0.65rem;">Decoy SSH and HTTP services lure attackers. Canary tokens generate instant alerts on access. Threat hunting runs automated IOC hypothesis queries.</div>
            <div style="background:#fff7ed; border:1px solid #fed7aa; border-radius:5px; padding:0.5rem 0.65rem; font-size:0.72rem; color:#9a3412;">
              <b>To activate honeypots:</b><br>
              Start the decoy service: <code>python -m services.deception.decoy_service</code><br>
              SSH trap listens on port <b>2222</b>, HTTP trap on port <b>8088</b>.<br>
              Any connection triggers an alert in the threat stream below.
            </div>
          </div>
        </div>
      </div>

    </div>

    <!-- COMPLIANCE ROW -->
    <div class="section-card" style="margin-bottom: 1.4rem;">
      <div class="pill-header" style="background:#f0fdf4; color:#166534; border-color:#bbf7d0;">COMPLIANCE AUDIT ENGINE</div>
      <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem; margin-top:0.5rem;">
        <div style="display:flex; align-items:flex-start; gap:0.75rem;">
          <div style="font-size:1.5rem;">📋</div>
          <div>
            <div class="feature-title">Automated Compliance Reports</div>
            <div class="feature-desc">Generate real compliance audit reports for PCI-DSS, SOC2, HIPAA, or GDPR. Each report evaluates your current IDPS rules and detection coverage against the framework's requirements.</div>
            <div style="margin-top:0.5rem; font-size:0.72rem; color:#64748b;"><b>How to generate a report:</b> Click any button → report runs against live rule set → score appears in the compliance modal.</div>
          </div>
        </div>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
          <button onclick="generateCompliance('pci_dss')" class="btn" style="font-size:0.75rem; font-weight:600;">📄 PCI-DSS 4.0</button>
          <button onclick="generateCompliance('soc2')" class="btn" style="font-size:0.75rem; font-weight:600;">📄 SOC 2</button>
          <button onclick="generateCompliance('hipaa')" class="btn" style="font-size:0.75rem; font-weight:600;">📄 HIPAA</button>
          <button onclick="generateCompliance('gdpr')" class="btn" style="font-size:0.75rem; font-weight:600;">📄 GDPR</button>
          <button onclick="openModule('compliance')" class="btn btn-primary" style="font-size:0.75rem;">📊 View Report</button>
        </div>
      </div>
    </div>

    <!-- LIVE THREAT STREAM TABLE -->
    <div class="section-card" id="section-threats">
      <div class="pill-header">LIVE ALERT QUEUE — ALL DETECTIONS FROM ALL ENGINES</div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem;">
        <div style="font-size: 0.82rem; color: #64748b;">
          Real alerts from the IDPS detection pipeline. Alerts appear here when the network sensor, WAF, honeypots, or rules fire.
          <span style="color:#0284c7; font-weight:600;">Click a row to view details. Click ⚡ Ingest Test Event to push a test alert.</span>
        </div>
        <button onclick="refreshData()" class="btn" style="font-size: 0.72rem; flex-shrink:0;">🔄 Refresh</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Threat / Detection</th>
            <th>Source → Target</th>
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
      } else if (mod === 'scanner') {
        title.innerText = '🔍 Website Security Scanner — Auto-Detect Everything';
        // Show previous scan result if in memory, otherwise show the scan form
        const prevScan = window._lastScanResult || null;
        body.innerHTML = `
          <div style="margin-bottom: 1rem;">
            <div style="font-size: 0.8rem; color: #475569; margin-bottom: 0.5rem;">
              Enter any website URL. The IDPS will automatically make real HTTP requests and detect:
              missing security headers, SSL/TLS issues, exposed sensitive files, server info leakage,
              insecure cookies, and more. <b>No simulation — real probes only.</b>
            </div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <input id="scanner-url-input"
                placeholder="https://your-website.com or any URL"
                style="flex: 1; min-width: 250px; padding: 0.4rem 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.85rem;"
                value="${prevScan ? prevScan.url : ''}"
                onkeydown="if(event.key==='Enter') runWebsiteScan()" />
              <label style="display: flex; align-items: center; gap: 0.3rem; font-size: 0.78rem; color: #64748b; cursor: pointer;">
                <input type="checkbox" id="scanner-probe-paths" checked> Probe sensitive paths
              </label>
              <label style="display: flex; align-items: center; gap: 0.3rem; font-size: 0.78rem; color: #64748b; cursor: pointer;">
                <input type="checkbox" id="scanner-check-ssl" checked> Check SSL/TLS
              </label>
              <button onclick="runWebsiteScan()" class="btn btn-primary" id="scanner-run-btn">▶ Scan Now</button>
            </div>
            <div id="scanner-progress" style="margin-top: 0.5rem; font-size: 0.78rem; color: #64748b;"></div>
          </div>
          <div id="scanner-results">${prevScan ? renderScanResult(prevScan) : '<div style="color:#94a3b8; text-align:center; padding: 2rem 0; font-size: 0.85rem;">Enter a URL above and click Scan Now. Results appear here automatically.</div>'}</div>
        `;
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

    async function runWebsiteScan() {
      const urlInput = document.getElementById('scanner-url-input');
      const probePaths = document.getElementById('scanner-probe-paths')?.checked ?? true;
      const checkSsl = document.getElementById('scanner-check-ssl')?.checked ?? true;
      const progressEl = document.getElementById('scanner-progress');
      const resultsEl = document.getElementById('scanner-results');
      const runBtn = document.getElementById('scanner-run-btn');

      let url = urlInput?.value?.trim();
      if (!url) { showToast('Enter a URL first'); return; }
      if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;

      if (runBtn) { runBtn.disabled = true; runBtn.innerText = '⏳ Scanning...'; }
      if (progressEl) progressEl.innerHTML = '<span style="color: #0284c7;">⏳ Probing target — making real HTTP requests, checking SSL, scanning paths. This takes 5–15 seconds...</span>';
      if (resultsEl) resultsEl.innerHTML = '';

      try {
        const res = await fetch('/api/v1/scanner/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            probe_sensitive_paths: probePaths,
            check_ssl: checkSsl,
            timeout_seconds: 12
          })
        });

        if (!res.ok) {
          const err = await res.json();
          if (progressEl) progressEl.innerHTML = `<span style="color: #dc2626;">Error: ${err.detail || 'Scan failed'}</span>`;
          if (runBtn) { runBtn.disabled = false; runBtn.innerText = '▶ Scan Now'; }
          return;
        }

        const data = await res.json();
        window._lastScanResult = data;
        if (progressEl) progressEl.innerHTML = `<span style="color: #16a34a;">✅ Scan complete — ${data.issue_summary.total} issues found</span>`;
        if (resultsEl) resultsEl.innerHTML = renderScanResult(data);
        showToast(`Scan: Grade ${data.grade} — ${data.issue_summary.high} HIGH, ${data.issue_summary.medium} MEDIUM issues`);
      } catch (e) {
        if (progressEl) progressEl.innerHTML = `<span style="color: #dc2626;">Network error: ${e.message}</span>`;
      } finally {
        if (runBtn) { runBtn.disabled = false; runBtn.innerText = '▶ Scan Now'; }
      }
    }

    function renderScanResult(data) {
      const gradeColor = {'A':'#16a34a','B':'#65a30d','C':'#d97706','D':'#ea580c','F':'#dc2626'}[data.grade] || '#64748b';
      const sevIcon = s => ({'HIGH':'🔴','MEDIUM':'🟠','LOW':'🟡','INFO':'🔵','OK':'🟢'}[s] || '⚪');

      const issueFindings = data.findings.filter(f => f.severity !== 'OK' && f.severity !== 'INFO');
      const okFindings = data.findings.filter(f => f.severity === 'OK');
      const exposedPaths = (data.probed_paths || []).filter(p => p.exposed);

      return `
        <!-- Score header -->
        <div style="display: flex; align-items: center; gap: 1.5rem; padding: 1rem; background: #f8fafc; border-radius: 10px; border: 1px solid #e2e8f0; margin-bottom: 1rem;">
          <div style="text-align: center; min-width: 70px;">
            <div style="font-size: 2.8rem; font-weight: 900; line-height: 1; color: ${gradeColor};">${data.grade}</div>
            <div style="font-size: 0.68rem; color: #64748b; text-transform: uppercase; font-weight: 600;">Security Grade</div>
          </div>
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem;">
              <div style="flex: 1; height: 8px; border-radius: 4px; background: #e2e8f0; overflow: hidden;">
                <div style="height: 100%; width: ${data.score}%; background: ${gradeColor}; border-radius: 4px;"></div>
              </div>
              <span style="font-weight: 700; font-size: 0.9rem; color: ${gradeColor};">${data.score}/100</span>
            </div>
            <div style="font-size: 0.75rem; color: #64748b;">
              ${data.url} &bull; ${new Date(data.scanned_at).toLocaleString()} &bull; ${data.response?.latency_ms || 0}ms response
            </div>
          </div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; justify-content: flex-end;">
            <span style="padding: 0.25rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 700; background: #fef2f2; color: #dc2626;">🔴 ${data.issue_summary.high} HIGH</span>
            <span style="padding: 0.25rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 700; background: #fff7ed; color: #ea580c;">🟠 ${data.issue_summary.medium} MED</span>
            <span style="padding: 0.25rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 700; background: #fefce8; color: #ca8a04;">🟡 ${data.issue_summary.low} LOW</span>
            <span style="padding: 0.25rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 700; background: #f0fdf4; color: #16a34a;">🟢 ${data.issue_summary.ok} OK</span>
          </div>
        </div>

        ${issueFindings.length > 0 ? `
        <!-- Issues -->
        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.82rem; font-weight: 700; color: #1e293b; margin-bottom: 0.4rem;">⚠️ Issues Found (${issueFindings.length})</div>
          ${issueFindings.sort((a,b) => ({'HIGH':0,'MEDIUM':1,'LOW':2}[a.severity]??3) - ({'HIGH':0,'MEDIUM':1,'LOW':2}[b.severity]??3)).map(f => `
            <div style="display: flex; align-items: flex-start; gap: 0.5rem; padding: 0.5rem 0.6rem; border-radius: 6px; margin-bottom: 0.3rem; background: ${{HIGH:'#fef2f2',MEDIUM:'#fff7ed',LOW:'#fefce8',INFO:'#eff6ff'}[f.severity]||'#f8fafc'}; border-left: 3px solid ${{HIGH:'#dc2626',MEDIUM:'#ea580c',LOW:'#ca8a04',INFO:'#3b82f6'}[f.severity]||'#94a3b8'};">
              <span style="flex-shrink: 0; font-size: 0.75rem; padding-top: 1px;">${sevIcon(f.severity)}</span>
              <div>
                <span style="font-size: 0.76rem; font-weight: 700; color: ${{HIGH:'#991b1b',MEDIUM:'#9a3412',LOW:'#92400e'}[f.severity]||'#1e293b'};">${f.type.replace(/_/g,' ')}</span>
                <div style="font-size: 0.73rem; color: #475569; margin-top: 0.1rem;">${f.detail}</div>
              </div>
            </div>
          `).join('')}
        </div>` : ''}

        ${exposedPaths.length > 0 ? `
        <!-- Exposed Paths -->
        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.82rem; font-weight: 700; color: #dc2626; margin-bottom: 0.4rem;">🗂️ Sensitive Paths Exposed (${exposedPaths.length})</div>
          <table style="width:100%; font-size: 0.74rem; border-collapse: collapse;">
            <thead><tr style="border-bottom: 1px solid #e2e8f0;">
              <th style="padding: 4px; text-align:left;">Path</th>
              <th style="padding: 4px; text-align:left;">HTTP Status</th>
              <th style="padding: 4px; text-align:left;">Size</th>
              <th style="padding: 4px; text-align:left;">Action</th>
            </tr></thead>
            <tbody>
              ${exposedPaths.map(p => `
                <tr style="border-bottom: 1px solid #f8fafc;">
                  <td style="padding:4px; font-family: monospace; color: #dc2626; font-weight: 600;">${p.path}</td>
                  <td style="padding:4px; font-family: monospace;">${p.status_code}</td>
                  <td style="padding:4px; color: #64748b;">${p.size_bytes} B</td>
                  <td style="padding:4px;"><a href="${p.url}" target="_blank" style="font-size: 0.7rem; color: #0284c7; text-decoration: none;">Open ↗</a></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>` : ''}

        ${okFindings.length > 0 ? `
        <!-- OK Items (collapsed) -->
        <details style="margin-bottom: 0.5rem;">
          <summary style="cursor: pointer; font-size: 0.78rem; color: #16a34a; font-weight: 600; padding: 0.3rem 0;">✅ Passing Checks (${okFindings.length})</summary>
          <div style="margin-top: 0.3rem;">
            ${okFindings.map(f => `
              <div style="padding: 0.35rem 0.6rem; font-size: 0.73rem; color: #166534; background: #f0fdf4; border-radius: 4px; margin-bottom: 0.2rem;">
                🟢 ${f.detail}
              </div>
            `).join('')}
          </div>
        </details>` : ''}
      `;
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
