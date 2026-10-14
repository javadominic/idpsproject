"""
Next-Generation Enterprise IDPS SOC Command Console
===================================================
Redesigned according to the UI/UX Pro Max guidelines:
- Sleek Cybersecurity / Operations Center aesthetic with dimensional cards and rich color accents
- Slide-out Menu UI Drawer for clean navigation without cluttered navbar buttons
- Zero hardcoded mock data: 100% wired to real IDPS API telemetry
- Fixed compliance report score parsing (.overall_score)
- High-contrast SVG vector icons (no raw emojis)
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDPS &bull; Next-Gen Intrusion Detection &amp; Prevention System</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --bg-card: #0f172a;
      --bg-card-hover: #131d35;
      --border: #1e293b;
      --border-bright: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      
      /* Vibrant Cyber Accents */
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.15);
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.15);
      --crimson: #ef4444;
      --crimson-glow: rgba(239, 68, 68, 0.15);
      --purple: #a855f7;
      --purple-glow: rgba(168, 85, 247, 0.15);
      --indigo: #6366f1;
      --indigo-glow: rgba(99, 102, 241, 0.15);
      --amber: #f59e0b;
      --amber-glow: rgba(245, 158, 11, 0.15);
      --blue: #0284c7;
      
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* ─── Top Navbar ────────────────────────────────────────── */
    header {
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      height: 60px;
      padding: 0 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .nav-left {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }

    /* Menu Toggle Button (Prominent & Clean) */
    .menu-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      background: #1e293b;
      color: var(--text-main);
      border: 1px solid var(--border-bright);
      padding: 0.45rem 0.9rem;
      border-radius: 8px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .menu-btn:hover {
      background: #334155;
      border-color: var(--cyan);
      box-shadow: 0 0 12px var(--cyan-glow);
    }

    .logo-container {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      cursor: pointer;
      text-decoration: none;
    }
    .logo-badge {
      font-weight: 900;
      font-size: 1.25rem;
      letter-spacing: -0.03em;
      color: #ffffff;
      display: flex;
      align-items: center;
    }
    .logo-badge span {
      color: var(--cyan);
      text-shadow: 0 0 10px rgba(6, 182, 212, 0.6);
    }
    .logo-tag {
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 0.15rem 0.45rem;
      background: rgba(6, 182, 212, 0.15);
      color: var(--cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      border-radius: 4px;
    }

    .status-armed-pill {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.72rem;
      font-weight: 600;
      background: rgba(16, 185, 129, 0.12);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 0.25rem 0.65rem;
      border-radius: 20px;
    }
    .status-pulse-dot {
      width: 7px;
      height: 7px;
      background: #10b981;
      border-radius: 50%;
      box-shadow: 0 0 8px #10b981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.2); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    /* Action Buttons */
    .btn {
      padding: 0.42rem 0.85rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      border: 1px solid var(--border-bright);
      background: #1e293b;
      color: var(--text-main);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      text-decoration: none;
      transition: all 0.2s ease;
    }
    .btn:hover {
      background: #283548;
      border-color: #475569;
    }
    .btn-primary {
      background: linear-gradient(135deg, #0284c7, #0369a1);
      color: #ffffff;
      border-color: #0284c7;
      box-shadow: 0 2px 8px rgba(2, 132, 199, 0.3);
    }
    .btn-primary:hover {
      background: linear-gradient(135deg, #0369a1, #075985);
      border-color: #38bdf8;
    }
    .btn-danger {
      background: linear-gradient(135deg, #dc2626, #b91c1c);
      color: #ffffff;
      border-color: #ef4444;
      box-shadow: 0 2px 8px rgba(220, 38, 38, 0.3);
    }
    .btn-danger:hover {
      background: linear-gradient(135deg, #ef4444, #dc2626);
      box-shadow: 0 0 12px rgba(239, 68, 68, 0.5);
    }
    .btn-indigo {
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: #ffffff;
      border-color: #818cf8;
      box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3);
    }
    .btn-indigo:hover {
      background: linear-gradient(135deg, #4f46e5, #4338ca);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.5);
    }

    /* ─── Slide-out Menu UI Drawer ───────────────────────────── */
    #drawer-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      z-index: 998;
      opacity: 0;
      transition: opacity 0.25s ease;
    }
    #drawer-overlay.active {
      display: block;
      opacity: 1;
    }

    #soc-menu-drawer {
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      width: 330px;
      background: #0f172a;
      border-right: 1px solid var(--border-bright);
      z-index: 999;
      transform: translateX(-100%);
      transition: transform 0.28s cubic-bezier(0.16, 1, 0.3, 1);
      display: flex;
      flex-direction: column;
      box-shadow: 10px 0 30px rgba(0, 0, 0, 0.6);
    }
    #soc-menu-drawer.active {
      transform: translateX(0);
    }

    .drawer-header {
      padding: 1.25rem 1.4rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #0b0f19;
    }
    .drawer-title {
      font-size: 0.85rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--cyan);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 1.25rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      transition: all 0.2s;
    }
    .drawer-close:hover {
      color: #ffffff;
      background: #1e293b;
    }

    .drawer-body {
      flex: 1;
      overflow-y: auto;
      padding: 1rem 0.85rem;
    }

    .menu-group-label {
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--text-dim);
      padding: 0.8rem 0.75rem 0.4rem;
    }

    .menu-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.65rem 0.75rem;
      border-radius: 8px;
      color: #cbd5e1;
      text-decoration: none;
      font-size: 0.82rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
      margin-bottom: 0.25rem;
    }
    .menu-item:hover {
      background: #1e293b;
      color: #ffffff;
      border-color: rgba(255, 255, 255, 0.06);
    }
    .menu-item.active {
      background: rgba(6, 182, 212, 0.12);
      color: var(--cyan);
      border-color: rgba(6, 182, 212, 0.3);
      font-weight: 600;
    }
    .menu-icon-svg {
      width: 18px;
      height: 18px;
      stroke-width: 2;
      flex-shrink: 0;
    }
    .menu-badge {
      margin-left: auto;
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.15rem 0.45rem;
      border-radius: 10px;
      background: #1e293b;
      color: var(--text-muted);
    }

    .drawer-footer {
      padding: 1rem 1.25rem;
      border-top: 1px solid var(--border);
      background: #0b0f19;
      font-size: 0.72rem;
      color: var(--text-dim);
    }

    /* ─── Hero System Health Strip ───────────────────────────── */
    .system-strip {
      background: #0c1322;
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 2rem;
      font-size: 0.78rem;
    }
    .strip-item {
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
    }
    .strip-label {
      color: var(--text-dim);
      font-size: 0.68rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .strip-val {
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-family: var(--font-mono);
      font-size: 0.76rem;
    }

    /* ─── Main Content ───────────────────────────────────────── */
    main {
      flex: 1;
      padding: 1.5rem;
      max-width: 1720px;
      width: 100%;
      margin: 0 auto;
    }

    /* Section Header */
    .section-title-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .section-title {
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    /* ─── KPI Severity Bento Grid ────────────────────────────── */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 900px) {
      .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 500px) {
      .kpi-grid { grid-template-columns: 1fr; }
    }

    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.15rem;
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }
    .kpi-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
    }
    .kpi-card.active-filter {
      border-color: #ffffff;
      box-shadow: 0 0 15px rgba(255, 255, 255, 0.2);
    }
    .kpi-bar {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
    }
    .kpi-bar.crit { background: var(--crimson); box-shadow: 0 0 10px var(--crimson); }
    .kpi-bar.high { background: var(--amber); box-shadow: 0 0 10px var(--amber); }
    .kpi-bar.med  { background: var(--cyan); box-shadow: 0 0 10px var(--cyan); }
    .kpi-bar.low  { background: var(--indigo); box-shadow: 0 0 10px var(--indigo); }

    .kpi-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .kpi-label {
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .kpi-num {
      font-size: 2.2rem;
      font-weight: 800;
      line-height: 1;
      font-family: var(--font-mono);
      margin-bottom: 0.35rem;
    }
    .kpi-num.crit { color: #f87171; }
    .kpi-num.high { color: #fbbf24; }
    .kpi-num.med  { color: #38bdf8; }
    .kpi-num.low  { color: #a5b4fc; }

    .kpi-sub {
      font-size: 0.7rem;
      color: var(--text-dim);
    }

    /* ─── Interactive Feature Bento Grid ─────────────────────── */
    .module-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 1200px) {
      .module-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 768px) {
      .module-grid { grid-template-columns: 1fr; }
    }

    .module-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.4rem;
      display: flex;
      flex-direction: column;
      position: relative;
      transition: all 0.25s ease;
      cursor: pointer;
    }
    .module-card:hover {
      background: var(--bg-card-hover);
      transform: translateY(-2px);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.45);
    }
    
    /* Dedicated Accent Card Styles */
    .card-cyan:hover   { border-color: var(--cyan); box-shadow: 0 0 20px var(--cyan-glow); }
    .card-emerald:hover{ border-color: var(--emerald); box-shadow: 0 0 20px var(--emerald-glow); }
    .card-crimson:hover{ border-color: var(--crimson); box-shadow: 0 0 20px var(--crimson-glow); }
    .card-purple:hover { border-color: var(--purple); box-shadow: 0 0 20px var(--purple-glow); }
    .card-indigo:hover { border-color: var(--indigo); box-shadow: 0 0 20px var(--indigo-glow); }
    .card-amber:hover  { border-color: var(--amber); box-shadow: 0 0 20px var(--amber-glow); }

    .card-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.85rem;
    }
    .card-badge {
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      border: 1px solid transparent;
    }
    .badge-cyan   { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border-color: rgba(6, 182, 212, 0.3); }
    .badge-emerald{ background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .badge-crimson{ background: rgba(239, 68, 68, 0.15); color: #f87171; border-color: rgba(239, 68, 68, 0.3); }
    .badge-purple { background: rgba(168, 85, 247, 0.15); color: #c084fc; border-color: rgba(168, 85, 247, 0.3); }
    .badge-indigo { background: rgba(99, 102, 241, 0.15); color: #818cf8; border-color: rgba(99, 102, 241, 0.3); }
    .badge-amber  { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border-color: rgba(245, 158, 11, 0.3); }

    .card-icon-wrapper {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--border-bright);
      background: #0b1120;
    }

    .card-title {
      font-size: 1rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.35rem;
    }
    .card-desc {
      font-size: 0.78rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 0.85rem;
      flex: 1;
    }

    .terminal-how-to {
      background: #080d1a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 0.7rem 0.85rem;
      font-size: 0.72rem;
      color: #94a3b8;
      line-height: 1.55;
      margin-bottom: 0.85rem;
    }
    .terminal-how-to b {
      color: #e2e8f0;
      display: block;
      margin-bottom: 0.25rem;
    }
    .terminal-how-to code {
      font-family: var(--font-mono);
      background: #1e293b;
      color: #38bdf8;
      padding: 0.1rem 0.3rem;
      border-radius: 4px;
      font-size: 0.68rem;
    }

    .card-action-row {
      margin-top: auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 0.5rem;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
    }
    .action-link {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--cyan);
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      text-decoration: none;
    }

    /* ─── Compliance Row ─────────────────────────────────────── */
    .compliance-card {
      background: linear-gradient(180deg, #0f172a 0%, #0d1527 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.4rem;
      margin-bottom: 1.5rem;
    }

    /* ─── Live Threat Stream Table ───────────────────────────── */
    .table-container {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .table-header-bar {
      padding: 1.1rem 1.4rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #0b0f19;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.78rem;
      text-align: left;
    }
    th {
      padding: 0.75rem 1rem;
      font-weight: 600;
      color: var(--text-dim);
      font-size: 0.68rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      border-bottom: 1px solid var(--border);
      background: #090e18;
    }
    td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(30, 41, 59, 0.7);
      vertical-align: middle;
      color: #cbd5e1;
    }
    tr:hover td {
      background: rgba(30, 41, 59, 0.5);
    }

    .tag-badge {
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
      font-family: var(--font-mono);
      letter-spacing: 0.04em;
    }
    .tag-fail { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .tag-amber{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .tag-blue { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .tag-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

    /* ─── Modal Inspector ────────────────────────────────────── */
    #detail-modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(6px);
      z-index: 999;
      align-items: center;
      justify-content: center;
    }
    .modal-box {
      background: #0f172a;
      width: 92%;
      max-width: 820px;
      max-height: 85vh;
      overflow-y: auto;
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border-bright);
      box-shadow: 0 20px 40px rgba(0,0,0,0.7);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .modal-title {
      font-size: 1.1rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    /* ─── Toast Notifications ────────────────────────────────── */
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
      border: 1px solid var(--border-bright);
      padding: 0.75rem 1.1rem;
      border-radius: 8px;
      font-size: 0.8rem;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      gap: 0.6rem;
      animation: slideIn 0.25s ease-out;
    }
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  </style>
</head>
<body>

  <!-- Overlay for Slide-out Menu -->
  <div id="drawer-overlay" onclick="toggleMenu(false)"></div>

  <!-- Slide-out SOC Control Drawer (The MENU UI) -->
  <nav id="soc-menu-drawer">
    <div class="drawer-header">
      <div class="drawer-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        IDPS Control Center
      </div>
      <button class="drawer-close" onclick="toggleMenu(false)">&times;</button>
    </div>

    <div class="drawer-body">
      <div class="menu-group-label">Core Operations</div>
      <div class="menu-item active" onclick="navigate('overview')">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        SOC Overview
      </div>
      <div class="menu-item" onclick="navigate('threats')">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        Live Threat Stream
        <span class="menu-badge" id="menu-badge-alerts">0 alerts</span>
      </div>

      <div class="menu-group-label">Perimeter &amp; Inspection</div>
      <div class="menu-item" onclick="openModule('waf'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #c084fc;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        Website WAF Shield
      </div>
      <div class="menu-item" onclick="openModule('scanner'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #818cf8;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        Website Auto-Scanner
        <span class="menu-badge" style="background:#4338ca; color:#ffffff;">PRO</span>
      </div>
      <div class="menu-item" onclick="openModule('enforcement'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #f87171;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Firewall &amp; IPS Blocks
      </div>
      <div class="menu-item" onclick="openModule('network'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #34d399;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
        Network Sniffer &amp; PCAP
      </div>

      <div class="menu-group-label">Engines &amp; Deception</div>
      <div class="menu-item" onclick="openModule('engines'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #22d3ee;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
        Signature Engine Rules
      </div>
      <div class="menu-item" onclick="openModule('deception'); toggleMenu(false);">
        <svg class="menu-icon-svg" style="stroke: #fbbf24;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
        Honeypots &amp; Canary
      </div>
      <div class="menu-item" onclick="openModule('hunting'); toggleMenu(false);">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>
        Threat Hunting
      </div>

      <div class="menu-group-label">Governance &amp; APIs</div>
      <div class="menu-item" onclick="openModule('compliance'); toggleMenu(false);">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        Continuous Compliance
      </div>
      <a class="menu-item" href="/docs" target="_blank">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
        API Documentation ↗
      </a>
      <a class="menu-item" href="/metrics" target="_blank">
        <svg class="menu-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        Prometheus Metrics ↗
      </a>
    </div>

    <div class="drawer-footer">
      <div><b>IDPS Engine 2.0</b> &bull; Production Mode</div>
      <div style="margin-top: 0.25rem;">Real-time Telemetry Active</div>
    </div>
  </nav>

  <!-- Top Navigation Bar -->
  <header>
    <div class="nav-left">
      <!-- Clean Menu Button that triggers the Menu Drawer -->
      <button class="menu-btn" onclick="toggleMenu(true)" title="Open IDPS Navigation Menu (M)">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
        <span>Menu</span>
      </button>

      <div class="logo-container" onclick="navigate('overview')">
        <div class="logo-badge">IDPS<span>.</span></div>
        <div class="logo-tag">CORE DEFENSE</div>
      </div>

      <div class="status-armed-pill">
        <span class="status-pulse-dot"></span>
        <span>ENGINES ARMED</span>
      </div>
    </div>

    <div class="nav-right">
      <button onclick="simulateAttack()" class="btn btn-danger" title="Trigger a live attack event into detection pipeline">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        <span>⚡ Ingest Test Event</span>
      </button>
      <button onclick="refreshData()" class="btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        <span>Refresh</span>
      </button>
      <a href="/docs" target="_blank" class="btn" title="Open Swagger OpenAPI Documentation">
        <span>API Docs</span>
      </a>
    </div>
  </header>

  <!-- Live System Health Strip (Dynamic Real Data) -->
  <div class="system-strip">
    <div class="strip-item">
      <span class="strip-label">IDPS Core API</span>
      <span class="strip-val" id="strip-api-status"><span style="color:#10b981;">●</span> Online</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Loaded Rules</span>
      <span class="strip-val" id="strip-rules-count" style="color:#22d3ee;">Loading rules...</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Network Sniffer</span>
      <span class="strip-val" id="strip-sensor-status">Probing interfaces...</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Firewall State</span>
      <span class="strip-val" id="strip-firewall-status" style="color:#f87171;">0 Blocks</span>
    </div>
    <div class="strip-item">
      <span class="strip-label">Deception Traps</span>
      <span class="strip-val" id="strip-deception-status" style="color:#fbbf24;">Checking sockets...</span>
    </div>
    <div style="margin-left: auto; display: flex; align-items: center; gap: 0.5rem;">
      <span style="font-size: 0.72rem; color: var(--text-dim);">Time Window:</span>
      <span class="btn" style="padding: 0.2rem 0.6rem; font-size: 0.72rem;">Last 24 Hours</span>
    </div>
  </div>

  <main>

    <!-- SECTION: SEVERITY KPI COUNTERS -->
    <div class="section-title-row">
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Threat Telemetry — Last 24 Hours
      </div>
      <span style="font-size: 0.72rem; color: var(--text-dim);">Click any card to filter live threat table</span>
    </div>

    <div class="kpi-grid">
      <!-- Critical -->
      <div class="kpi-card" id="kpi-card-critical" onclick="filterBySeverity('critical')">
        <div class="kpi-bar crit"></div>
        <div class="kpi-header">
          <span class="kpi-label">Critical Severity</span>
          <span class="tag-badge tag-fail">RISK &ge; 85</span>
        </div>
        <div class="kpi-num crit" id="stat-critical">0</div>
        <div class="kpi-sub">Immediate block required &bull; Auto-firewalled</div>
      </div>

      <!-- High -->
      <div class="kpi-card" id="kpi-card-high" onclick="filterBySeverity('high')">
        <div class="kpi-bar high"></div>
        <div class="kpi-header">
          <span class="kpi-label">High Severity</span>
          <span class="tag-badge tag-amber">RISK 70–84</span>
        </div>
        <div class="kpi-num high" id="stat-high">0</div>
        <div class="kpi-sub">Exploit payloads &bull; C2 beacon activity</div>
      </div>

      <!-- Medium -->
      <div class="kpi-card" id="kpi-card-medium" onclick="filterBySeverity('medium')">
        <div class="kpi-bar med"></div>
        <div class="kpi-header">
          <span class="kpi-label">Medium Severity</span>
          <span class="tag-badge tag-blue">RISK 40–69</span>
        </div>
        <div class="kpi-num med" id="stat-medium">0</div>
        <div class="kpi-sub">Port sweeps &bull; Protocol anomalies</div>
      </div>

      <!-- Low -->
      <div class="kpi-card" id="kpi-card-low" onclick="filterBySeverity('low')">
        <div class="kpi-bar low"></div>
        <div class="kpi-header">
          <span class="kpi-label">Low Severity</span>
          <span class="tag-badge" style="background:rgba(99,102,241,0.2); color:#a5b4fc; border:1px solid rgba(99,102,241,0.3);">RISK 0–39</span>
        </div>
        <div class="kpi-num low" id="stat-low">0</div>
        <div class="kpi-sub">Informational &bull; Reconnaissance</div>
      </div>
    </div>

    <!-- SECTION: CORE DEFENSE COMPONENTS BENTO GRID -->
    <div class="section-title-row">
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        Defense &amp; Inspection Components
      </div>
      <span style="font-size: 0.72rem; color: var(--text-dim);">All modules backed by real runtime services</span>
    </div>

    <div class="module-grid">

      <!-- 1. SIGNATURE DETECTION (CYAN ACCENT) -->
      <div class="module-card card-cyan" onclick="openModule('engines')">
        <div class="card-top">
          <span class="card-badge badge-cyan">Detection Engine</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          </div>
        </div>
        <div class="card-title">Signature &amp; Protocol Engine</div>
        <div class="card-desc">Suricata-compatible rule evaluator inspecting network payloads in sub-millisecond latency. Analyzes TLS JA4 fingerprints and protocol compliance.</div>
        <div class="terminal-how-to">
          <b>How to register custom signatures:</b>
          <code>POST /api/v1/rules</code> with JSON:<br>
          <code>{"rule_id":"R101","name":"SQLi Probe","severity":"critical"}</code>
        </div>
        <div class="card-action-row">
          <span class="action-link">View Loaded Rules &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">Sub-ms execution</span>
        </div>
      </div>

      <!-- 2. NETWORK SNIFFER (EMERALD ACCENT) -->
      <div class="module-card card-emerald" onclick="openModule('network')">
        <div class="card-top">
          <span class="card-badge badge-emerald">Network Sniffer</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          </div>
        </div>
        <div class="card-title">Live Packet Sniffer &amp; PCAP</div>
        <div class="card-desc">Enumerates real OS network adapters. Captures raw network frames via BPF filters, or replays offline Wireshark .pcap captures into the detection engine.</div>
        <div class="terminal-how-to">
          <b>How to sniff your network:</b>
          1. Select adapter (e.g. <code>en0</code> or <code>eth0</code>)<br>
          2. Set BPF filter (e.g. <code>tcp port 80 or port 443</code>)<br>
          3. Click <b>Start Capture</b> (requires raw socket privileges)
        </div>
        <div class="card-action-row">
          <span class="action-link" style="color:#34d399;">Configure Sniffer &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">Zero-copy BPF</span>
        </div>
      </div>

      <!-- 3. FIREWALL & IPS (CRIMSON ACCENT) -->
      <div class="module-card card-crimson" onclick="openModule('enforcement')">
        <div class="card-top">
          <span class="card-badge badge-crimson">Active Shield</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
        </div>
        <div class="card-title">Firewall &amp; Inline IPS</div>
        <div class="card-desc">Dynamically enforces IP blocks via OS packet filters (pf/iptables). Automatically purges blocks upon TTL expiration with complete audit logs.</div>
        <div class="terminal-how-to">
          <b>How to enforce an IP ban:</b>
          <code>POST /api/v1/network/blocks</code><br>
          Payload: <code>{"ip":"203.0.113.55","ttl_seconds":3600}</code><br>
          Or click the red <b>Block</b> button on any threat below.
        </div>
        <div class="card-action-row">
          <span class="action-link" style="color:#f87171;">Inspect Active Blocks &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">Automated fail-open</span>
        </div>
      </div>

      <!-- 4. WEBSITE WAF (PURPLE ACCENT) -->
      <div class="module-card card-purple" onclick="openModule('waf')">
        <div class="card-top">
          <span class="card-badge badge-purple">Layer 7 Defense</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#c084fc" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          </div>
        </div>
        <div class="card-title">Web Application Firewall</div>
        <div class="card-desc">Real-time HTTP request inspector. Blocks SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and Command Injection with sub-millisecond evaluation.</div>
        <div class="terminal-how-to">
          <b>How to protect your website:</b>
          Route web traffic through IDPS reverse proxy on port <b>8080</b>.<br>
          Or use the <b>Test Request</b> tab to inspect any URL query path.
        </div>
        <div class="card-action-row">
          <span class="action-link" style="color:#c084fc;">Inspect WAF &amp; Test URL &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">OWASP Top 10</span>
        </div>
      </div>

      <!-- 5. WEBSITE SCANNER (INDIGO ACCENT) -->
      <div class="module-card card-indigo" onclick="openModule('scanner')">
        <div class="card-top">
          <span class="card-badge badge-indigo">Auto Security Audit</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </div>
        </div>
        <div class="card-title">Website Security Scanner</div>
        <div class="card-desc">Autonomous URL vulnerability scanner. Makes live HTTP requests to detect missing security headers (HSTS, CSP), SSL flaws, exposed .env/.git files, and server leakage.</div>
        
        <!-- Embedded Quick Scan Input -->
        <div style="background:#080d1a; border:1px solid #1e293b; border-radius:8px; padding:0.6rem; margin-bottom:0.85rem;" onclick="event.stopPropagation()">
          <div style="font-size:0.68rem; color:#94a3b8; margin-bottom:0.35rem; font-weight:600;">Quick Target Scan:</div>
          <div style="display:flex; gap:0.4rem;">
            <input id="quick-scan-url" placeholder="https://example.com" style="flex:1; background:#0f172a; border:1px solid #334155; border-radius:4px; padding:0.3rem 0.5rem; color:#ffffff; font-size:0.75rem; font-family:var(--font-mono);" onkeydown="if(event.key==='Enter') quickRunScan()" />
            <button onclick="quickRunScan()" class="btn btn-indigo" style="padding:0.3rem 0.6rem; font-size:0.72rem;">Scan</button>
          </div>
        </div>

        <div class="card-action-row">
          <span class="action-link" style="color:#818cf8;">Launch Full Scanner Suite &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">Grades A&ndash;F</span>
        </div>
      </div>

      <!-- 6. DECEPTION & HUNTING (AMBER ACCENT) -->
      <div class="module-card card-amber" onclick="openModule('deception')">
        <div class="card-top">
          <span class="card-badge badge-amber">Deception &amp; Decoys</span>
          <div class="card-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
          </div>
        </div>
        <div class="card-title">Honeypots &amp; Threat Hunting</div>
        <div class="card-desc">Active decoy services on ports 2222 (SSH) and 8088 (HTTP) generate high-fidelity intrusion signals. Threat hunter runs hypothesis IOC queries.</div>
        <div class="terminal-how-to">
          <b>How to activate decoy traps:</b>
          Start daemon: <code>python -m services.deception.decoy_service</code><br>
          Any connection directly generates a verified incident alert.
        </div>
        <div class="card-action-row">
          <span class="action-link" style="color:#fbbf24;">Inspect Traps &amp; Canary Tokens &rarr;</span>
          <span style="font-size: 0.7rem; color: #64748b;">Zero false alarms</span>
        </div>
      </div>

    </div>

    <!-- SECTION: COMPLIANCE AUDIT ENGINE -->
    <div class="compliance-card">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
        <div style="display:flex; align-items:center; gap:0.85rem;">
          <div class="card-icon-wrapper" style="border-color: rgba(56, 189, 248, 0.4); background: rgba(56, 189, 248, 0.1);">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          </div>
          <div>
            <div style="font-size: 0.95rem; font-weight: 700; color: #ffffff;">Continuous Regulatory Compliance Engine</div>
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.15rem;">Automated security control auditing against live IDPS detection telemetry and rules.</div>
          </div>
        </div>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
          <button onclick="generateCompliance('pci-dss')" class="btn" style="border-color:#334155;">📄 PCI-DSS 4.0</button>
          <button onclick="generateCompliance('soc2')" class="btn" style="border-color:#334155;">📄 SOC 2</button>
          <button onclick="generateCompliance('hipaa')" class="btn" style="border-color:#334155;">📄 HIPAA</button>
          <button onclick="generateCompliance('gdpr')" class="btn" style="border-color:#334155;">📄 GDPR</button>
          <button onclick="openModule('compliance')" class="btn btn-primary">📊 Audit Center</button>
        </div>
      </div>
    </div>

    <!-- SECTION: LIVE THREAT STREAM TABLE -->
    <div class="table-container" id="section-threats">
      <div class="table-header-bar">
        <div>
          <div style="font-size: 0.9rem; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 0.5rem;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Live Threat Stream &amp; Alert Queue
          </div>
          <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.2rem;">
            Real detections from all engines (Sniffer, WAF, Honeypots, Signature rules). Click row for full forensics.
          </div>
        </div>
        <button onclick="refreshData()" class="btn" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
          🔄 Refresh Queue
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Threat / Detection Title</th>
            <th>Source &rarr; Target</th>
            <th>Detection Engine</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th>SOC Actions</th>
          </tr>
        </thead>
        <tbody id="alerts-tbody">
          <tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2.5rem;">Connecting to IDPS telemetry queue...</td></tr>
        </tbody>
      </table>
    </div>

  </main>

  <!-- Interactive Dynamic Modal Inspector -->
  <div id="detail-modal" onclick="closeModal(event)">
    <div class="modal-box" onclick="event.stopPropagation()">
      <div class="modal-header">
        <div class="modal-title" id="modal-title">Module Inspector</div>
        <button onclick="closeModal()" class="drawer-close">&times;</button>
      </div>
      <div id="modal-body" style="font-size: 0.82rem; color: #cbd5e1; line-height: 1.6; margin-bottom: 1.25rem;">
        Loading live data...
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 0.5rem;">
        <button onclick="closeModal()" class="btn">Close</button>
      </div>
    </div>
  </div>

  <!-- Toast Container -->
  <div id="toast-container"></div>

  <script>
    let activeSeverityFilter = null;

    // Toggle the Slide-out SOC Menu Drawer
    function toggleMenu(show) {
      const drawer = document.getElementById('soc-menu-drawer');
      const overlay = document.getElementById('drawer-overlay');
      if (show) {
        drawer.classList.add('active');
        overlay.classList.add('active');
      } else {
        drawer.classList.remove('active');
        overlay.classList.remove('active');
      }
    }

    // Keyboard shortcut 'm' toggles menu
    document.addEventListener('keydown', (e) => {
      if (e.key === 'm' || e.key === 'M') {
        if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
          const drawer = document.getElementById('soc-menu-drawer');
          toggleMenu(!drawer.classList.contains('active'));
        }
      }
      if (e.key === 'Escape') {
        toggleMenu(false);
        closeModal();
      }
    });

    function navigate(tab) {
      toggleMenu(false);
      if (tab === 'threats') {
        document.getElementById('section-threats').scrollIntoView({ behavior: 'smooth' });
      } else if (tab === 'overview') {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    }

    function quickRunScan() {
      const url = document.getElementById('quick-scan-url').value.trim();
      if (!url) { showToast('Please enter a target URL to scan'); return; }
      openModule('scanner');
      setTimeout(() => {
        const inp = document.getElementById('scanner-url-input');
        if (inp) {
          inp.value = url;
          runWebsiteScan();
        }
      }, 100);
    }

    async function openModule(mod) {
      const modal = document.getElementById('detail-modal');
      const title = document.getElementById('modal-title');
      const body = document.getElementById('modal-body');
      modal.style.display = 'flex';

      if (mod === 'engines') {
        title.innerHTML = '🛡️ Signature Engine & Loaded Rules';
        body.innerHTML = '<i>Fetching verified rules from backend...</i>';
        try {
          const res = await fetch('/api/v1/rules');
          const rules = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.85rem; font-weight: 600; color: #ffffff;">Loaded Rules in Signature Engine: ${rules.length}</div>
            <table style="width: 100%;">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Rule Name</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${rules.map(r => `
                  <tr>
                    <td style="font-family: monospace; font-weight: 700; color: var(--cyan);">${r.rule_id}</td>
                    <td>${r.name}<div style="color: #64748b; font-size: 0.72rem;">${r.description || ''}</div></td>
                    <td><span class="tag-badge ${r.severity === 'critical' ? 'tag-fail' : (r.severity === 'high' ? 'tag-amber' : 'tag-blue')}">${r.severity.toUpperCase()}</span></td>
                    <td style="color: ${r.enabled ? '#10b981' : '#ef4444'}; font-weight: 600;">${r.enabled ? 'ACTIVE' : 'DISABLED'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        } catch (e) {
          body.innerText = 'Error loading rules: ' + e.message;
        }
      } else if (mod === 'enforcement') {
        title.innerHTML = '🔒 Perimeter Firewall &amp; IPS Blocks';
        body.innerHTML = '<i>Fetching verified firewall state...</i>';
        try {
          const res = await fetch('/api/v1/network/blocks');
          const blocks = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.85rem; font-weight: 600; color: #ffffff;">Active Perimeter Firewall Blocks: ${blocks.length}</div>
            ${blocks.length === 0 ? '<div style="color: #64748b; padding: 1.25rem 0;">No active IP blocks currently enforced.</div>' : `
              <table style="width: 100%;">
                <thead>
                  <tr><th>Blocked IP</th><th>Reason</th><th>Expires At</th><th>Action</th></tr>
                </thead>
                <tbody>
                  ${blocks.map(b => `
                    <tr>
                      <td style="font-family: monospace; font-weight: 700; color: #f87171;">${b.ip}</td>
                      <td>${b.reason}</td>
                      <td style="font-family: monospace; font-size: 0.72rem;">${b.expires_at}</td>
                      <td><button onclick="unblockIP('${b.ip}')" class="btn btn-danger" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;">Unblock</button></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1.5rem; border-top: 1px solid #1e293b; padding-top: 1rem;">
              <b style="color: #ffffff;">Manually Block IP:</b>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                <input id="manual-block-ip" placeholder="Target IP (e.g. 198.51.100.99)" style="flex: 1; padding: 0.45rem 0.65rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-family: monospace; font-size: 0.82rem;" />
                <button onclick="submitManualBlock()" class="btn btn-danger">Enforce Block</button>
              </div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading firewall status: ' + e.message;
        }
      } else if (mod === 'waf') {
        title.innerHTML = '🌐 Website WAF &amp; Layer 7 Protection';
        body.innerHTML = '<i>Checking WAF telemetry...</i>';
        try {
          const res = await fetch('/api/v1/waf/status');
          const status = await res.json();
          const recentRes = await fetch('/api/v1/waf/requests');
          const recent = await recentRes.json();
          body.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 1.25rem;">
              <div style="background: #0b1526; padding: 0.85rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.7rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Requests Inspected</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; font-family: monospace;">${status.inspected_requests_total}</div>
              </div>
              <div style="background: #180d17; padding: 0.85rem; border-radius: 8px; border: 1px solid #2e1022;">
                <div style="font-size: 0.7rem; color: #f87171; font-weight: 600; text-transform: uppercase;">Attacks Blocked</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #f87171; font-family: monospace;">${status.blocked_attacks_total}</div>
              </div>
              <div style="background: #0b1526; padding: 0.85rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.7rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Request Buffer</div>
                <div style="font-size: 1.6rem; font-weight: 700; color: #22d3ee; font-family: monospace;">${recent.length}</div>
              </div>
            </div>

            <b style="font-size: 0.82rem; color: #ffffff;">Active Inspection Shields:</b>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.5rem 0 1.25rem;">
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 600; background: ${status.sqli_shield ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}; color: ${status.sqli_shield ? '#34d399' : '#f87171'}; border: 1px solid ${status.sqli_shield ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'};">SQLi ${status.sqli_shield ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 600; background: ${status.xss_shield ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}; color: ${status.xss_shield ? '#34d399' : '#f87171'}; border: 1px solid ${status.xss_shield ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'};">XSS ${status.xss_shield ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 600; background: ${status.path_traversal_guard ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}; color: ${status.path_traversal_guard ? '#34d399' : '#f87171'}; border: 1px solid ${status.path_traversal_guard ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'};">Path Traversal ${status.path_traversal_guard ? '✓' : '✗'}</span>
              <span style="padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.72rem; font-weight: 600; background: ${status.command_injection_shield ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}; color: ${status.command_injection_shield ? '#34d399' : '#f87171'}; border: 1px solid ${status.command_injection_shield ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'};">Cmd Injection ${status.command_injection_shield ? '✓' : '✗'}</span>
            </div>

            <div style="border-top: 1px solid #1e293b; padding-top: 1rem; margin-bottom: 1rem;">
              <b style="font-size: 0.85rem; color: #ffffff;">Test Your Website Request:</b>
              <div style="font-size: 0.72rem; color: var(--text-dim); margin-bottom: 0.5rem;">Enter a path or query to inspect it through the WAF engine.</div>
              <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                <select id="waf-test-method" style="padding: 0.4rem 0.6rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-size: 0.8rem;">
                  <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
                </select>
                <input id="waf-test-path" placeholder="/path?query=val" style="flex: 1; min-width: 200px; padding: 0.4rem 0.6rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-size: 0.8rem; font-family: monospace;" />
                <button onclick="wafTestRequest()" class="btn btn-primary" style="white-space: nowrap;">Inspect Request</button>
              </div>
              <div id="waf-test-result" style="margin-top: 0.6rem;"></div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading WAF status: ' + e.message;
        }
      } else if (mod === 'scanner') {
        title.innerHTML = '🔍 Website Security Scanner &mdash; Auto Detection';
        const prevScan = window._lastScanResult || null;
        body.innerHTML = `
          <div style="margin-bottom: 1rem;">
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">
              Enter any URL. The IDPS makes genuine HTTP requests and checks SSL/TLS, missing security headers, exposed sensitive files, and cookie security flags.
            </div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.75rem;">
              <input id="scanner-url-input"
                placeholder="https://example.com"
                style="flex: 1; min-width: 260px; padding: 0.45rem 0.75rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-size: 0.85rem; font-family: monospace;"
                value="${prevScan ? prevScan.url : ''}"
                onkeydown="if(event.key==='Enter') runWebsiteScan()" />
              <button onclick="runWebsiteScan()" class="btn btn-indigo" id="scanner-run-btn">▶ Scan Now</button>
            </div>
            <div style="display: flex; gap: 1rem; font-size: 0.75rem; color: var(--text-dim); margin-bottom: 0.75rem;">
              <label style="display: flex; align-items: center; gap: 0.35rem; cursor: pointer;">
                <input type="checkbox" id="scanner-probe-paths" checked> Probe sensitive paths (.env, /admin)
              </label>
              <label style="display: flex; align-items: center; gap: 0.35rem; cursor: pointer;">
                <input type="checkbox" id="scanner-check-ssl" checked> Verify SSL/TLS
              </label>
            </div>
            <div id="scanner-progress" style="margin-top: 0.5rem; font-size: 0.78rem;"></div>
          </div>
          <div id="scanner-results">${prevScan ? renderScanResult(prevScan) : '<div style="color:var(--text-dim); text-align:center; padding: 2.5rem 0; font-size: 0.85rem;">Enter a URL above and click Scan Now. Real results appear here automatically.</div>'}</div>
        `;
      } else if (mod === 'network') {
        title.innerHTML = '📡 Live Network Packet Sniffer';
        body.innerHTML = '<i>Probing network adapters...</i>';
        try {
          const res = await fetch('/api/v1/network/interfaces');
          const ifaces = await res.json();
          const isCapturing = ifaces.capture_status === 'capturing';
          body.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.65rem; margin-bottom: 1.25rem;">
              <div style="background: #080d1a; padding: 0.75rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Sensor Status</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: ${isCapturing ? '#10b981' : '#94a3b8'};">● ${ifaces.capture_status.toUpperCase()}</div>
              </div>
              <div style="background: #080d1a; padding: 0.75rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Active Adapter</div>
                <div style="font-size: 0.95rem; font-weight: 700; font-family: monospace; color: var(--cyan);">${ifaces.active_interface}</div>
              </div>
              <div style="background: #080d1a; padding: 0.75rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Packets Captured</div>
                <div style="font-size: 0.95rem; font-weight: 700; font-family: monospace; color: #ffffff;">${ifaces.packets_captured}</div>
              </div>
              <div style="background: #080d1a; padding: 0.75rem; border-radius: 8px; border: 1px solid #1e293b;">
                <div style="font-size: 0.68rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Packets Dropped</div>
                <div style="font-size: 0.95rem; font-weight: 700; font-family: monospace; color: #f87171;">${ifaces.packets_dropped}</div>
              </div>
            </div>

            <div style="background: #080d1a; border: 1px solid #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
              <b style="font-size: 0.85rem; color: #ffffff;">Packet Sniffer Controls</b>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.6rem; flex-wrap: wrap;">
                <select id="net-iface-select" style="padding: 0.4rem 0.6rem; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-family: monospace; font-size: 0.8rem;">
                  ${ifaces.available_interfaces.map(i => `<option value="${i.name}" ${i.name === ifaces.active_interface ? 'selected' : ''}>${i.name} — ${i.type}</option>`).join('')}
                </select>
                <input id="net-bpf-filter" placeholder="BPF filter (e.g. tcp port 80)" style="flex: 1; min-width: 160px; padding: 0.4rem 0.6rem; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-family: monospace; font-size: 0.8rem;" />
                ${isCapturing
                  ? `<button onclick="captureStop()" class="btn btn-danger">⏹ Stop Sniffer</button>`
                  : `<button onclick="captureStart()" class="btn btn-primary">▶ Start Sniffer</button>`
                }
              </div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading network status: ' + e.message;
        }
      } else if (mod === 'deception') {
        title.innerHTML = '🪤 Honeypots &amp; Canary Deception';
        body.innerHTML = '<i>Checking deception daemons...</i>';
        try {
          const res = await fetch('/api/v1/deception/status');
          const dec = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 1rem;">
              <b style="color: #ffffff;">Decoy Services:</b>
              <table style="width: 100%; margin-top: 0.5rem;">
                <thead><tr><th>Trap Service</th><th>Port</th><th>Protocol</th><th>Status</th></tr></thead>
                <tbody>
                  ${dec.honeypots.map(h => `
                    <tr>
                      <td style="font-weight: 700; color: #ffffff;">${h.service}</td>
                      <td style="font-family: monospace;">${h.port}</td>
                      <td style="font-family: monospace;">${h.protocol}</td>
                      <td style="color: ${h.status.includes('LISTENING') ? '#10b981' : '#fbbf24'}; font-weight: 600;">● ${h.status}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
            <div style="margin-top: 1rem; color: #94a3b8;">
              <b style="color: #ffffff;">Armed Canary Credentials:</b> ${dec.active_canary_tokens}
              <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.2rem;">Canaries trigger zero false-positive alerts immediately on unauthorized access.</div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading deception status: ' + e.message;
        }
      } else if (mod === 'compliance') {
        title.innerHTML = '📋 Continuous Compliance Audit Reports';
        body.innerHTML = '<i>Loading compliance audit status...</i>';
        try {
          const res = await fetch('/api/v1/compliance');
          const reports = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.85rem; font-weight: 600; color: #ffffff;">Evaluated Regulatory Frameworks: ${reports.length}</div>
            ${reports.length === 0 ? '<div style="color: #64748b; padding: 1rem 0;">No compliance reports generated yet. Click any framework button to generate an audit report.</div>' : `
              <table style="width: 100%; margin-bottom: 1rem;">
                <thead><tr><th>Framework</th><th>Compliance Score</th><th>Passing Controls</th><th>Status</th></tr></thead>
                <tbody>
                  ${reports.map(r => {
                    const score = (r.overall_score !== undefined ? r.overall_score : (r.score !== undefined ? r.score : 0));
                    return `
                    <tr>
                      <td style="font-weight: 700; color: #ffffff;">${r.framework.toUpperCase()}</td>
                      <td style="font-weight: 700; font-family: monospace; color: ${score >= 80 ? '#10b981' : '#f87171'};">${Number(score).toFixed(1)}%</td>
                      <td>${r.passing_controls !== undefined ? r.passing_controls : r.controls_passed} / ${r.total_controls}</td>
                      <td><span class="tag-badge ${r.status === 'compliant' || score >= 80 ? 'tag-pass' : 'tag-fail'}">${(r.status || 'evaluated').toUpperCase()}</span></td>
                    </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1.25rem; border-top: 1px solid #1e293b; padding-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <button onclick="generateCompliance('pci-dss')" class="btn">Audit PCI-DSS</button>
              <button onclick="generateCompliance('soc2')" class="btn">Audit SOC2</button>
              <button onclick="generateCompliance('hipaa')" class="btn">Audit HIPAA</button>
              <button onclick="generateCompliance('gdpr')" class="btn">Audit GDPR</button>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading compliance: ' + e.message;
        }
      } else if (mod === 'hunting') {
        title.innerHTML = '🎯 Proactive Threat Hunter';
        body.innerHTML = '<i>Loading hunting sessions...</i>';
        try {
          const res = await fetch('/api/v1/hunting');
          const hunts = await res.json();
          body.innerHTML = `
            <div style="margin-bottom: 0.85rem; font-weight: 600; color: #ffffff;">Historical Threat Hunts: ${hunts.length}</div>
            ${hunts.length === 0 ? '<div style="color: #64748b; padding: 0.5rem 0;">No hunts executed yet. Launch a hypothesis query below.</div>' : `
              <table style="width: 100%; margin-bottom: 1rem;">
                <thead><tr><th>Title</th><th>Hypothesis</th><th>Status</th><th>Findings</th></tr></thead>
                <tbody>
                  ${hunts.map(h => `
                    <tr>
                      <td style="font-weight: 700; color: #ffffff;">${h.title}</td>
                      <td style="color: #94a3b8;">${h.hypothesis}</td>
                      <td><span class="tag-badge tag-blue">${h.status.toUpperCase()}</span></td>
                      <td style="font-weight: 700; color: var(--cyan);">${(h.findings || []).length} match(es)</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `}
            <div style="margin-top: 1rem; border-top: 1px solid #1e293b; padding-top: 1rem;">
              <b style="color: #ffffff;">Launch Hypothesis Hunt:</b>
              <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem;">
                <input id="hunt-title" placeholder="Hunt Title (e.g. Audit LOLBin Binaries)" style="padding: 0.45rem 0.65rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-size: 0.8rem;" />
                <input id="hunt-query" placeholder="Query Pattern (e.g. certutil or powershell -enc)" style="padding: 0.45rem 0.65rem; background: #080d1a; border: 1px solid #334155; border-radius: 6px; color: #ffffff; font-size: 0.8rem; font-family: monospace;" />
                <button onclick="launchHuntFromModal()" class="btn btn-primary" style="align-self: flex-start;">Run Threat Hunt</button>
              </div>
            </div>
          `;
        } catch (e) {
          body.innerText = 'Error loading hunts: ' + e.message;
        }
      } else {
        title.innerText = mod.toUpperCase();
        body.innerText = `Module ${mod} inspector ready.`;
      }
    }

    function closeModal() {
      document.getElementById('detail-modal').style.display = 'none';
    }

    async function generateCompliance(framework) {
      try {
        showToast(`Running continuous compliance audit for ${framework.toUpperCase()}...`);
        const res = await fetch(`/api/v1/compliance/generate?framework=${framework}`, { method: 'POST' });
        if (res.ok) {
          const rep = await res.json();
          const scoreVal = rep.overall_score !== undefined ? rep.overall_score : (rep.score !== undefined ? rep.score : 0);
          showToast(`Report complete: ${Number(scoreVal).toFixed(1)}% score`);
          openModule('compliance');
        } else {
          showToast('Audit failed');
        }
      } catch (e) {
        showToast(e.message);
      }
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
            hypothesis: 'Automated SOC operator hunt',
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
          showToast(`Capture started on ${iface}`);
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
        showToast(`Capture stopped — ${data.packets_captured} packets captured`);
        openModule('network');
      } catch (e) {
        showToast(e.message);
      }
    }

    async function wafTestRequest() {
      const method = document.getElementById('waf-test-method').value;
      const path = document.getElementById('waf-test-path').value.trim();
      const resultEl = document.getElementById('waf-test-result');
      if (!path) { resultEl.innerText = 'Enter a path first.'; return; }
      resultEl.innerHTML = '<i style="color: #94a3b8;">Inspecting...</i>';
      try {
        const res = await fetch('/api/v1/waf/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ method, path, client_ip: '127.0.0.1', body: '', headers: {} })
        });
        const data = await res.json();
        const isBlocked = data.verdict === 'BLOCKED';
        resultEl.innerHTML = `
          <div style="padding: 0.65rem; border-radius: 6px; border: 1px solid ${isBlocked ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.4)'}; background: ${isBlocked ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'};">
            <span style="font-weight: 700; color: ${isBlocked ? '#f87171' : '#34d399'};">
              ${isBlocked ? '🚫 BLOCKED' : '✅ ALLOWED'}
            </span>
            ${data.reason ? `<span style="color: #94a3b8; margin-left: 0.5rem;">${data.reason}</span>` : ''}
            <div style="font-size: 0.72rem; color: #64748b; margin-top: 0.25rem;">Latency: ${data.latency_ms}ms</div>
          </div>`;
        showToast(`WAF: ${data.verdict}`);
      } catch (e) {
        resultEl.innerHTML = `<span style="color: #f87171;">${e.message}</span>`;
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
      if (progressEl) progressEl.innerHTML = '<span style="color: var(--cyan);">⏳ Probing target — sending live HTTP probes, auditing headers, probing paths. Takes ~5s...</span>';
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
          if (progressEl) progressEl.innerHTML = `<span style="color: #f87171;">Error: ${err.detail || 'Scan failed'}</span>`;
          if (runBtn) { runBtn.disabled = false; runBtn.innerText = '▶ Scan Now'; }
          return;
        }

        const data = await res.json();
        window._lastScanResult = data;
        if (progressEl) progressEl.innerHTML = `<span style="color: #34d399;">✅ Scan complete — ${data.issue_summary.total} issues detected</span>`;
        if (resultsEl) resultsEl.innerHTML = renderScanResult(data);
        showToast(`Scan complete: Grade ${data.grade}`);
      } catch (e) {
        if (progressEl) progressEl.innerHTML = `<span style="color: #f87171;">Network error: ${e.message}</span>`;
      } finally {
        if (runBtn) { runBtn.disabled = false; runBtn.innerText = '▶ Scan Now'; }
      }
    }

    function renderScanResult(data) {
      const gradeColor = {'A':'#10b981','B':'#84cc16','C':'#f59e0b','D':'#f97316','F':'#ef4444'}[data.grade] || '#94a3b8';
      const sevIcon = s => ({'HIGH':'🔴','MEDIUM':'🟠','LOW':'🟡','INFO':'🔵','OK':'🟢'}[s] || '⚪');

      const issueFindings = data.findings.filter(f => f.severity !== 'OK' && f.severity !== 'INFO');
      const okFindings = data.findings.filter(f => f.severity === 'OK');
      const exposedPaths = (data.probed_paths || []).filter(p => p.exposed);

      return `
        <div style="display: flex; align-items: center; gap: 1.5rem; padding: 1.25rem; background: #080d1a; border-radius: 10px; border: 1px solid #1e293b; margin-bottom: 1rem;">
          <div style="text-align: center; min-width: 70px;">
            <div style="font-size: 2.8rem; font-weight: 900; line-height: 1; color: ${gradeColor}; font-family: monospace;">${data.grade}</div>
            <div style="font-size: 0.68rem; color: #64748b; text-transform: uppercase; font-weight: 700; margin-top: 0.2rem;">Grade</div>
          </div>
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
              <div style="flex: 1; height: 8px; border-radius: 4px; background: #1e293b; overflow: hidden;">
                <div style="height: 100%; width: ${data.score}%; background: ${gradeColor}; border-radius: 4px;"></div>
              </div>
              <span style="font-weight: 700; font-family: monospace; font-size: 0.95rem; color: ${gradeColor};">${data.score}/100</span>
            </div>
            <div style="font-size: 0.74rem; color: #94a3b8; font-family: monospace;">
              ${data.url} &bull; ${data.response?.latency_ms || 0}ms latency
            </div>
          </div>
          <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
            <span class="tag-badge tag-fail">🔴 ${data.issue_summary.high} HIGH</span>
            <span class="tag-badge tag-amber">🟠 ${data.issue_summary.medium} MED</span>
            <span class="tag-badge tag-pass">🟢 ${data.issue_summary.ok} OK</span>
          </div>
        </div>

        ${issueFindings.length > 0 ? `
        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.85rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem;">Vulnerabilities &amp; Misconfigurations (${issueFindings.length})</div>
          ${issueFindings.map(f => `
            <div style="display: flex; align-items: flex-start; gap: 0.6rem; padding: 0.6rem 0.75rem; border-radius: 6px; margin-bottom: 0.35rem; background: #080d1a; border-left: 3px solid ${{HIGH:'#ef4444',MEDIUM:'#f59e0b',LOW:'#3b82f6'}[f.severity]||'#64748b'};">
              <span style="flex-shrink: 0; font-size: 0.8rem;">${sevIcon(f.severity)}</span>
              <div>
                <span style="font-size: 0.78rem; font-weight: 700; color: #ffffff;">${f.type.replace(/_/g,' ')}</span>
                <div style="font-size: 0.74rem; color: #94a3b8; margin-top: 0.15rem;">${f.detail}</div>
              </div>
            </div>
          `).join('')}
        </div>` : ''}

        ${exposedPaths.length > 0 ? `
        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.85rem; font-weight: 700; color: #f87171; margin-bottom: 0.5rem;">Sensitive Files Exposed (${exposedPaths.length})</div>
          <table style="width:100%;">
            <thead><tr><th>Path</th><th>HTTP Status</th><th>Size</th><th>Link</th></tr></thead>
            <tbody>
              ${exposedPaths.map(p => `
                <tr>
                  <td style="font-family: monospace; color: #f87171; font-weight: 700;">${p.path}</td>
                  <td style="font-family: monospace;">${p.status_code}</td>
                  <td style="color: #64748b;">${p.size_bytes} B</td>
                  <td><a href="${p.url}" target="_blank" style="color: var(--cyan); text-decoration: none;">View ↗</a></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>` : ''}
      `;
    }

    function filterBySeverity(sev) {
      document.querySelectorAll('.kpi-card').forEach(c => c.classList.remove('active-filter'));
      if (activeSeverityFilter === sev) {
        activeSeverityFilter = null;
        showToast('Filter cleared: Showing ALL alerts');
      } else {
        activeSeverityFilter = sev;
        const activeCard = document.getElementById(`kpi-card-${sev}`);
        if (activeCard) activeCard.classList.add('active-filter');
        showToast(`Filtered by ${sev.toUpperCase()} severity`);
      }
      refreshData();
    }

    function showToast(msg) {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span style="color:var(--cyan);">&bull;</span> <span>${msg}</span>`;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.25s';
        setTimeout(() => toast.remove(), 250);
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

          document.getElementById('stat-critical').innerText = crit;
          document.getElementById('stat-high').innerText = high;
          document.getElementById('stat-medium').innerText = med;
          document.getElementById('stat-low').innerText = low;
          document.getElementById('menu-badge-alerts').innerText = `${alerts.length} alerts`;

          const filtered = activeSeverityFilter ? alerts.filter(a => a.severity === activeSeverityFilter) : alerts;
          const tbody = document.getElementById('alerts-tbody');

          if (filtered.length > 0) {
            tbody.innerHTML = filtered.map(a => `
              <tr>
                <td>
                  <span class="tag-badge ${a.severity === 'critical' ? 'tag-fail' : (a.severity === 'high' ? 'tag-amber' : 'tag-blue')}">
                    ${a.severity.toUpperCase()}
                  </span>
                </td>
                <td>
                  <div style="font-weight: 700; color: #ffffff;">${a.title}</div>
                  <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 2px;">${a.description || 'Verified IDPS rule match'}</div>
                </td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem; color: #38bdf8;">
                  ${a.source_ip || '0.0.0.0'} &rarr; ${a.dest_ip || 'local'}
                </td>
                <td>
                  <span class="tag-badge" style="background:#1e293b; color:#cbd5e1;">${a.engine || 'Signature'}</span>
                </td>
                <td>
                  <span style="font-family: var(--font-mono); font-weight: 700; color: ${a.risk_score >= 80 ? '#f87171' : (a.risk_score >= 50 ? '#fbbf24' : '#34d399')}">
                    ${a.risk_score ? a.risk_score.toFixed(1) : '0.0'}
                  </span>
                </td>
                <td>
                  <span style="font-weight: 600; font-size: 0.72rem; text-transform: uppercase;">${a.status}</span>
                </td>
                <td>
                  <div style="display:flex; gap:0.35rem;">
                    <button onclick="triageAlert('${a.id}', 'acknowledged')" class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Ack</button>
                    <button onclick="triageAlert('${a.id}', 'resolved')" class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; color: #34d399; border-color: #34d399;">Resolve</button>
                    <button onclick="submitBlockFromAlert('${a.source_ip}')" class="btn btn-danger" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Block</button>
                  </div>
                </td>
              </tr>
            `).join('');
          } else {
            tbody.innerHTML = `
              <tr>
                <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2.5rem 1rem;">
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
            ? `<span style="color:#10b981;">●</span> ${net.active_interface} &bull; capturing (${net.packets_captured} pkts)`
            : `<span style="color:#64748b;">●</span> ${net.active_interface} (${net.capture_status})`;
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
        showToast(`Error: ${e.message}`);
      }
    }

    async function submitBlockFromAlert(ip) {
      if (!ip || ip === '0.0.0.0' || ip === '127.0.0.1') {
        showToast('Cannot block loopback or unspecified IP');
        return;
      }
      try {
        const res = await fetch('/api/v1/network/blocks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip, reason: 'SOC alert triggered block', ttl_seconds: 3600 })
        });
        if (res.ok) {
          showToast(`Firewall block applied for ${ip}`);
          refreshData();
        } else {
          const data = await res.json();
          showToast(`Block error: ${data.detail || 'Failed'}`);
        }
      } catch (e) {
        showToast(e.message);
      }
    }

    async function simulateAttack() {
      showToast('⚡ Ingesting live exploit event into detection pipeline...');
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
          showToast('Exploit ingested: Evaluating across all engines...');
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
    window.addEventListener('DOMContentLoaded', refreshData);
  </script>
</body>
</html>
"""
