import html
import os
import time

import streamlit as st
import streamlit.components.v1 as components
from core.cortex_graph import build_cortex_graph
from agents.breach_agent import run_breach_radar
from tools.breach_tools import (
    leakcheck_email, urlscan_domain, crtsh_subdomains,
    intelx_phonebook, dns_recon, hunter_email_lookup, hunter_domain_search
)


st.set_page_config(
    page_title="CorteX AI",
    page_icon="CX",
    layout="wide",
    initial_sidebar_state="collapsed",
)


PHASES_INTEL = [
    ("OSINT Recon", "Shodan, VirusTotal, WHOIS", 14),
    ("Threat Feeds", "CISA KEV and OTX enrichment", 28),
    ("Dark Web Sweep", "Ransomware.live, ThreatFox, URLhaus", 42),
    ("IOC Extraction", "Local AI + pattern extraction", 57),
    ("MITRE Mapping", "Tactics, techniques, risk scoring", 71),
    ("Actor Profiling", "Motivation, capability, next actions", 85),
    ("CTI Report", "PDF intelligence brief", 100),
]

PHASES_BREACH = [
    ("Breach Database", "LeakCheck multi-source scan", 16),
    ("Email Discovery", "Hunter.io employee footprint", 32),
    ("Subdomain Recon", "Certificate transparency logs", 48),
    ("Web Fingerprint", "URLScan.io technology stack", 64),
    ("Paste & Leak Sites", "IntelX phonebook search", 80),
    ("Risk Scoring", "Digital exposure assessment", 100),
]

PHASES_BREACH_EMAIL = [
    ("Email Lookup", "LeakCheck email breach scan", 50),
    ("Risk Assessment", "Breach severity scoring", 100),
]


def esc(value) -> str:
    return html.escape(str(value if value is not None else "N/A"), quote=True)


def risk_color(value) -> str:
    text = str(value or "").upper()
    if text in {"CRITICAL", "HIGH", "IMMEDIATE"}:
        return "#ff4d6d"
    if text == "MEDIUM":
        return "#ffb020"
    if text == "LOW":
        return "#21d19f"
    return "#48a7ff"


def numeric_color(value, warn=50, danger=75) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "#48a7ff"
    if score >= danger:
        return "#ff4d6d"
    if score >= warn:
        return "#ffb020"
    return "#21d19f"


def inject_global_css() -> None:
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');

:root {
    --cx-bg: #030712;
    --cx-panel: rgba(7, 13, 28, 0.76);
    --cx-panel-strong: rgba(9, 18, 38, 0.92);
    --cx-line: rgba(115, 175, 255, 0.18);
    --cx-line-strong: rgba(80, 160, 255, 0.42);
    --cx-text: #eef6ff;
    --cx-muted: #7d8ca5;
    --cx-blue: #48a7ff;
    --cx-cyan: #35e4ff;
    --cx-red: #ff4d6d;
    --cx-green: #21d19f;
    --cx-amber: #ffb020;
}

* {
    font-family: 'Inter', sans-serif !important;
    letter-spacing: 0;
}

code, pre, .mono, .cx-chip, .cx-kicker, .cx-phase-index {
    font-family: 'JetBrains Mono', monospace !important;
}

.stApp {
    color: var(--cx-text);
    background:
        radial-gradient(circle at 24% 0%, rgba(30, 111, 255, 0.26), transparent 32rem),
        radial-gradient(circle at 82% 12%, rgba(53, 228, 255, 0.12), transparent 34rem),
        linear-gradient(135deg, #02040a 0%, #060b18 42%, #030712 100%) !important;
}

.main .block-container {
    max-width: 1500px;
    padding: 1.15rem 1.6rem 2.5rem !important;
}

.block-container,
[data-testid="stMainBlockContainer"] {
    padding-top: 1rem !important;
}

header[data-testid="stHeader"],
#MainMenu,
footer {
    display: none !important;
}

[data-testid="stSidebar"] {
    display: none !important;
}

[data-testid="collapsedControl"] {
    display: none !important;
}

.cx-topbar {
    position: sticky;
    top: 0.45rem;
    z-index: 50;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    min-height: 64px;
    margin-bottom: 0.9rem;
    padding: 0.62rem 0.75rem;
    border: 1px solid rgba(115, 175, 255, 0.18);
    border-radius: 16px;
    background: rgba(3, 7, 18, 0.76);
    box-shadow: 0 18px 55px rgba(0, 0, 0, 0.34);
    backdrop-filter: blur(20px);
}

.cx-nav {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
    gap: 0.4rem;
}

.cx-nav-pill {
    min-height: 2rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.32rem 0.72rem;
    border-radius: 999px;
    border: 1px solid rgba(115, 175, 255, 0.12);
    background: rgba(255, 255, 255, 0.035);
    color: #9fb0ca;
    font-size: 0.76rem;
    font-weight: 700;
}

.cx-nav-pill.active {
    color: #eef6ff;
    border-color: rgba(72, 167, 255, 0.38);
    background: rgba(72, 167, 255, 0.12);
    box-shadow: 0 0 26px rgba(72, 167, 255, 0.12);
}

.cx-command-wrap {
    max-width: 1080px;
    margin: 0.95rem auto 1.1rem;
}

.cx-command-shell {
    padding: 1.05rem;
    border-radius: 16px;
    border: 1px solid rgba(115, 175, 255, 0.2);
    background:
        radial-gradient(circle at 50% 0%, rgba(72, 167, 255, 0.15), transparent 24rem),
        rgba(7, 13, 28, 0.78);
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.35);
    backdrop-filter: blur(18px);
}

.cx-command-shell.red {
    border-color: rgba(255, 77, 109, 0.24);
    background:
        radial-gradient(circle at 50% 0%, rgba(255, 77, 109, 0.14), transparent 24rem),
        rgba(7, 13, 28, 0.78);
}

.cx-command-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.8rem;
    padding-bottom: 0.78rem;
    margin-bottom: 0.85rem;
    border-bottom: 1px solid rgba(115, 175, 255, 0.14);
}

.cx-command-copy {
    color: var(--cx-muted);
    font-size: 0.82rem;
    line-height: 1.55;
    margin-top: 0.22rem;
}

.cx-brand {
    border: 1px solid var(--cx-line);
    border-radius: 12px;
    padding: 1rem;
    background: linear-gradient(145deg, rgba(72, 167, 255, 0.1), rgba(255, 255, 255, 0.02));
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.32);
}

.cx-logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.cx-mark {
    width: 38px;
    height: 38px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    color: white;
    font-weight: 800;
    background:
        radial-gradient(circle at 35% 30%, rgba(255,255,255,0.95), transparent 0.18rem),
        conic-gradient(from 210deg, var(--cx-blue), var(--cx-cyan), #7c3aed, var(--cx-blue));
    box-shadow: 0 0 28px rgba(72, 167, 255, 0.36);
}

.cx-brand-title {
    color: var(--cx-text);
    font-weight: 800;
    font-size: 1.15rem;
}

.cx-brand-sub {
    color: var(--cx-muted);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08rem;
}

.cx-kicker {
    color: var(--cx-cyan);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.14rem;
}

.cx-panel {
    background: var(--cx-panel);
    border: 1px solid var(--cx-line);
    border-radius: 12px;
    box-shadow: 0 18px 55px rgba(0, 0, 0, 0.32);
    backdrop-filter: blur(18px);
}

.cx-section {
    padding: 1.05rem 1.15rem;
    margin: 0.85rem 0;
}

.cx-section-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.8rem;
    padding-bottom: 0.65rem;
    border-bottom: 1px solid rgba(115, 175, 255, 0.14);
}

.cx-title {
    color: var(--cx-text);
    font-weight: 800;
    font-size: 1.05rem;
}

.cx-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.38rem;
    min-height: 1.65rem;
    padding: 0.25rem 0.58rem;
    border-radius: 999px;
    color: #cfe8ff;
    background: rgba(72, 167, 255, 0.1);
    border: 1px solid rgba(72, 167, 255, 0.24);
    font-size: 0.66rem;
    text-transform: uppercase;
}

.cx-chip.red {
    color: #ffd4dc;
    background: rgba(255, 77, 109, 0.11);
    border-color: rgba(255, 77, 109, 0.3);
}

.cx-dot {
    width: 0.48rem;
    height: 0.48rem;
    border-radius: 50%;
    background: var(--cx-cyan);
    box-shadow: 0 0 12px var(--cx-cyan);
}

.cx-dot.red {
    background: var(--cx-red);
    box-shadow: 0 0 12px var(--cx-red);
}

.cx-metrics {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 0.85rem;
    margin: 0.9rem 0 1.1rem;
}

.cx-metric {
    min-height: 118px;
    position: relative;
    overflow: hidden;
    padding: 0.9rem;
    border-radius: 12px;
    border: 1px solid rgba(115, 175, 255, 0.18);
    background:
        linear-gradient(145deg, rgba(10, 20, 44, 0.92), rgba(4, 9, 21, 0.82)),
        radial-gradient(circle at top right, rgba(72, 167, 255, 0.22), transparent 12rem);
}

.cx-metric::after {
    content: '';
    position: absolute;
    inset: auto 0 0 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent, var(--cx-blue)), transparent);
}

.cx-metric-label {
    color: var(--cx-muted);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08rem;
}

.cx-metric-value {
    color: var(--accent, var(--cx-text));
    font-size: clamp(1.35rem, 2vw, 2rem);
    font-weight: 800;
    margin-top: 0.45rem;
    overflow-wrap: anywhere;
    text-shadow: 0 0 24px color-mix(in srgb, var(--accent, var(--cx-blue)) 42%, transparent);
}

.cx-metric-sub {
    color: #8797b0;
    font-size: 0.76rem;
    margin-top: 0.35rem;
}

.cx-phase-grid {
    display: grid;
    grid-template-columns: repeat(7, minmax(0, 1fr));
    gap: 0.55rem;
    margin: 0.8rem 0 1rem;
}

.cx-phase {
    min-height: 104px;
    padding: 0.72rem;
    border-radius: 10px;
    border: 1px solid rgba(115, 175, 255, 0.15);
    background: rgba(7, 15, 32, 0.7);
    position: relative;
    overflow: hidden;
}

.cx-phase.active {
    border-color: rgba(72, 167, 255, 0.55);
    background: rgba(72, 167, 255, 0.11);
    box-shadow: 0 0 26px rgba(72, 167, 255, 0.12);
}

.cx-phase.red.active {
    border-color: rgba(255, 77, 109, 0.55);
    background: rgba(255, 77, 109, 0.11);
    box-shadow: 0 0 26px rgba(255, 77, 109, 0.12);
}

.cx-phase-index {
    color: var(--cx-cyan);
    font-size: 0.66rem;
    margin-bottom: 0.34rem;
}

.cx-phase-name {
    color: var(--cx-text);
    font-size: 0.78rem;
    font-weight: 700;
}

.cx-phase-desc {
    color: var(--cx-muted);
    font-size: 0.68rem;
    line-height: 1.35;
    margin-top: 0.3rem;
}

.cx-alert {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.9rem 1rem;
    border-radius: 12px;
    border: 1px solid rgba(115, 175, 255, 0.18);
    background: linear-gradient(90deg, rgba(72, 167, 255, 0.13), rgba(7, 13, 28, 0.8));
    margin: 0.8rem 0;
}

.cx-alert.red {
    border-color: rgba(255, 77, 109, 0.24);
    background: linear-gradient(90deg, rgba(255, 77, 109, 0.13), rgba(7, 13, 28, 0.8));
}

.cx-alert-main {
    font-weight: 800;
    font-size: 1.05rem;
}

.cx-alert-sub {
    color: var(--cx-muted);
    font-size: 0.8rem;
}

.cx-card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 0.85rem;
}

.cx-data-card {
    padding: 1rem;
    border-radius: 12px;
    border: 1px solid rgba(115, 175, 255, 0.17);
    background: rgba(6, 13, 28, 0.75);
}

.cx-data-title {
    color: #cfe8ff;
    font-size: 0.85rem;
    font-weight: 800;
    margin-bottom: 0.45rem;
}

.cx-muted {
    color: var(--cx-muted);
}

.cx-list-item {
    padding: 0.62rem 0.7rem;
    margin: 0.45rem 0;
    border-radius: 9px;
    background: rgba(255, 255, 255, 0.035);
    border: 1px solid rgba(115, 175, 255, 0.12);
    color: #dcecff;
}

.cx-chain {
    padding: 1rem;
    margin-bottom: 0.8rem;
    border-radius: 12px;
    border: 1px solid rgba(255, 77, 109, 0.22);
    background: linear-gradient(145deg, rgba(40, 8, 16, 0.62), rgba(7, 13, 28, 0.88));
}

.cx-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    margin-top: 0.7rem;
}

.cx-pill {
    border-radius: 999px;
    border: 1px solid rgba(72, 167, 255, 0.22);
    background: rgba(72, 167, 255, 0.09);
    color: #cfe8ff;
    padding: 0.28rem 0.58rem;
    font-size: 0.72rem;
}

.stTextInput input,
.stSelectbox div[data-baseweb="select"] {
    background: rgba(7, 13, 28, 0.9) !important;
    border: 1px solid rgba(115, 175, 255, 0.22) !important;
    color: #eef6ff !important;
    border-radius: 10px !important;
}

.stTextInput input:focus {
    border-color: rgba(72, 167, 255, 0.8) !important;
    box-shadow: 0 0 0 1px rgba(72, 167, 255, 0.32), 0 0 26px rgba(72, 167, 255, 0.18) !important;
}

.stButton > button {
    min-height: 2.75rem;
    border-radius: 10px !important;
    border: 1px solid rgba(72, 167, 255, 0.38) !important;
    background: linear-gradient(135deg, rgba(72, 167, 255, 0.9), rgba(35, 73, 255, 0.72)) !important;
    color: #ffffff !important;
    font-weight: 800 !important;
    box-shadow: 0 14px 36px rgba(35, 73, 255, 0.25) !important;
}

.stButton > button:hover {
    border-color: rgba(53, 228, 255, 0.9) !important;
    box-shadow: 0 18px 46px rgba(53, 228, 255, 0.25) !important;
    transform: translateY(-1px);
}

.stRadio [role="radiogroup"] {
    gap: 0.4rem;
}

.stRadio [data-testid="stMarkdownContainer"] p {
    font-weight: 700;
    color: #eef6ff;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 0.35rem;
    background: rgba(5, 10, 22, 0.56) !important;
    border: 1px solid rgba(115, 175, 255, 0.14);
    border-radius: 12px;
    padding: 0.25rem;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 9px !important;
    color: #8ea0bd !important;
    padding: 0.56rem 0.85rem !important;
}

.stTabs [aria-selected="true"] {
    color: #eef6ff !important;
    background: rgba(72, 167, 255, 0.14) !important;
}

.stProgress > div > div {
    background: linear-gradient(90deg, var(--cx-blue), var(--cx-cyan)) !important;
}

[data-testid="stJson"],
.stDataFrame {
    border: 1px solid rgba(115, 175, 255, 0.14) !important;
    border-radius: 10px !important;
    overflow: hidden;
}

hr {
    border-color: rgba(115, 175, 255, 0.14) !important;
}

@media (max-width: 1100px) {
    .cx-metrics {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .cx-phase-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}

@media (max-width: 680px) {
    .main .block-container {
        padding: 0.85rem !important;
    }
    .cx-metrics,
    .cx-phase-grid {
        grid-template-columns: 1fr;
    }
    .cx-alert {
        align-items: flex-start;
        flex-direction: column;
    }
    .cx-topbar {
        position: relative;
        top: 0;
        align-items: flex-start;
        flex-direction: column;
    }
}
</style>
        """,
        unsafe_allow_html=True,
    )


def render_top_bar(mode: str) -> None:
    st.markdown(
        f"""
<div class="cx-topbar">
  <div class="cx-logo">
    <div class="cx-mark">CX</div>
    <div>
      <div class="cx-brand-title">CorteX AI</div>
      <div class="cx-brand-sub">Autonomous CTI OSINT</div>
    </div>
  </div>
  <div class="cx-nav">
    <div class="cx-nav-pill {'active' if mode == 'Intelligence Mode' else ''}">Intelligence</div>
    <div class="cx-nav-pill {'active' if mode == 'BREACH RADAR' else ''}">Breach Radar</div>
    <div class="cx-nav-pill">Reports</div>
    <div class="cx-nav-pill">MITRE</div>
  </div>
  <div class="cx-chip">
    <span class="cx-dot"></span>{esc(mode)}
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


def render_mode_selector(mode_label: str) -> tuple[str, bool]:
    left_pad, center, right_pad = st.columns([0.08, 0.84, 0.08])
    with center:
        mode = st.radio(
            "OPERATING MODE",
            ["Intelligence Mode", "BREACH RADAR"],
            horizontal=True,
            key="mode_selector",
        )
    return mode, mode == "BREACH RADAR"


def render_mission_console(mode: str, is_breach: bool) -> tuple[str, str, str, bool]:
    """Returns (target, target_type, breach_sub_mode, run_btn)"""
    left_pad, center, right_pad = st.columns([0.08, 0.84, 0.08])
    breach_sub_mode = "domain"
    with center:
        if is_breach:
            copy = "Scan domains for breached credentials and digital footprint, or look up individual email addresses in breach databases."
        else:
            copy = "Collect OSINT, threat-feed, dark-web, MITRE and actor-profile intelligence from one central cockpit."

        st.markdown(
            f"""
<div class="cx-command-wrap">
  <div class="cx-command-shell">
    <div class="cx-command-title">
      <div>
        <div class="cx-kicker">{'BREACH CONFIG' if is_breach else 'INTEL CONFIG'}</div>
        <div class="cx-command-copy">{esc(copy)}</div>
      </div>
      <div class="cx-chip">
        <span class="cx-dot"></span>Ready for analysis
      </div>
    </div>
  </div>
</div>
            """,
            unsafe_allow_html=True,
        )

        if is_breach:
            # Sub-mode selector for breach radar
            sub_col, input_col, run_col = st.columns([0.22, 0.52, 0.26])
            with sub_col:
                breach_sub_mode = st.radio(
                    "Scan Mode",
                    ["Domain Scan", "Email Lookup"],
                    horizontal=False,
                    key="breach_sub_mode",
                )
            with input_col:
                if breach_sub_mode == "Email Lookup":
                    target = st.text_input("Email Address", placeholder="user@example.com")
                else:
                    target = st.text_input("Domain", placeholder="example.com")
                target_type = "domain"
            with run_col:
                st.markdown("<div style='height:1.78rem;'></div>", unsafe_allow_html=True)
                run_btn = st.button("RUN BREACH SCAN", use_container_width=True)
        else:
            input_col, type_col, run_col = st.columns([0.52, 0.2, 0.28])
            with input_col:
                target = st.text_input("Target", placeholder="185.220.101.34")
            with type_col:
                target_type = st.selectbox("Target Type", ["ip", "domain"])
            with run_col:
                st.markdown("<div style='height:1.78rem;'></div>", unsafe_allow_html=True)
                run_btn = st.button("RUN PIPELINE", use_container_width=True)

        section_header("Pipeline Map", "Centered controls")
        if is_breach:
            phases = PHASES_BREACH_EMAIL if (breach_sub_mode == "Email Lookup") else PHASES_BREACH
        else:
            phases = PHASES_INTEL
        render_phase_grid(phases, active_count=0)

    return target.strip(), target_type, breach_sub_mode, run_btn


def render_hero(mode: str, target: str = "") -> None:
    accent = "#48a7ff"
    accent2 = "#35e4ff"
    title = "CorteX AI Threat Intelligence"
    headline = "Defending the digital frontier on the dot."
    subcopy = "Autonomous OSINT, threat-feed intelligence, dark-web exposure checks, MITRE mapping, actor profiling, and PDF reporting."
    target_label = target or "185.220.101.34"
    status = "INTEL PIPELINE READY"

    template = """
<!doctype html>
<html>
<head>
<meta charset="UTF-8" />
<style>
html, body {
  margin: 0;
  overflow: hidden;
  background: transparent;
  font-family: Inter, Arial, sans-serif;
}
.hero {
  height: 520px;
  position: relative;
  border: 1px solid rgba(115,175,255,0.2);
  border-radius: 20px;
  overflow: hidden;
  background:
    radial-gradient(circle at 62% 38%, __ACCENT_ALPHA__, transparent 19rem),
    radial-gradient(circle at 10% 15%, rgba(53,228,255,0.12), transparent 18rem),
    linear-gradient(135deg, rgba(3,7,18,0.98), rgba(6,13,28,0.92) 52%, rgba(2,4,10,0.98));
  box-shadow: inset 0 0 90px rgba(72,167,255,0.06), 0 24px 80px rgba(0,0,0,0.45);
}
#stage {
  position: absolute;
  inset: 0;
  opacity: 0.98;
}
.scanline {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(0deg, rgba(255,255,255,0.025) 0, rgba(255,255,255,0.025) 1px, transparent 1px, transparent 7px);
  mix-blend-mode: screen;
  opacity: 0.38;
}
.hud {
  position: absolute;
  inset: 0;
  z-index: 2;
  pointer-events: none;
}
.nav {
  position: absolute;
  left: 34px;
  top: 30px;
  display: flex;
  align-items: center;
  gap: 10px;
  color: #eef6ff;
  font-weight: 800;
  letter-spacing: 0;
}
.mark {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  color: white;
  font-size: 12px;
  background: conic-gradient(from 220deg, __ACCENT__, __ACCENT2__, #7c3aed, __ACCENT__);
  box-shadow: 0 0 28px __ACCENT_GLOW__;
}
.top-pill {
  position: absolute;
  right: 34px;
  top: 30px;
  color: #dbeafe;
  border: 1px solid rgba(255,255,255,0.16);
  background: rgba(2,6,23,0.48);
  border-radius: 999px;
  padding: 10px 14px;
  font-size: 12px;
  backdrop-filter: blur(14px);
}
.copy {
  position: absolute;
  left: 34px;
  top: 132px;
  width: min(600px, 58%);
}
.kicker {
  color: __ACCENT2__;
  font-family: "JetBrains Mono", monospace;
  font-size: 12px;
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 18px;
}
.headline {
  color: white;
  font-size: clamp(42px, 7vw, 76px);
  line-height: 0.92;
  font-weight: 500;
  letter-spacing: 0;
  text-shadow: 0 18px 80px rgba(0,0,0,0.75);
}
.headline span {
  color: __ACCENT2__;
}
.subcopy {
  margin-top: 22px;
  max-width: 430px;
  color: #9fb0ca;
  font-size: 14px;
  line-height: 1.6;
}
.status {
  position: absolute;
  left: 34px;
  bottom: 32px;
  display: grid;
  grid-template-columns: repeat(3, minmax(120px, 1fr));
  gap: 10px;
  width: min(610px, calc(100% - 68px));
}
.stat {
  border: 1px solid rgba(115,175,255,0.14);
  background: rgba(2,6,23,0.5);
  border-radius: 12px;
  padding: 12px;
  backdrop-filter: blur(16px);
}
.stat-label {
  color: #6f829f;
  font-family: "JetBrains Mono", monospace;
  font-size: 10px;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.stat-value {
  color: #eef6ff;
  font-size: 14px;
  font-weight: 800;
  margin-top: 5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.float {
  position: absolute;
  right: 48px;
  color: #dbeafe;
  border: 1px solid rgba(115,175,255,0.14);
  background: rgba(2,6,23,0.42);
  border-radius: 12px;
  padding: 12px 14px;
  backdrop-filter: blur(16px);
  animation: drift 5s ease-in-out infinite;
}
.float .small {
  color: #7d8ca5;
  font-family: "JetBrains Mono", monospace;
  font-size: 10px;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.float .big {
  color: __ACCENT2__;
  font-size: 20px;
  font-weight: 800;
  margin-top: 3px;
}
.float.a { top: 150px; }
.float.b { top: 260px; right: 90px; animation-delay: -1.7s; }
.float.c { bottom: 60px; animation-delay: -3.2s; }
.fallback {
  position:absolute;
  inset:0;
  display:none;
  place-items:center;
  color:#dbeafe;
  background: radial-gradient(circle, __ACCENT_ALPHA__, transparent 20rem);
}
@keyframes drift {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-10px); }
}
@media (max-width: 760px) {
  .hero { height: 620px; }
  .copy { width: calc(100% - 54px); left: 27px; top: 116px; }
  .headline { font-size: 48px; }
  .float { display: none; }
  .status { grid-template-columns: 1fr; left: 27px; width: calc(100% - 54px); }
}
</style>
</head>
<body>
<div class="hero">
  <canvas id="stage"></canvas>
  <div class="fallback" id="fallback">CorteX neural scene loading...</div>
  <div class="scanline"></div>
  <div class="hud">
    <div class="nav"><div class="mark">CX</div><div>CorteX AI</div></div>
    <div class="top-pill">Live cyber operations cockpit</div>
    <div class="copy">
      <div class="kicker">[ __TITLE__ ]</div>
      <div class="headline">__HEADLINE__ <span>.</span></div>
      <div class="subcopy">__SUBCOPY__</div>
    </div>
    <div class="float a"><div class="small">Threat Mesh</div><div class="big">ACTIVE</div></div>
    <div class="float b"><div class="small">Target</div><div class="big">__TARGET__</div></div>
    <div class="float c"><div class="small">Neural Core</div><div class="big">ONLINE</div></div>
    <div class="status">
      <div class="stat"><div class="stat-label">Status</div><div class="stat-value">__STATUS__</div></div>
      <div class="stat"><div class="stat-label">Mode</div><div class="stat-value">__MODE__</div></div>
      <div class="stat"><div class="stat-label">Visual Engine</div><div class="stat-value">Three.js WebGL</div></div>
    </div>
  </div>
</div>
<script type="module">
import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.164.1/build/three.module.js';

const canvas = document.getElementById('stage');
const hero = document.querySelector('.hero');
const fallback = document.getElementById('fallback');
let renderer, scene, camera, points, core, lines;
const accent = new THREE.Color('__ACCENT__');
const accent2 = new THREE.Color('__ACCENT2__');

function init() {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(45, hero.clientWidth / hero.clientHeight, 0.1, 100);
  camera.position.set(0, 0, 9.5);

  const group = new THREE.Group();
  group.position.set(1.9, 0.2, 0);
  scene.add(group);

  const count = 880;
  const positions = new Float32Array(count * 3);
  const colors = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    const t = Math.random() * Math.PI * 2;
    const p = Math.acos(2 * Math.random() - 1);
    const radius = 1.55 + Math.sin(t * 3) * 0.32 + (Math.random() - 0.5) * 0.28;
    const x = radius * Math.sin(p) * Math.cos(t) * 1.55;
    const y = radius * Math.cos(p) * 0.92 + Math.sin(t * 2.2) * 0.22;
    const z = radius * Math.sin(p) * Math.sin(t) * 0.8;
    positions[i * 3] = x;
    positions[i * 3 + 1] = y;
    positions[i * 3 + 2] = z;
    const c = accent.clone().lerp(accent2, Math.random() * 0.7);
    colors[i * 3] = c.r;
    colors[i * 3 + 1] = c.g;
    colors[i * 3 + 2] = c.b;
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  geo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
  points = new THREE.Points(
    geo,
    new THREE.PointsMaterial({ size: 0.025, vertexColors: true, transparent: true, opacity: 0.9 })
  );
  group.add(points);

  core = new THREE.Mesh(
    new THREE.IcosahedronGeometry(1.22, 4),
    new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.16 })
  );
  group.add(core);

  const linePositions = [];
  for (let i = 0; i < 130; i++) {
    const a = Math.floor(Math.random() * count) * 3;
    const b = Math.floor(Math.random() * count) * 3;
    linePositions.push(
      positions[a], positions[a + 1], positions[a + 2],
      positions[b], positions[b + 1], positions[b + 2]
    );
  }
  const lineGeo = new THREE.BufferGeometry();
  lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
  lines = new THREE.LineSegments(
    lineGeo,
    new THREE.LineBasicMaterial({ color: accent2, transparent: true, opacity: 0.12 })
  );
  group.add(lines);

  const starGeo = new THREE.BufferGeometry();
  const starPositions = [];
  for (let i = 0; i < 430; i++) {
    starPositions.push((Math.random() - 0.5) * 16, (Math.random() - 0.5) * 9, -2 - Math.random() * 7);
  }
  starGeo.setAttribute('position', new THREE.Float32BufferAttribute(starPositions, 3));
  const stars = new THREE.Points(
    starGeo,
    new THREE.PointsMaterial({ color: 0xbfdcff, size: 0.012, transparent: true, opacity: 0.75 })
  );
  scene.add(stars);

  function resize() {
    const w = hero.clientWidth;
    const h = hero.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);
  resize();

  let mouseX = 0;
  let mouseY = 0;
  hero.addEventListener('pointermove', (event) => {
    const rect = hero.getBoundingClientRect();
    mouseX = ((event.clientX - rect.left) / rect.width - 0.5) * 0.7;
    mouseY = ((event.clientY - rect.top) / rect.height - 0.5) * 0.45;
  });

  function animate(t) {
    requestAnimationFrame(animate);
    const time = t * 0.001;
    group.rotation.y = time * 0.12 + mouseX;
    group.rotation.x = Math.sin(time * 0.45) * 0.08 + mouseY;
    points.rotation.z = Math.sin(time * 0.32) * 0.04;
    core.rotation.x = time * 0.22;
    core.rotation.y = time * 0.28;
    lines.material.opacity = 0.09 + Math.sin(time * 1.5) * 0.035;
    renderer.render(scene, camera);
  }
  animate(0);
}

try {
  init();
} catch (err) {
  console.error(err);
  fallback.style.display = 'grid';
}
</script>
</body>
</html>
    """
    html_doc = (
        template.replace("__ACCENT__", accent)
        .replace("__ACCENT2__", accent2)
        .replace("__ACCENT_ALPHA__", f"{accent}22")
        .replace("__ACCENT_GLOW__", f"{accent}66")
        .replace("__TITLE__", esc(title))
        .replace("__HEADLINE__", esc(headline))
        .replace("__SUBCOPY__", esc(subcopy))
        .replace("__TARGET__", esc(target_label))
        .replace("__STATUS__", esc(status))
        .replace("__MODE__", esc(mode))
    )
    components.html(html_doc, height=540, scrolling=False)


def render_phase_grid(phases, active_count: int = 0, red: bool = False) -> None:
    cards = []
    for idx, (name, desc, _) in enumerate(phases, 1):
        klass = "cx-phase"
        if red:
            klass += " red"
        if idx <= active_count:
            klass += " active"
        cards.append(
            f"""
<div class="{klass}">
  <div class="cx-phase-index">PHASE {idx:02d}</div>
  <div class="cx-phase-name">{esc(name)}</div>
  <div class="cx-phase-desc">{esc(desc)}</div>
</div>
            """
        )
    st.markdown(f'<div class="cx-phase-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value, sub: str = "", color: str = "#48a7ff") -> str:
    return f"""
<div class="cx-metric" style="--accent:{color};">
  <div class="cx-metric-label">{esc(label)}</div>
  <div class="cx-metric-value">{esc(value)}</div>
  <div class="cx-metric-sub">{esc(sub)}</div>
</div>
    """


def render_metrics(metrics: list[tuple[str, object, str, str]]) -> None:
    cards = "".join(metric_card(*item) for item in metrics)
    st.markdown(f'<div class="cx-metrics">{cards}</div>', unsafe_allow_html=True)


def section_header(title: str, tag: str, red: bool = False) -> None:
    st.markdown(
        f"""
<div class="cx-section-head">
  <div class="cx-title">{esc(title)}</div>
  <div class="cx-chip {'red' if red else ''}"><span class="cx-dot {'red' if red else ''}"></span>{esc(tag)}</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def result_alert(label: str, target: str, color: str, red: bool = False) -> None:
    st.markdown(
        f"""
<div class="cx-alert {'red' if red else ''}">
  <div>
    <div class="cx-alert-main" style="color:{color};">{esc(label)}</div>
    <div class="cx-alert-sub">Target: <span class="mono">{esc(target)}</span></div>
  </div>
  <div class="cx-chip {'red' if red else ''}"><span class="cx-dot {'red' if red else ''}"></span>Analysis complete</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def render_json_card(title: str, data) -> None:
    st.markdown(f'<div class="cx-data-title">{esc(title)}</div>', unsafe_allow_html=True)
    st.json(data)


def run_intel_pipeline(target: str, target_type: str) -> None:
    st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
    section_header("Autonomous Intelligence Pipeline", "Live execution")
    render_phase_grid(PHASES_INTEL, active_count=0)
    progress_bar = st.progress(0)
    status = st.empty()
    st.markdown("</div>", unsafe_allow_html=True)

    def update(name: str, desc: str, pct: int):
        status.markdown(
            f'<div class="cx-chip"><span class="cx-dot"></span>{esc(name)}: {esc(desc)}</div>',
            unsafe_allow_html=True,
        )
        progress_bar.progress(pct)

    try:
        from agents.osint_agent import run_osint_agent
        from agents.threat_feed_agent import run_threat_feed_agent
        from agents.darkweb_agent import run_darkweb_agent
        from agents.ioc_agent import run_ioc_agent
        from agents.mitre_agent import run_mitre_agent
        from agents.profiling_agent import run_profiling_agent
        from agents.report_agent import generate_report

        state = {
            "target": target, "target_type": target_type,
            "osint_data": None, "threat_data": None, "darkweb_data": None,
            "ioc_data": None, "mitre_data": None, "profile_data": None,
            "report_path": None,
        }

        # Phase 1 – OSINT
        update("OSINT Recon", "Shodan, VirusTotal, WHOIS", 14)
        try:
            state["osint_data"] = run_osint_agent(target)
        except Exception as e:
            state["osint_data"] = {"error": str(e)}

        # Phase 2 – Threat Feeds
        update("Threat Feeds", "CISA KEV and OTX enrichment", 28)
        try:
            state["threat_data"] = run_threat_feed_agent(target, target_type)
        except Exception as e:
            state["threat_data"] = {"error": str(e), "threat_level": "UNKNOWN", "otx_alienvault": {}}

        # Phase 3 – Dark Web
        update("Dark Web Sweep", "Ransomware.live, ThreatFox, URLhaus", 42)
        try:
            state["darkweb_data"] = run_darkweb_agent(target)
        except Exception as e:
            state["darkweb_data"] = {
                "error": str(e),
                "dark_web_exposure_score": 0,
                "exposure_level": "UNKNOWN",
                "ransomware_leaks": {"matches_found": 0, "note": str(e)},
                "threatfox": {"matches_found": 0},
                "urlhaus": {"malicious_urls": 0},
            }

        # Phase 4 – IOC Extraction
        update("IOC Extraction", "Local AI + pattern extraction", 57)
        try:
            combined_text = str(state["osint_data"]) + str(state["threat_data"]) + str(state["darkweb_data"])
            state["ioc_data"] = run_ioc_agent(combined_text)
        except Exception as e:
            state["ioc_data"] = {"error": str(e)}

        # Phase 5 – MITRE Mapping
        update("MITRE Mapping", "Tactics, techniques, risk scoring", 71)
        try:
            state["mitre_data"] = run_mitre_agent(
                state["osint_data"], state["threat_data"], state["darkweb_data"]
            )
        except Exception as e:
            state["mitre_data"] = {"error": str(e), "risk_score": 0}

        # Phase 6 – Actor Profiling
        update("Actor Profiling", "Motivation, capability, next actions", 85)
        try:
            state["profile_data"] = run_profiling_agent(
                target, state["osint_data"], state["threat_data"],
                state["darkweb_data"], state["mitre_data"]
            )
        except Exception as e:
            state["profile_data"] = {"error": str(e), "overall_threat_rating": "UNKNOWN"}

        # Phase 7 – Report
        update("CTI Report", "PDF intelligence brief", 95)
        try:
            state["report_path"] = generate_report(
                target, state["osint_data"], state["threat_data"],
                state["darkweb_data"], state["mitre_data"], state["profile_data"]
            )
        except Exception as e:
            state["report_path"] = None

        progress_bar.progress(100)
        status.markdown(
            '<div class="cx-chip"><span class="cx-dot"></span>Intelligence pipeline complete</div>',
            unsafe_allow_html=True,
        )
        render_intel_results(state, target)

    except Exception as exc:
        st.error(f"Pipeline error: {exc}")
        st.exception(exc)



def render_intel_results(result: dict, target: str) -> None:
    profile = result.get("profile_data") or {}
    threat_data = result.get("threat_data") or {}
    mitre_data = result.get("mitre_data") or {}
    darkweb_data = result.get("darkweb_data") or {}

    rating = profile.get("overall_threat_rating", "UNKNOWN")
    threat_level = threat_data.get("threat_level", "LOW")
    pulse_count = threat_data.get("otx_alienvault", {}).get("pulse_count", 0)
    risk_score = mitre_data.get("risk_score", 0)
    dark_score = darkweb_data.get("dark_web_exposure_score", 0)

    result_alert(f"{rating} THREAT", target, risk_color(rating))
    render_metrics(
        [
            ("Threat Rating", rating, "AI profile verdict", risk_color(rating)),
            ("Threat Level", threat_level, "Threat-feed severity", risk_color(threat_level)),
            ("OTX Pulses", pulse_count, "AlienVault references", numeric_color(pulse_count, 1, 10)),
            ("MITRE Risk", f"{risk_score}/100", "Mapped attack risk", numeric_color(risk_score)),
            ("Dark Web", f"{dark_score}/100", "Exposure score", numeric_color(dark_score)),
        ]
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["OSINT", "Dark Web", "MITRE ATT&CK", "Threat Profile", "Report"]
    )

    with tab1:
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("OSINT Reconnaissance", "Live data")
        osint = result.get("osint_data") or {}
        shodan = osint.get("shodan") or {}
        vt = osint.get("virustotal") or {}
        whois = osint.get("whois") or {}

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="cx-data-title">Shodan Intelligence</div>', unsafe_allow_html=True)
            if shodan.get("error"):
                err = shodan["error"]
                if "403" in err or "Forbidden" in err or "upgrade" in err.lower():
                    st.markdown("""
<div class="cx-data-card" style="border-left:3px solid #ffb020;">
  <div style="color:#ffb020; font-weight:600; margin-bottom:0.3rem;">⚠ Shodan API plan limitation</div>
  <div class="cx-muted">Your Shodan free key doesn't cover IP host lookups.<br>
  The tool now auto-falls back to <b>Shodan InternetDB</b> (free, no key needed).<br>
  Add <code>SHODAN_API_KEY</code> with a paid plan for full data.</div>
</div>""", unsafe_allow_html=True)
                else:
                    st.error(f"Shodan: {err}")
            else:
                source = shodan.get("source", "")
                if source == "internetdb_free":
                    st.markdown('<div style="color:#64748b; font-size:0.72rem; margin-bottom:0.5rem;">SOURCE: SHODAN INTERNETDB (FREE)</div>', unsafe_allow_html=True)
                ports = shodan.get("open_ports", [])
                vulns = shodan.get("vulns", [])
                tags  = shodan.get("tags", [])
                cpes  = shodan.get("cpes", [])
                st.markdown(f"""
<div class="cx-data-card">
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
    <div><div class="cx-muted" style="font-size:0.7rem;">ORG</div><div style="color:#eef6ff;">{esc(shodan.get("org","N/A"))}</div></div>
    <div><div class="cx-muted" style="font-size:0.7rem;">COUNTRY</div><div style="color:#eef6ff;">{esc(shodan.get("country","N/A"))}</div></div>
  </div>
  <div style="margin-top:0.75rem;">
    <div class="cx-muted" style="font-size:0.7rem; margin-bottom:0.3rem;">OPEN PORTS ({len(ports)})</div>
    <div style="color:{'#ff4d6d' if len(ports)>5 else '#ffb020' if ports else '#21d19f'}; font-family:monospace; font-size:0.85rem;">
      {', '.join(str(p) for p in ports[:12]) or 'None detected'}
    </div>
  </div>
  {f'<div style="margin-top:0.5rem;"><div class="cx-muted" style="font-size:0.7rem;">VULNS</div><div style="color:#ff4d6d; font-family:monospace;">{", ".join(vulns[:5])}</div></div>' if vulns else ''}
  {f'<div style="margin-top:0.5rem;"><div class="cx-muted" style="font-size:0.7rem;">TAGS</div><div style="color:#ffb020;">{", ".join(tags)}</div></div>' if tags else ''}
  {f'<div style="margin-top:0.5rem;"><div class="cx-muted" style="font-size:0.7rem;">CPES</div><div class="cx-muted" style="font-size:0.78rem;">{" · ".join(cpes[:3])}</div></div>' if cpes else ''}
</div>""", unsafe_allow_html=True)

        with col2:
            st.markdown('<div class="cx-data-title">VirusTotal</div>', unsafe_allow_html=True)
            if vt.get("error"):
                st.error(f"VirusTotal: {vt['error']}")
            else:
                mal   = vt.get("malicious", 0)
                sus   = vt.get("suspicious", 0)
                harm  = vt.get("harmless", 0)
                rep   = vt.get("reputation", 0)
                vtags = vt.get("tags", [])
                rc = "#ff4d6d" if mal > 5 else "#ffb020" if mal > 0 else "#21d19f"
                st.markdown(f"""
<div class="cx-data-card">
  <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; text-align:center; margin-bottom:0.75rem;">
    <div style="background:#ff4d6d18; border-radius:8px; padding:0.5rem;">
      <div style="color:#ff4d6d; font-size:1.4rem; font-weight:800;">{mal}</div>
      <div class="cx-muted" style="font-size:0.65rem;">MALICIOUS</div>
    </div>
    <div style="background:#ffb02018; border-radius:8px; padding:0.5rem;">
      <div style="color:#ffb020; font-size:1.4rem; font-weight:800;">{sus}</div>
      <div class="cx-muted" style="font-size:0.65rem;">SUSPICIOUS</div>
    </div>
    <div style="background:#21d19f18; border-radius:8px; padding:0.5rem;">
      <div style="color:#21d19f; font-size:1.4rem; font-weight:800;">{harm}</div>
      <div class="cx-muted" style="font-size:0.65rem;">HARMLESS</div>
    </div>
  </div>
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <span class="cx-muted" style="font-size:0.75rem;">Reputation</span>
    <span style="color:{'#ff4d6d' if rep < 0 else '#21d19f'}; font-weight:700; font-family:monospace;">{rep}</span>
  </div>
  {f'<div style="margin-top:0.5rem;"><div class="cx-muted" style="font-size:0.7rem;">TAGS</div><div style="color:#ffb020; font-family:monospace; font-size:0.82rem;">{", ".join(vtags)}</div></div>' if vtags else ''}
</div>""", unsafe_allow_html=True)

        if whois and not whois.get("error"):
            st.markdown('<div class="cx-data-title" style="margin-top:1rem;">WHOIS / GeoIP</div>', unsafe_allow_html=True)
            cols = st.columns(4)
            fields = [("IP", "ip"), ("City", "city"), ("Country", "country"),
                      ("Org", "org"), ("ISP", "isp"), ("ASN", "asn"), ("TZ", "timezone")]
            for i, (label, key) in enumerate(fields):
                if whois.get(key):
                    with cols[i % 4]:
                        st.markdown(f'<div class="cx-data-card" style="text-align:center; padding:0.6rem;">'
                                    f'<div class="cx-muted" style="font-size:0.65rem;">{label}</div>'
                                    f'<div style="color:#eef6ff; font-weight:600; font-size:0.85rem;">{esc(str(whois[key]))}</div>'
                                    f'</div>', unsafe_allow_html=True)
        elif whois.get("error"):
            st.caption(f"WHOIS/GeoIP: {whois['error']}")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("Dark Web Exposure", "Monitored sources")
        exp_level = darkweb_data.get("exposure_level", "LOW")
        exp_score = darkweb_data.get("dark_web_exposure_score", 0)
        ransomware = darkweb_data.get("ransomware_leaks", {})
        threatfox  = darkweb_data.get("threatfox", {})
        urlhaus    = darkweb_data.get("urlhaus", {})

        render_metrics([
            ("Exposure Score",     f"{exp_score}/100", "Aggregate dark-web posture", numeric_color(exp_score)),
            ("Exposure Level",     exp_level,          "Classifier output",          risk_color(exp_level)),
            ("Ransomware Mentions", ransomware.get("matches_found", 0), "Ransomware.live", "#ff4d6d"),
            ("ThreatFox IOCs",     threatfox.get("matches_found", 0),  "abuse.ch",         "#ff4d6d"),
            ("URLhaus URLs",       urlhaus.get("malicious_urls", 0),   "abuse.ch",         "#ff4d6d"),
        ])

        # Ransomware.live
        st.markdown('<div class="cx-data-title" style="margin-top:1rem;">Ransomware.live</div>', unsafe_allow_html=True)
        r_note = ransomware.get("note", "")
        r_matches = ransomware.get("matches", [])
        if r_note:
            st.caption(f"ℹ {r_note}")
        if r_matches:
            for m in r_matches:
                st.markdown(f"""
<div class="cx-data-card" style="border-left:3px solid #ff4d6d; margin-bottom:0.5rem;">
  <div style="display:flex; justify-content:space-between; flex-wrap:wrap;">
    <b style="color:#eef6ff;">{esc(m.get('victim',''))}</b>
    <span class="cx-chip red">{esc(m.get('group',''))}</span>
  </div>
  <div class="cx-muted" style="font-size:0.78rem; margin-top:0.3rem;">
    {esc(m.get('date',''))} · {esc(m.get('country',''))} · {esc(m.get('website',''))}
  </div>
  {f'<div class="cx-muted" style="margin-top:0.3rem; font-size:0.8rem;">{esc(m.get("description",""))}</div>' if m.get('description') else ''}
</div>""", unsafe_allow_html=True)
        elif not r_note:
            st.success("✅ No ransomware victim records found")

        # ThreatFox IOCs
        st.markdown('<div class="cx-data-title" style="margin-top:1rem;">ThreatFox IOCs</div>', unsafe_allow_html=True)
        tf_note = threatfox.get("note", "")
        tf_iocs = threatfox.get("iocs", [])
        if tf_note:
            st.caption(f"ℹ {tf_note}")
        if tf_iocs:
            for ioc in tf_iocs:
                conf = ioc.get("confidence", 0)
                cc = "#ff4d6d" if conf >= 75 else "#ffb020" if conf >= 50 else "#64748b"
                st.markdown(f"""
<div class="cx-data-card" style="border-left:3px solid {cc}; margin-bottom:0.4rem;">
  <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.5rem;">
    <code style="color:#35e4ff;">{esc(str(ioc.get('ioc','')))}</code>
    <span style="color:{cc}; font-size:0.75rem; font-weight:700;">Confidence: {conf}%</span>
  </div>
  <div class="cx-muted" style="font-size:0.78rem;">
    {esc(ioc.get('ioc_type',''))} · {esc(ioc.get('threat_type',''))} · {esc(ioc.get('malware_printable') or ioc.get('malware',''))}
    · First: {esc(str(ioc.get('first_seen',''))[:10])}
  </div>
</div>""", unsafe_allow_html=True)
        elif not tf_note:
            st.success("✅ No ThreatFox IOC matches")

        # URLhaus
        st.markdown('<div class="cx-data-title" style="margin-top:1rem;">URLhaus</div>', unsafe_allow_html=True)
        uh_note = urlhaus.get("note", "")
        uh_urls = urlhaus.get("urls", [])
        if uh_note:
            st.caption(f"ℹ {uh_note}")
        if uh_urls:
            for u in uh_urls:
                st.markdown(f"""
<div class="cx-data-card" style="border-left:3px solid #ff4d6d; margin-bottom:0.4rem;">
  <div style="color:#ff4d6d; font-family:monospace; font-size:0.82rem; word-break:break-all;">{esc(u.get('url',''))}</div>
  <div class="cx-muted" style="font-size:0.78rem; margin-top:0.3rem;">
    Status: {esc(u.get('status',''))} · Threat: {esc(u.get('threat',''))} · Added: {esc(u.get('date_added',''))}
    {' · Tags: ' + ', '.join(u.get('tags',[])) if u.get('tags') else ''}
  </div>
</div>""", unsafe_allow_html=True)
        elif not uh_note:
            st.success("✅ No URLhaus malware URL matches")

        st.markdown("</div>", unsafe_allow_html=True)


    with tab3:
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("MITRE ATT&CK Mapping", "AI mapped")
        render_metrics(
            [
                ("Primary Tactic", mitre_data.get("primary_tactic", "N/A"), "Dominant tactic", "#48a7ff"),
                ("Attack Stage", mitre_data.get("attack_stage", "N/A"), "Likely lifecycle stage", "#35e4ff"),
                ("Risk Score", f"{mitre_data.get('risk_score', 0)}/100", "Technique-weighted risk", numeric_color(mitre_data.get("risk_score", 0))),
            ]
        )
        techniques = mitre_data.get("mapped_techniques", [])
        if techniques:
            st.dataframe(techniques, use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE techniques were mapped for this target.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("Threat Actor Profile", "AI generated")
        render_metrics(
            [
                ("Actor Type", profile.get("threat_actor_type", "N/A"), "Likely operator class", "#48a7ff"),
                ("Sophistication", profile.get("sophistication_level", "N/A"), "Capability estimate", "#35e4ff"),
                ("Motivation", profile.get("likely_motivation", "N/A"), "Intent hypothesis", "#21d19f"),
            ]
        )
        st.markdown(
            f"""
<div class="cx-data-card">
  <div class="cx-data-title">Analyst Summary</div>
  <div class="cx-muted" style="line-height:1.7;">{esc(profile.get("analyst_summary", "N/A"))}</div>
</div>
            """,
            unsafe_allow_html=True,
        )
        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="cx-data-title">Predicted Next Actions</div>', unsafe_allow_html=True)
            for action in profile.get("predicted_next_actions", []):
                st.markdown(f'<div class="cx-list-item">{esc(action)}</div>', unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="cx-data-title">Recommended Defenses</div>', unsafe_allow_html=True)
            for defense in profile.get("recommended_defenses", []):
                st.markdown(f'<div class="cx-list-item">{esc(defense)}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab5:
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("CTI Report", "PDF")
        report_path = result.get("report_path")
        if report_path and os.path.exists(report_path):
            st.success(f"Report generated: `{report_path}`")
            with open(report_path, "rb") as report_file:
                st.download_button(
                    "Download PDF Report",
                    data=report_file,
                    file_name=os.path.basename(report_path),
                    mime="application/pdf",
                    use_container_width=True,
                )
        else:
            st.warning("The report path was not returned or the file does not exist.")
        st.markdown("</div>", unsafe_allow_html=True)

def run_breach_pipeline(target: str) -> None:
    """Breach Radar — Domain Scan mode: URLScan + crt.sh + IntelX + DNS"""
    from tools.breach_tools import _normalize_domain
    target = _normalize_domain(target)  # normalize once upfront

    st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
    section_header("BREACH RADAR — Domain Scan", "Live scan")
    render_phase_grid(PHASES_BREACH, active_count=0)
    pb = st.progress(0)
    status = st.empty()
    st.markdown("</div>", unsafe_allow_html=True)

    def update(msg: str, pct: int):
        status.markdown(
            f'<div class="cx-chip"><span class="cx-dot"></span>{esc(msg)}</div>',
            unsafe_allow_html=True,
        )
        pb.progress(pct)

    try:
        result = {}
        api_errors = []  # collect non-fatal API errors to surface in UI

        update("Subdomain Recon: crt.sh certificate transparency logs...", 16)
        try:
            result["subdomains"] = crtsh_subdomains(target)
            err = result["subdomains"].get("error", "")
            if err:
                api_errors.append(("crt.sh", err))
        except Exception as e:
            result["subdomains"] = {"error": str(e), "total": 0, "sensitive": [], "normal": [], "certificate_records": 0}
            api_errors.append(("crt.sh", str(e)))

        update("Web Fingerprint: URLScan.io technology stack...", 32)
        try:
            result["urlscan"] = urlscan_domain(target)
            err = result["urlscan"].get("error", "")
            if err:
                api_errors.append(("URLScan", err))
        except Exception as e:
            result["urlscan"] = {"error": str(e), "scans_found": 0, "technologies": [], "recent_pages": [], "known_ips": []}
            api_errors.append(("URLScan", str(e)))

        update("Paste & Leak Sites: IntelX phonebook search...", 48)
        try:
            result["intelx"] = intelx_phonebook(target)
            err = result["intelx"].get("error", "")
            if err:
                if err == "no_key":
                    api_errors.append(("IntelX", "INTELX_API_KEY not set in .env"))
                else:
                    api_errors.append(("IntelX", err))
        except Exception as e:
            result["intelx"] = {"error": str(e), "email_count": 0, "emails_found": [], "related_urls": [], "related_domains": [], "total_selectors": 0}
            api_errors.append(("IntelX", str(e)))

        update("DNS Recon: record lookup and provider detection...", 64)
        try:
            result["dns"] = dns_recon(target)
            err = result["dns"].get("error", "")
            if err:
                api_errors.append(("DNS", err))
        except Exception as e:
            result["dns"] = {"error": str(e), "email_provider": "Unknown", "mx": [], "a": [], "txt": [], "resolved_ip": "N/A"}
            api_errors.append(("DNS", str(e)))

        update("Risk Scoring: digital exposure assessment...", 85)
        # Compute a simplified risk score for domain-only scan
        subs = result["subdomains"]
        intelx = result["intelx"]
        urlscan = result["urlscan"]

        score = 0
        factors = []

        sensitive_count = len(subs.get("sensitive", []))
        total_subs = subs.get("total", 0)
        if sensitive_count > 8:
            score += 30; factors.append(f"CRITICAL: {sensitive_count} sensitive subdomains exposed (admin/vpn/dev/api)")
        elif sensitive_count > 3:
            score += 20; factors.append(f"HIGH: {sensitive_count} sensitive subdomains exposed")
        elif sensitive_count > 0:
            score += 10; factors.append(f"{sensitive_count} potentially sensitive subdomains")
        if total_subs > 30:
            score += 10; factors.append(f"Large attack surface: {total_subs} total subdomains")

        intelx_emails = intelx.get("email_count", 0)
        if intelx_emails > 15:
            score += 30; factors.append(f"HIGH: {intelx_emails} employee emails indexed in paste/leak sites")
        elif intelx_emails > 5:
            score += 20; factors.append(f"MEDIUM: {intelx_emails} emails found in IntelX paste databases")
        elif intelx_emails > 0:
            score += 10; factors.append(f"{intelx_emails} email mentions in IntelX")

        scans = urlscan.get("scans_found", 0)
        techs = urlscan.get("technologies", [])
        if scans > 0 and techs:
            score += 15; factors.append(f"Tech stack fingerprinted via URLScan: {', '.join([t['name'] for t in techs[:3]])}")
        elif scans > 0:
            score += 5; factors.append(f"Web presence confirmed — {scans} URLScan records")

        score = min(score, 100)
        if score >= 60:
            level, summary = "CRITICAL", "Severe digital exposure. Large discoverable attack surface with significant email leak data."
        elif score >= 40:
            level, summary = "HIGH", "Significant exposure. Multiple sensitive subdomains and discoverable employee data."
        elif score >= 20:
            level, summary = "MEDIUM", "Moderate exposure. Some sensitive assets and email exposure require attention."
        else:
            level, summary = "LOW", "Limited publicly known exposure detected."

        result["risk"] = {"score": score, "level": level, "summary": summary, "factors": factors}
        # Empty leakcheck/hunter so render_breach_results won't crash on missing keys
        result["leakcheck"] = {"found": False, "total_exposed_accounts": 0, "unique_breaches": 0, "breach_sources": []}
        result["hunter"] = {"total_found": 0, "emails": []}
        result["api_errors"] = api_errors  # surface in UI

        pb.progress(100)
        update("Scan complete", 100)
        render_breach_results(result, target)  # target is already normalized

    except Exception as e:
        st.error(f"BREACH RADAR error: {e}")
        st.exception(e)



def render_breach_results(r: dict, domain: str) -> None:
    risk     = r.get("risk", {})
    leak     = r.get("leakcheck", {})
    hunter   = r.get("hunter", {})
    subs     = r.get("subdomains", {})
    urlscan  = r.get("urlscan", {})
    intelx   = r.get("intelx", {})
    dns      = r.get("dns", {})

    score = risk.get("score", 0)
    level = risk.get("level", "UNKNOWN")
    rc = {"CRITICAL":"#ff4d6d","HIGH":"#ff4d6d","MEDIUM":"#ffb020","LOW":"#21d19f"}.get(level,"#48a7ff")

    # Hero risk banner
    st.markdown(f"""
<div style="border:1px solid {rc}44; border-radius:16px; padding:1.5rem 2rem; margin:1rem 0;
     background:linear-gradient(135deg,{rc}12,rgba(7,13,28,0.9));
     box-shadow:0 0 40px {rc}18;">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
    <div>
      <div style="color:{rc}; font-size:0.7rem; font-family:'JetBrains Mono',monospace;
           letter-spacing:3px; text-transform:uppercase; margin-bottom:0.5rem;">
        BREACH RADAR — DIGITAL RISK ASSESSMENT
      </div>
      <div style="color:{rc}; font-size:1.8rem; font-weight:800;">{level} RISK — {esc(domain)}</div>
      <div style="color:#94a3b8; font-size:0.88rem; margin-top:0.4rem; max-width:580px;">
        {esc(risk.get("summary",""))}
      </div>
    </div>
    <div style="text-align:center; min-width:110px;">
      <div style="font-size:4.5rem; font-weight:800; color:{rc};
           font-family:'JetBrains Mono',monospace;
           text-shadow:0 0 40px {rc};">{score}</div>
      <div style="color:#64748b; font-size:0.68rem; letter-spacing:2px;">RISK SCORE / 100</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    # API errors — smart actionable messages per source
    api_errors = r.get("api_errors", [])
    if api_errors:
        # Map error codes to user-friendly fix instructions
        FIX_GUIDE = {
            "crt.sh": {
                "icon": "🔍",
                "what": "Subdomain enumeration via certificate transparency",
                "fix": "crt.sh is a free public API — if it returned 404, it may be temporarily down. "
                       "Add **OTX_API_KEY** or **VIRUSTOTAL_API_KEY** to `.env` as fallback sources.",
                "env_key": None,
            },
            "IntelX": {
                "icon": "📋",
                "what": "Email/paste/leak database phonebook",
                "fix": "IntelX free unauthenticated API is **dead**. Requires a paid key.",
                "env_key": "INTELX_API_KEY",
                "link": "https://intelx.io/signup",
            },
            "URLScan": {
                "icon": "🌐",
                "what": "Web footprint and technology stack",
                "fix": "URLScan works without a key but rate-limits heavily. Add a free key for 1000 req/day.",
                "env_key": "URLSCAN_API_KEY",
                "link": "https://urlscan.io/user/signup",
            },
        }

        st.markdown("""
<div style="border:1px solid #1e3a5f; border-radius:12px; overflow:hidden; margin:1rem 0;">
  <div style="background:#0d1f38; padding:0.75rem 1.25rem; display:flex;
       justify-content:space-between; align-items:center; cursor:pointer;">
    <div style="color:#ffb020; font-weight:600; font-size:0.85rem;">
      ⚙ API SETUP REQUIRED — some sources need keys to return data
    </div>
  </div>""", unsafe_allow_html=True)

        with st.expander(f"Click to see setup instructions for {len(api_errors)} source(s)", expanded=False):
            for source, err in api_errors:
                guide = FIX_GUIDE.get(source, {})
                env_key = guide.get("env_key")
                link = guide.get("link", "")
                fix_text = guide.get("fix", err)
                icon = guide.get("icon", "⚠")

                key_line = f'<code style="color:#35e4ff; background:#0a1628; padding:0.15rem 0.4rem; border-radius:4px;">{env_key}=your_key_here</code>' if env_key else ""
                link_line = f'<a href="{link}" target="_blank" style="color:#48a7ff; font-size:0.8rem;">Get key → {link}</a>' if link else ""

                st.markdown(f"""
<div style="padding:1rem 0; border-bottom:1px solid #1a2d45;">
  <div style="display:flex; gap:0.75rem; align-items:flex-start;">
    <div style="font-size:1.3rem;">{icon}</div>
    <div style="flex:1;">
      <div style="color:#eef6ff; font-weight:700; margin-bottom:0.3rem;">{source}</div>
      <div style="color:#64748b; font-size:0.78rem; margin-bottom:0.5rem;">{guide.get('what', '')}</div>
      <div style="color:#94a3b8; font-size:0.82rem; line-height:1.5; margin-bottom:0.4rem;">{fix_text}</div>
      {f'<div style="margin:0.4rem 0;">Add to <code style="color:#48a7ff;">.env</code>: {key_line}</div>' if env_key else ""}
      {f'<div style="margin-top:0.3rem;">{link_line}</div>' if link_line else ""}
    </div>
  </div>
</div>""", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # Top metrics
    render_metrics([
        ("Breached Accounts", leak.get("total_exposed_accounts", 0),
         "LeakCheck database", numeric_color(leak.get("total_exposed_accounts",0), 5, 25)),
        ("Breach Sources", leak.get("unique_breaches", 0),
         "Distinct breach events", numeric_color(leak.get("unique_breaches",0), 2, 6)),
        ("IntelX Emails", intelx.get("email_count", 0),
         "Emails in paste/leak sites", numeric_color(intelx.get("email_count",0), 3, 10)),
        ("Subdomains", subs.get("total", 0),
         f"{len(subs.get('sensitive',[]))} sensitive", numeric_color(subs.get("total",0), 10, 30)),
        ("Email Provider", dns.get("email_provider","Unknown"),
         dns.get("resolved_ip",""), "#48a7ff"),
    ])

    # Detailed tabs
    t1, t2, t3, t4, t5 = st.tabs([
        "📧 IntelX Emails", "🌐 Subdomains",
        "🔍 Web Footprint", "📡 DNS & Raw", "💡 Risk Factors"
    ])

    with t1:
        # TAB 1 — IntelX Emails
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("IntelX Email Exposure", "Paste & leak site indexing")
        ix_emails = intelx.get("emails_found", [])
        ix_urls = intelx.get("related_urls", [])
        ix_domains = intelx.get("related_domains", [])
        if ix_emails:
            st.markdown(
                f'<div class="cx-data-card" style="margin-bottom:1rem; border-left:3px solid #ffb020;">'
                f'<div class="cx-data-title" style="color:#ffb020;">⚠ {len(ix_emails)} emails indexed in paste/leak databases</div>'
                f'<div class="cx-muted">These addresses were found in IntelX phonebook — likely exposed in data dumps or paste sites.</div>'
                f'</div>',
                unsafe_allow_html=True)
            for email in ix_emails[:20]:
                st.markdown(
                    f'<div class="cx-list-item" style="border-left:3px solid #ffb020; font-family:monospace;">{esc(email)}</div>',
                    unsafe_allow_html=True)
        else:
            st.success("✅ No emails found in IntelX paste/leak databases for this domain.")
        if ix_urls:
            with st.expander(f"Related URLs ({len(ix_urls)})"):
                for u in ix_urls:
                    st.markdown(f'<div style="color:#64748b; font-family:monospace; font-size:0.8rem; padding:0.2rem 0;">{esc(u)}</div>', unsafe_allow_html=True)
        if ix_domains:
            with st.expander(f"Related Domains ({len(ix_domains)})"):
                for d in ix_domains:
                    st.markdown(f'<div style="color:#64748b; font-family:monospace; font-size:0.8rem; padding:0.2rem 0;">{esc(d)}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with t2:
        # TAB 2 — Subdomains
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("Subdomain Enumeration", "Certificate transparency — crt.sh")

        total = subs.get("total", 0)
        sensitive = subs.get("sensitive", [])
        normal = subs.get("normal", [])

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Subdomains", total)
        with col2:
            st.metric("Sensitive", len(sensitive), delta="⚠ High risk" if sensitive else None)
        with col3:
            st.metric("Cert Records", subs.get("certificate_records", 0))

        if sensitive:
            st.markdown(
                '<div class="cx-data-title" style="color:#ff4d6d; margin-top:1rem;">'
                '⚠ Sensitive Subdomains — admin/dev/api/vpn/mail</div>',
                unsafe_allow_html=True)
            for sub in sensitive:
                st.markdown(
                    f'<div class="cx-list-item" style="border-left:3px solid #ff4d6d; '
                    f'font-family:monospace; font-size:0.85rem;">{esc(sub)}</div>',
                    unsafe_allow_html=True)

        if normal:
            with st.expander(f"Other subdomains ({len(normal)})"):
                for sub in normal:
                    st.markdown(
                        f'<div style="color:#64748b; font-family:monospace; '
                        f'font-size:0.8rem; padding:0.2rem 0;">{esc(sub)}</div>',
                        unsafe_allow_html=True)
        if not total:
            st.info("No subdomains found via crt.sh for this domain.")
        st.markdown("</div>", unsafe_allow_html=True)

    with t3:
        # TAB 3 — Web Footprint
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("Web Footprint", "URLScan.io")

        scans = urlscan.get("scans_found", 0)
        techs = urlscan.get("technologies", [])

        if scans > 0:
            st.markdown(
                f'<div class="cx-data-card" style="margin-bottom:1rem;">'
                f'<div class="cx-data-title">{scans} URLScan records found</div>'
                f'<div class="cx-muted">Known IPs: {", ".join(urlscan.get("known_ips",[])[:5]) or "N/A"}</div>'
                f'</div>',
                unsafe_allow_html=True)

            if techs:
                st.markdown('<div class="cx-data-title">Detected Technology Stack</div>', unsafe_allow_html=True)
                for tech in techs:
                    cats = ", ".join(tech.get("categories", []))
                    st.markdown(
                        f'<div class="cx-list-item">'
                        f'<b>{esc(tech.get("name",""))}</b>'
                        f'{" · " + esc(cats) if cats else ""}'
                        f'</div>',
                        unsafe_allow_html=True)

            pages = urlscan.get("recent_pages", [])
            if pages:
                st.markdown('<div class="cx-data-title" style="margin-top:1rem;">Recent Scans</div>', unsafe_allow_html=True)
                import pandas as pd
                df_pages = pd.DataFrame(pages)
                cols_present = [c for c in ["url","ip","server","status","country","scan_date"] if c in df_pages.columns]
                st.dataframe(df_pages[cols_present], use_container_width=True, hide_index=True)
        else:
            st.info("No URLScan records found for this domain.")
        st.markdown("</div>", unsafe_allow_html=True)

    with t4:
        # TAB 4 — DNS & Raw
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("DNS Intelligence", "HackerTarget")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="cx-data-title">DNS Records</div>', unsafe_allow_html=True)
            st.json({k: v for k, v in dns.items() if k != "error"})
        with col2:
            st.markdown('<div class="cx-data-title">IntelX Summary</div>', unsafe_allow_html=True)
            st.json({
                "email_count": intelx.get("email_count", 0),
                "total_selectors": intelx.get("total_selectors", 0),
                "related_urls_count": len(intelx.get("related_urls", [])),
                "related_domains_count": len(intelx.get("related_domains", [])),
            })
        st.markdown("</div>", unsafe_allow_html=True)

    with t5:
        # TAB 5 — Risk Factors
        st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
        section_header("Risk Factor Breakdown", "Scoring details")
        factors = risk.get("factors", [])
        if factors:
            for f in factors:
                c = "#ff4d6d" if "CRITICAL" in f else "#ffb020" if "HIGH" in f else "#21d19f"
                st.markdown(
                    f'<div class="cx-list-item" style="border-left:3px solid {c};">{esc(f)}</div>',
                    unsafe_allow_html=True)
        else:
            st.info("No significant risk factors detected.")
        st.markdown("</div>", unsafe_allow_html=True)


def run_email_lookup_pipeline(email: str) -> None:
    """Breach Radar — Email Lookup: LeakCheck if key set, Hunter.io as fallback"""
    import os
    has_leakcheck = bool(os.getenv("LEAKCHECK_API_KEY", ""))
    has_hunter    = bool(os.getenv("HUNTER_API_KEY", ""))

    st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
    section_header("BREACH RADAR — Email Lookup",
                   "LeakCheck.io" if has_leakcheck else "Hunter.io" if has_hunter else "Setup required")
    render_phase_grid(PHASES_BREACH_EMAIL, active_count=0)
    pb = st.progress(0)
    status = st.empty()
    st.markdown("</div>", unsafe_allow_html=True)

    # No keys at all — show combined setup card
    if not has_leakcheck and not has_hunter:
        pb.progress(100)
        status.markdown('<div class="cx-chip"><span class="cx-dot"></span>No API key configured</div>',
                        unsafe_allow_html=True)
        st.markdown("""
<div style="border:1px solid #ffb020; border-radius:12px; padding:1.75rem 2rem; background:#ffb02010; margin:1rem 0;">
  <div style="color:#ffb020; font-weight:800; font-size:1.1rem; margin-bottom:1rem;">
    ⚙ Email Lookup needs an API key — pick one:
  </div>
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem;">
    <div style="background:#0a1628; border-radius:10px; padding:1.25rem; border:1px solid #1e3a5f;">
      <div style="color:#eef6ff; font-weight:700; margin-bottom:0.4rem;">Hunter.io <span style="color:#21d19f; font-size:0.75rem;">FREE TIER</span></div>
      <div style="color:#64748b; font-size:0.8rem; margin-bottom:0.75rem;">25 verifications/month free. Validates email existence + SMTP.</div>
      <code style="color:#35e4ff; font-size:0.8rem;">HUNTER_API_KEY=your_key</code><br>
      <a href="https://hunter.io/api-keys" target="_blank" style="color:#48a7ff; font-size:0.78rem;">Get free key → hunter.io</a>
    </div>
    <div style="background:#0a1628; border-radius:10px; padding:1.25rem; border:1px solid #1e3a5f;">
      <div style="color:#eef6ff; font-weight:700; margin-bottom:0.4rem;">LeakCheck.io <span style="color:#ffb020; font-size:0.75rem;">PAID ~$4/mo</span></div>
      <div style="color:#64748b; font-size:0.8rem; margin-bottom:0.75rem;">Shows actual breach databases the email appears in.</div>
      <code style="color:#35e4ff; font-size:0.8rem;">LEAKCHECK_API_KEY=your_key</code><br>
      <a href="https://leakcheck.io/pricing" target="_blank" style="color:#48a7ff; font-size:0.78rem;">Get key → leakcheck.io</a>
    </div>
  </div>
</div>""", unsafe_allow_html=True)
        return

    # LeakCheck preferred (has breach database data)
    if has_leakcheck:
        status.markdown('<div class="cx-chip"><span class="cx-dot"></span>Scanning LeakCheck breach databases...</div>',
                        unsafe_allow_html=True)
        pb.progress(50)
        result = leakcheck_email(email)
        pb.progress(100)
        if result.get("error") and result["error"] != "no_key":
            err = result["error"]
            if "403" in err or "status_403" in err:
                st.error("LeakCheck 403 — API key invalid or plan expired. Check leakcheck.io/pricing")
            else:
                st.error(f"LeakCheck error: {err}")
            return
        status.markdown('<div class="cx-chip"><span class="cx-dot"></span>Scan complete</div>',
                        unsafe_allow_html=True)
        render_email_lookup_results(result, email)
        return

    # Hunter fallback — email verification (not breach lookup, but useful)
    status.markdown('<div class="cx-chip"><span class="cx-dot"></span>Verifying email via Hunter.io...</div>',
                    unsafe_allow_html=True)
    pb.progress(50)
    result = hunter_email_lookup(email)
    pb.progress(100)
    if result.get("error") and result["error"] != "no_key":
        st.error(f"Hunter error: {result['error']}")
        return
    status.markdown('<div class="cx-chip"><span class="cx-dot"></span>Verification complete</div>',
                    unsafe_allow_html=True)
    render_hunter_email_results(result, email)


def render_hunter_email_results(r: dict, email: str) -> None:
    """Render Hunter.io email verification result"""
    status = r.get("status", "unknown")
    score = r.get("score", 0)
    found = r.get("found", False)

    color = "#21d19f" if found else "#ff4d6d"
    label = "VALID EMAIL" if status == "valid" else "ACCEPT ALL" if status == "accept_all" else \
            "RISKY" if status == "risky" else "INVALID" if status == "invalid" else "UNKNOWN"

    st.markdown(f"""
<div style="border:1px solid {color}44; border-radius:16px; padding:1.5rem 2rem; margin:1rem 0;
     background:linear-gradient(135deg,{color}12,rgba(7,13,28,0.9));
     box-shadow:0 0 40px {color}18;">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
    <div>
      <div style="color:{color}; font-size:0.7rem; font-family:'JetBrains Mono',monospace;
           letter-spacing:3px; text-transform:uppercase; margin-bottom:0.5rem;">
        BREACH RADAR — EMAIL VERIFICATION (HUNTER.IO)
      </div>
      <div style="color:{color}; font-size:1.8rem; font-weight:800;">{label} — {esc(email)}</div>
      <div style="color:#94a3b8; font-size:0.88rem; margin-top:0.5rem;">
        {'Email address exists and accepts mail' if found else 'Email address could not be verified'}
      </div>
    </div>
    <div style="text-align:center; min-width:110px;">
      <div style="font-size:4.5rem; font-weight:800; color:{color};
           font-family:'JetBrains Mono',monospace; text-shadow:0 0 40px {color};">{score}</div>
      <div style="color:#64748b; font-size:0.68rem; letter-spacing:2px;">DELIVERABILITY SCORE</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("MX Records", "✓" if r.get("mx_records") else "✗")
    with col2:
        st.metric("SMTP Check", "✓" if r.get("smtp_check") else "✗")
    with col3:
        st.metric("Disposable", "Yes ⚠" if r.get("disposable") else "No ✓")

    st.info("💡 Hunter.io verifies email existence but doesn't check breach databases. "
            "Add **LEAKCHECK_API_KEY** to `.env` for actual breach data.")




def render_email_lookup_results(r: dict, email: str) -> None:
    if r.get("error"):
        err = r["error"]
        if "403" in err or "invalid" in err.lower() or "plan" in err.lower() or "key" in err.lower():
            return  # already handled in pipeline with nice UI
        st.error(f"LeakCheck error: {err}")
        return

    found = r.get("found", False)
    breach_count = r.get("breach_count", 0)
    breaches = r.get("breaches", [])

    rc = "#ff4d6d" if breach_count > 5 else "#ffb020" if breach_count > 0 else "#21d19f"
    level = "HIGH RISK" if breach_count > 5 else "MEDIUM RISK" if breach_count > 0 else "CLEAN"

    st.markdown(f"""
<div style="border:1px solid {rc}44; border-radius:16px; padding:1.5rem 2rem; margin:1rem 0;
     background:linear-gradient(135deg,{rc}12,rgba(7,13,28,0.9));
     box-shadow:0 0 40px {rc}18;">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
    <div>
      <div style="color:{rc}; font-size:0.7rem; font-family:'JetBrains Mono',monospace;
           letter-spacing:3px; text-transform:uppercase; margin-bottom:0.5rem;">
        BREACH RADAR — EMAIL LOOKUP
      </div>
      <div style="color:{rc}; font-size:1.8rem; font-weight:800;">{level} — {esc(email)}</div>
      <div style="color:#94a3b8; font-size:0.88rem; margin-top:0.4rem;">
        {f"{breach_count} breach databases contain this email address" if found else "No breach records found for this email address."}
      </div>
    </div>
    <div style="text-align:center; min-width:110px;">
      <div style="font-size:4.5rem; font-weight:800; color:{rc};
           font-family:'JetBrains Mono',monospace;
           text-shadow:0 0 40px {rc};">{breach_count}</div>
      <div style="color:#64748b; font-size:0.68rem; letter-spacing:2px;">BREACHES FOUND</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    if not found or not breaches:
        st.success(f"✅ {esc(email)} was not found in any known breach database.")
        return

    st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
    section_header("Breach Records", f"{breach_count} sources")
    for b in breaches:
        fields_html = "".join(
            f'<span class="cx-pill">{esc(f)}</span>'
            for f in b.get("fields", [])[:6]
        )
        st.markdown(f"""
<div class="cx-data-card" style="margin-bottom:0.6rem; border-left:3px solid #ff4d6d;">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
    <div class="cx-data-title">{esc(b.get('name', 'Unknown'))}</div>
    <div class="cx-chip red">{esc(b.get('date', 'N/A'))}</div>
  </div>
  <div class="cx-pill-row">{fields_html if fields_html else '<span class="cx-muted">No field data</span>'}</div>
</div>""", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


def render_standby(mode: str, target: str) -> None:
    st.markdown('<div class="cx-panel cx-section">', unsafe_allow_html=True)
    section_header("Mission Control", "Pipeline ready")
    render_phase_grid(PHASES_INTEL, active_count=0)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            '<div class="cx-data-card"><div class="cx-data-title">Input</div><div class="cx-muted">Enter a target in the center mission console to arm the workflow.</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            '<div class="cx-data-card"><div class="cx-data-title">Demo Targets</div><div class="cx-muted mono">8.8.8.8<br>1.1.1.1<br>testphp.vulnweb.com</div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            '<div class="cx-data-card"><div class="cx-data-title">Output</div><div class="cx-muted">Interactive intelligence panels and downloadable PDF report.</div></div>',
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    inject_global_css()
    mode_seed = st.session_state.get("mode_selector", "Intelligence Mode")
    render_top_bar(mode_seed)
    mode, is_breach = render_mode_selector(mode_seed)
    render_hero(mode)
    target, target_type, breach_sub_mode, run_btn = render_mission_console(mode, is_breach)

    if run_btn and not target:
        st.warning("Enter a target first.")
        render_standby(mode, target)
    elif run_btn and target:
        if is_breach:
            if breach_sub_mode == "Email Lookup":
                run_email_lookup_pipeline(target)
            else:
                run_breach_pipeline(target)
        else:
            run_intel_pipeline(target, target_type)
    else:
        render_standby(mode, target)
