import streamlit as st
import json
import os
from core.cortex_graph import build_cortex_graph

st.set_page_config(
    page_title="CorteX AI",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap');

    /* Base Theme */
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif !important;
    }

    /* Background gradient */
    .stApp {
        background: radial-gradient(circle at top right, #0d1326, #050811);
        color: #e2e8f0;
    }

    /* Hide Streamlit Header */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: rgba(10, 15, 30, 0.6) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }

    /* Premium Headers */
    h1, h2, h3, h4 {
        background: -webkit-linear-gradient(45deg, #4ade80, #3b82f6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800 !important;
        animation: fadeInDown 0.8s ease-out;
    }
    h3 {
        background: -webkit-linear-gradient(45deg, #a855f7, #3b82f6);
        -webkit-background-clip: text;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(90deg, #3b82f6, #8b5cf6) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.2rem !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(139, 92, 246, 0.6) !important;
        background: linear-gradient(90deg, #60a5fa, #a855f7) !important;
    }

    /* Custom Metric Cards */
    .premium-card {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        transition: all 0.4s ease;
        animation: fadeInUp 0.6s ease-out both;
    }
    .premium-card:hover {
        transform: translateY(-5px);
        border-color: rgba(59, 130, 246, 0.5);
        box-shadow: 0 10px 30px rgba(59, 130, 246, 0.2);
    }

    .premium-card-title {
        font-size: 0.9rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
    }

    .premium-card-value {
        font-size: 2.2rem;
        font-weight: 800;
        color: #f8fafc;
        text-shadow: 0 0 10px rgba(255,255,255,0.2);
    }

    .glow-red { text-shadow: 0 0 15px rgba(239, 68, 68, 0.8) !important; color: #ef4444 !important; -webkit-text-fill-color: #ef4444 !important; }
    .glow-orange { text-shadow: 0 0 15px rgba(249, 115, 22, 0.8) !important; color: #f97316 !important; -webkit-text-fill-color: #f97316 !important; }
    .glow-yellow { text-shadow: 0 0 15px rgba(234, 179, 8, 0.8) !important; color: #eab308 !important; -webkit-text-fill-color: #eab308 !important; }
    .glow-green { text-shadow: 0 0 15px rgba(34, 197, 94, 0.8) !important; color: #22c55e !important; -webkit-text-fill-color: #22c55e !important; }
    .glow-blue { text-shadow: 0 0 15px rgba(59, 130, 246, 0.8) !important; color: #3b82f6 !important; -webkit-text-fill-color: #3b82f6 !important; }

    /* Pulse Animation */
    @keyframes pulseGlow {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
        70% { box-shadow: 0 0 0 15px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    @keyframes pulseGlowBlue {
        0% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); }
        70% { box-shadow: 0 0 0 15px rgba(59, 130, 246, 0); }
        100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); }
    }

    .critical-alert {
        border-left: 4px solid #ef4444;
        animation: pulseGlow 2s infinite;
    }

    /* Animations */
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeInDown {
        from { opacity: 0; transform: translateY(-20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Tabs Styling */
    [data-testid="stTabs"] button {
        font-size: 1.1rem !important;
        font-weight: 600 !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #3b82f6 !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"]::after {
        background-color: #a855f7 !important;
        height: 3px !important;
    }

    /* Divider */
    hr {
        border-color: rgba(255,255,255,0.1) !important;
    }

    /* Text Input */
    .stTextInput input, .stSelectbox div[data-baseweb="select"] {
        background-color: rgba(15, 23, 42, 0.5) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        color: white !important;
        border-radius: 8px !important;
    }
    .stTextInput input:focus, .stSelectbox div[data-baseweb="select"]:focus-within {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 10px rgba(59, 130, 246, 0.3) !important;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## 🧠 CorteX AI")
    st.markdown("*Autonomous Cyber Threat Intelligence*")
    st.divider()
    target = st.text_input("🎯 Target IP / Domain", placeholder="e.g. 8.8.8.8 or evil.ru")
    target_type = st.selectbox("Target Type", ["ip", "domain"])
    st.divider()
    run_btn = st.button("⚡ Run Intelligence Pipeline", use_container_width=True, type="primary")
    st.divider()
    st.markdown("**Pipeline Phases:**")
    phases = ["🔍 OSINT Recon", "📡 Threat Feeds", "🌑 Dark Web", "🔎 IOC Extraction", "🗺️ MITRE ATT&CK", "👤 Actor Profiling", "📄 CTI Report"]
    for p in phases:
        st.markdown(f"- {p}")

# Header
st.markdown("""
<div style="text-align: center; padding: 2rem 0; animation: fadeInDown 0.8s ease-out;">
    <h1 style="font-size: 3.5rem; margin-bottom: 0;">🧠 CorteX <span style="color: #f8fafc; -webkit-text-fill-color: #f8fafc;">AI</span></h1>
    <p style="font-size: 1.2rem; color: #94a3b8; font-weight: 300; letter-spacing: 2px;">AUTONOMOUS CYBER THREAT INTELLIGENCE</p>
</div>
""", unsafe_allow_html=True)
st.divider()

if run_btn and target:
    st.markdown(f"""
    <div class="premium-card" style="margin-bottom: 20px;">
        <h3 style="margin-top:0; margin-bottom:0;">🎯 Analyzing Target: <span class="glow-blue">{target}</span></h3>
    </div>
    """, unsafe_allow_html=True)

    progress_bar = st.progress(0)
    status = st.empty()

    phases_list = [
        ("🔍 Running OSINT Reconnaissance...", 14),
        ("📡 Querying Threat Feeds...", 28),
        ("🌑 Scanning Dark Web Sources...", 42),
        ("🔎 Extracting IOCs with AI...", 57),
        ("🗺️ Mapping MITRE ATT&CK...", 71),
        ("👤 Building Threat Actor Profile...", 85),
        ("📄 Generating CTI Report...", 100),
    ]

    def update_progress(step):
        msg, pct = phases_list[step]
        status.markdown(f"""
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); padding: 12px 20px; border-radius: 8px; color: #60a5fa; font-weight: 600; display: inline-block; animation: pulseGlowBlue 2s infinite;">
            <span style="margin-right: 10px;">⚡</span> {msg}
        </div>
        """, unsafe_allow_html=True)
        progress_bar.progress(pct)

    try:
        graph = build_cortex_graph()
        initial_state = {
            "target": target,
            "target_type": target_type,
            "osint_data": None,
            "threat_data": None,
            "darkweb_data": None,
            "ioc_data": None,
            "mitre_data": None,
            "profile_data": None,
            "report_path": None
        }

        # Run with progress updates
        for i, (node, result) in enumerate([]):
            update_progress(i)

        update_progress(0)
        result = graph.invoke(initial_state)
        progress_bar.progress(100)
        status.markdown("""
        <div style="background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); padding: 12px 20px; border-radius: 8px; color: #4ade80; font-weight: 600; display: inline-block; animation: fadeInUp 0.5s ease-out;">
            ✅ Intelligence Pipeline Complete!
        </div>
        """, unsafe_allow_html=True)

        # ─── METRICS ROW ───
        st.divider()
        col1, col2, col3, col4 = st.columns(4)

        rating = result["profile_data"].get("overall_threat_rating", "UNKNOWN")
        threat_level = result["threat_data"].get("threat_level", "LOW")
        pulse_count = result["threat_data"].get("otx_alienvault", {}).get("pulse_count", 0)
        risk_score = result["mitre_data"].get("risk_score", 0)

        def get_glow_class(val, is_risk=False):
            if isinstance(val, str):
                v = val.upper()
                if v in ["CRITICAL", "HIGH"]: return "glow-red"
                if v == "MEDIUM": return "glow-orange"
                if v == "LOW": return "glow-green"
                return "glow-blue"
            elif is_risk:
                try:
                    v = float(val)
                    if v > 75: return "glow-red"
                    if v > 50: return "glow-orange"
                    if v > 25: return "glow-yellow"
                    return "glow-green"
                except: return "glow-blue"
            return "glow-blue"

        with col1:
            glow = get_glow_class(rating)
            alert_class = "critical-alert" if rating in ["CRITICAL", "HIGH"] else ""
            st.markdown(f"""
            <div class="premium-card {alert_class}" style="animation-delay: 0.1s;">
                <div class="premium-card-title">Overall Threat Rating</div>
                <div class="premium-card-value {glow}">{rating}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            glow = get_glow_class(threat_level)
            st.markdown(f"""
            <div class="premium-card" style="animation-delay: 0.2s;">
                <div class="premium-card-title">Threat Level</div>
                <div class="premium-card-value {glow}">{threat_level}</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            try:
                pc = int(pulse_count)
                glow = "glow-blue" if pc == 0 else "glow-yellow" if pc < 10 else "glow-red"
            except:
                glow = "glow-blue"
            st.markdown(f"""
            <div class="premium-card" style="animation-delay: 0.3s;">
                <div class="premium-card-title">OTX Pulses</div>
                <div class="premium-card-value {glow}">{pulse_count}</div>
            </div>
            """, unsafe_allow_html=True)
        with col4:
            glow = get_glow_class(risk_score, is_risk=True)
            st.markdown(f"""
            <div class="premium-card" style="animation-delay: 0.4s;">
                <div class="premium-card-title">Risk Score</div>
                <div class="premium-card-value {glow}">{risk_score}/100</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ─── TABS ───
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 OSINT", "🌑 Dark Web", "🗺️ MITRE ATT&CK", "👤 Threat Profile", "📄 Report"])

        with tab1:
            st.markdown("### OSINT Reconnaissance Results")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Shodan Intelligence**")
                st.json(result["osint_data"]["shodan"])
            with col2:
                st.markdown("**VirusTotal**")
                st.json(result["osint_data"]["virustotal"])
            st.markdown("**WHOIS / GeoIP**")
            st.json(result["osint_data"]["whois"])

        with tab2:
            st.markdown("### Dark Web Exposure Analysis")
            exp_level = result["darkweb_data"].get("exposure_level", "LOW")
            exp_score = result["darkweb_data"].get("dark_web_exposure_score", 0)
            
            glow_class = "glow-red" if exp_level in ["HIGH", "CRITICAL"] else "glow-orange" if exp_level == "MEDIUM" else "glow-green"
            st.markdown(f"""
            <div class="premium-card" style="margin-bottom: 20px;">
                <div class="premium-card-title">Dark Web Exposure</div>
                <div class="premium-card-value {glow_class}">{exp_score}/100 <span style="font-size: 1rem; color: #94a3b8; text-shadow: none;">(Level: {exp_level})</span></div>
            </div>
            """, unsafe_allow_html=True)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown("**Ransomware.live**")
                st.json(result["darkweb_data"]["ransomware_leaks"])
            with col2:
                st.markdown("**ThreatFox**")
                st.json(result["darkweb_data"]["threatfox"])
            with col3:
                st.markdown("**URLhaus**")
                st.json(result["darkweb_data"]["urlhaus"])

        with tab3:
            st.markdown("### MITRE ATT&CK Mapping")
            col1, col2 = st.columns(2)
            with col1:
                tactic = result["mitre_data"].get("primary_tactic", "N/A")
                stage = result["mitre_data"].get("attack_stage", "N/A")
                st.markdown(f"""
                <div class="premium-card" style="margin-bottom: 15px;">
                    <div class="premium-card-title">Primary Tactic</div>
                    <div class="premium-card-value glow-orange" style="font-size: 1.5rem;">{tactic}</div>
                </div>
                <div class="premium-card">
                    <div class="premium-card-title">Attack Stage</div>
                    <div class="premium-card-value glow-orange" style="font-size: 1.5rem;">{stage}</div>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                r_score = result["mitre_data"].get("risk_score", 0)
                st.markdown(f"""
                <div class="premium-card" style="height: 100%; display: flex; flex-direction: column; justify-content: center;">
                    <div class="premium-card-title">MITRE Risk Score</div>
                    <div class="premium-card-value glow-red">{r_score}/100</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("**Mapped Techniques:**")
            techniques = result["mitre_data"].get("mapped_techniques", [])
            if techniques:
                import pandas as pd
                df = pd.DataFrame(techniques)
                st.dataframe(df, use_container_width=True)

        with tab4:
            st.markdown("### Threat Actor Profile")
            profile = result["profile_data"]
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"""
                <div class="premium-card">
                    <div class="premium-card-title">Actor Type</div>
                    <div class="premium-card-value glow-blue" style="font-size: 1.5rem;">{profile.get("threat_actor_type", "N/A")}</div>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.markdown(f"""
                <div class="premium-card">
                    <div class="premium-card-title">Sophistication</div>
                    <div class="premium-card-value glow-blue" style="font-size: 1.5rem;">{profile.get("sophistication_level", "N/A")}</div>
                </div>
                """, unsafe_allow_html=True)
            with col3:
                st.markdown(f"""
                <div class="premium-card">
                    <div class="premium-card-title">Motivation</div>
                    <div class="premium-card-value glow-blue" style="font-size: 1.5rem;">{profile.get("likely_motivation", "N/A")}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("**Analyst Summary:**")
            st.info(profile.get("analyst_summary", "N/A"))
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Predicted Next Actions:**")
                for action in profile.get("predicted_next_actions", []):
                    st.markdown(f"- {action}")
            with col2:
                st.markdown("**Recommended Defenses:**")
                for defense in profile.get("recommended_defenses", []):
                    st.markdown(f"- ✅ {defense}")

        with tab5:
            st.markdown("### CTI Report")
            report_path = result.get("report_path")
            if report_path and os.path.exists(report_path):
                st.success(f"✅ Report generated: `{report_path}`")
                with open(report_path, "rb") as f:
                    st.download_button(
                        label="📥 Download PDF Report",
                        data=f,
                        file_name=os.path.basename(report_path),
                        mime="application/pdf",
                        use_container_width=True
                    )

    except Exception as e:
        st.error(f"Pipeline error: {str(e)}")
        st.exception(e)

elif not target and run_btn:
    st.warning("Please enter a target IP or domain first!")
else:
    # Landing state
    st.markdown("""
    <div style="animation: fadeInUp 0.8s ease-out; padding: 20px;">
        <div class="premium-card" style="background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(59, 130, 246, 0.2);">
            <h2 style="margin-top: 0;">👋 Welcome to <span class="glow-blue">CorteX AI</span></h2>
            <p style="font-size: 1.1rem; color: #94a3b8;">Enter a target IP address or domain in the sidebar and click <b style="color: white;">Run Intelligence Pipeline</b> to start autonomous threat analysis.</p>
            <hr style="border-color: rgba(255,255,255,0.05); margin: 20px 0;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">🔍 <b>OSINT Recon</b><br><span style="color:#64748b; font-size:0.9rem;">Shodan, VirusTotal, WHOIS</span></div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">📡 <b>Threat Feeds</b><br><span style="color:#64748b; font-size:0.9rem;">CISA KEV, OTX AlienVault</span></div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">🌑 <b>Dark Web</b><br><span style="color:#64748b; font-size:0.9rem;">Ransomware.live, ThreatFox, URLhaus</span></div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">🔎 <b>IOC Extraction</b><br><span style="color:#64748b; font-size:0.9rem;">AI-powered (Ollama)</span></div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">🗺️ <b>MITRE ATT&CK</b><br><span style="color:#64748b; font-size:0.9rem;">Groq LLM mapping</span></div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">👤 <b>Threat Profiling</b><br><span style="color:#64748b; font-size:0.9rem;">Full adversary profile</span></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 15px 20px; border-radius: 0 8px 8px 0; margin-top: 20px; color: #94a3b8; animation: fadeInUp 1s ease-out;">
        💡 <b>Tip:</b> Try a test target like <code style="background: rgba(0,0,0,0.3); color: #60a5fa; padding: 2px 6px; border-radius: 4px;">8.8.8.8</code> (Google DNS) or <code style="background: rgba(0,0,0,0.3); color: #60a5fa; padding: 2px 6px; border-radius: 4px;">1.1.1.1</code> (Cloudflare)
    </div>
    """, unsafe_allow_html=True)