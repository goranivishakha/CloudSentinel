"""
CloudSentinel Enterprise Dashboard
SOC-Grade UI for Security Posture Management
"""

import streamlit as st
import json
import os
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
from datetime import datetime

# Import CloudSentinel orchestrator
from cloudscan_orchestrator import CloudSentinelOrchestrator

st.set_page_config(
    page_title="CloudSentinel",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    /* Base Theme Override - Deep Slate */
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
    }
    
    /* Hide Streamlit Branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Global Typography */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Enterprise Metric Cards */
    .metric-container {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 24px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 4px;
        line-height: 1.2;
    }
    
    .metric-label {
        font-size: 0.875rem;
        font-weight: 500;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Score specific colors */
    .score-value { color: #10b981; } /* Emerald */
    .score-warning { color: #f59e0b; } /* Amber */
    .score-critical { color: #ef4444; } /* Red */

    /* Severity Badges */
    .badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }
    .badge-high { background-color: rgba(249, 115, 22, 0.1); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.2); }
    .badge-medium { background-color: rgba(59, 130, 246, 0.1); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.2); }
    .badge-low { background-color: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); }

    /* Alert Row */
    .alert-row {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-left: 4px solid;
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .border-critical { border-left-color: #ef4444; }
    .border-high { border-left-color: #f97316; }
    
    .alert-title {
        font-size: 1rem;
        font-weight: 600;
        color: #f8fafc;
        margin-bottom: 4px;
    }
    .alert-meta {
        font-size: 0.875rem;
        color: #94a3b8;
    }
    .alert-recommendation {
        margin-top: 8px;
        font-size: 0.875rem;
        color: #cbd5e1;
        background: #0f172a;
        padding: 8px;
        border-radius: 4px;
        border: 1px solid #334155;
    }
    
    /* Status Dots */
    .dot {
        height: 10px;
        width: 10px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
    }
    .dot-critical { background-color: #ef4444; }
    .dot-high { background-color: #f97316; }
    .dot-medium { background-color: #3b82f6; }
    .dot-low { background-color: #10b981; }
    </style>
""", unsafe_allow_html=True)

# ========== HELPER FUNCTIONS ==========

@st.cache_data(ttl=60)
def load_latest_scan():
    """Load latest scan from reports directory."""
    report_dir = Path("reports")
    if not report_dir.exists():
        return None
    
    score_files = sorted(report_dir.glob("score_*.json"), reverse=True)
    if not score_files:
        return None
    
    with open(score_files[0], 'r') as f:
        score_data = json.load(f)
    
    timestamp = score_files[0].stem.replace("score_", "")
    findings_file = report_dir / f"findings_{timestamp}.json"
    plan_file = report_dir / f"remediation_plan_{timestamp}.json"
    
    findings_data = json.load(open(findings_file)) if findings_file.exists() else None
    plan_data = json.load(open(plan_file)) if plan_file.exists() else None
    
    return {"score": score_data, "findings": findings_data, "plan": plan_data, "timestamp": timestamp}

@st.cache_data(ttl=60)
def load_scan_history():
    """Load historical scan data."""
    history_dir = Path("scan_history")
    if not history_dir.exists():
        return []
    return [json.load(open(f)) for f in sorted(history_dir.glob("scan_*.json"))]

def get_severity_color(severity):
    """Get color for severity badge or visual indicator."""
    colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#3b82f6",
        "LOW": "#10b981"
    }
    return colors.get(severity, "#64748b")

# ========== SIDEBAR ==========

with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: #f8fafc; letter-spacing: 0.1em;'>CLOUDSENTINEL</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase;'>Security Operations</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    menu = st.radio(
        "Navigation",
        ["Executive Dashboard", "Findings Directory", "Remediation Queue", "Posture Trending", "Engine Settings"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    
    if st.button("Initialize Security Scan", type="primary", use_container_width=True):
        with st.spinner("Executing compliance engines..."):
            try:
                orchestrator = CloudSentinelOrchestrator(verbose=False)
                result = orchestrator.run_complete_scan()
                if result['status'] == 'SUCCESS':
                    st.success("Scan successful.")
                else:
                    st.error(f"Engine failure: {result.get('error', 'Unknown')}")
                st.cache_data.clear()
                st.rerun()
            except Exception as e:
                st.error(f"Execution Error: {str(e)}")

# Standard Chart Colors for Dark Theme
CHART_COLORS = ['#ef4444', '#f97316', '#3b82f6', '#10b981']
PLOTLY_THEME = dict(
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(0,0,0,0)',
    font=dict(color='#94a3b8'),
    margin=dict(t=30, b=30, l=30, r=30)
)

# ========== PAGES ==========

if menu == "Executive Dashboard":
    st.markdown("### Posture Overview")
    
    scan_data = load_latest_scan()
    history = load_scan_history()
    
    if not scan_data:
        st.info("System Ready. Initialize a scan from the control panel to generate telemetry.")
    else:
        score = scan_data["score"]["final_score"]
        grade = scan_data["score"]["grade"].split(" ")[0] # Just the letter
        findings = scan_data["findings"]["total_findings"]
        
        score_class = "score-value" if score >= 80 else "score-warning" if score >= 60 else "score-critical"
        
        # Key Metrics Row
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
                <div class='metric-container'>
                    <div class='metric-value {score_class}'>{score}<span style='font-size: 1.5rem; color: #64748b;'>/100</span></div>
                    <div class='metric-label'>Aggregate Risk Score ({grade})</div>
                </div>
            """, unsafe_allow_html=True)
            
        with c2:
            st.markdown(f"""
                <div class='metric-container'>
                    <div class='metric-value' style='color: #f8fafc;'>{findings}</div>
                    <div class='metric-label'>Active Misconfigurations</div>
                </div>
            """, unsafe_allow_html=True)
            
        with c3:
            if len(history) > 1:
                improvement = history[-1]["security_score"] - history[0]["security_score"]
                prefix = "+" if improvement >= 0 else ""
                imp_color = "#10b981" if improvement >= 0 else "#ef4444"
                st.markdown(f"""
                    <div class='metric-container'>
                        <div class='metric-value' style='color: {imp_color};'>{prefix}{improvement}</div>
                        <div class='metric-label'>Posture Delta</div>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                    <div class='metric-container'>
                        <div class='metric-value' style='color: #64748b;'>--</div>
                        <div class='metric-label'>Awaiting Baseline Comparison</div>
                    </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        
        # Charts Row
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.markdown("<div class='metric-label' style='margin-bottom: 10px;'>Risk Distribution</div>", unsafe_allow_html=True)
            sev_counts = scan_data["findings"]["count_by_severity"]
            # AWS Style Donut Chart
            fig = go.Figure(data=[go.Pie(
                labels=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                values=[sev_counts['CRITICAL'], sev_counts['HIGH'], sev_counts['MEDIUM'], sev_counts['LOW']],
                hole=0.7,
                marker=dict(colors=CHART_COLORS),
                textinfo='value',
                hoverinfo='label+percent'
            )])
            fig.update_layout(**PLOTLY_THEME, height=300, showlegend=True)
            st.plotly_chart(fig, use_container_width=True)

        with col_chart2:
            st.markdown("<div class='metric-label' style='margin-bottom: 10px;'>Affected Workloads</div>", unsafe_allow_html=True)
            srv_counts = scan_data["findings"]["count_by_service"]
            fig = px.bar(
                x=list(srv_counts.values()), 
                y=list(srv_counts.keys()),
                orientation='h',
                color_discrete_sequence=['#3b82f6']
            )
            fig.update_layout(**PLOTLY_THEME, height=300, xaxis_title="", yaxis_title="", showlegend=False)
            fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#334155')
            fig.update_yaxes(showgrid=False)
            st.plotly_chart(fig, use_container_width=True)

        # Critical Alerts Row
        st.markdown("<br><div class='metric-label' style='margin-bottom: 16px;'>Priority Security Events</div>", unsafe_allow_html=True)
        if scan_data["findings"]["findings"]:
            top_issues = [f for f in scan_data["findings"]["findings"] if f['severity'] in ['CRITICAL', 'HIGH']][:5]
            if not top_issues:
                st.markdown("<div style='color: #10b981; font-weight: 500;'>Zero critical security events detected.</div>", unsafe_allow_html=True)
            else:
                for issue in top_issues:
                    sev = issue['severity'].lower()
                    st.markdown(f"""
                        <div class='alert-row border-{sev}'>
                            <div class='alert-title'>
                                <span class='badge badge-{sev}'>{issue['severity']}</span> &nbsp; {issue['title']}
                            </div>
                            <div class='alert-meta'>
                                Target: <code>{issue['resource']}</code> &nbsp;|&nbsp; Service: {issue['service']}
                            </div>
                            <div class='alert-recommendation'>
                                Action Required: {issue['recommendation']}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

elif menu == "Findings Directory":
    st.markdown("### Vulnerability Database")
    
    scan_data = load_latest_scan()
    if not scan_data:
        st.warning("No telemetry available.")
    else:
        findings = scan_data["findings"]["findings"]
        
        # Clean Filters
        fc1, fc2, fc3 = st.columns([2, 2, 1])
        with fc1:
            sev_filter = st.multiselect("Severity Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
        with fc2:
            services = list(set(f['service'] for f in findings))
            srv_filter = st.multiselect("Target Service", services, default=services)
        
        filtered = [f for f in findings if f['severity'] in sev_filter and f['service'] in srv_filter]
        
        with fc3:
            st.markdown(f"""
                <div style='margin-top: 28px; text-align: right; color: #94a3b8;'>
                    Showing {len(filtered)} records
                </div>
            """, unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        
        if filtered:
            df = pd.DataFrame(filtered)
            display_df = df[['severity', 'service', 'resource', 'title', 'id']].copy()
            st.dataframe(display_df, use_container_width=True, hide_index=True)
            
            st.markdown("<br><div class='metric-label'>Evidence & Artifacts (Top 10)</div>", unsafe_allow_html=True)
            for f in filtered[:10]:
                sev = f['severity'].lower()
                with st.expander(f"{f['id']} — {f['title']} ({f['resource']})"):
                    st.markdown(f"**Severity:** <span class='badge badge-{sev}'>{f['severity']}</span>", unsafe_allow_html=True)
                    st.code(f"Evidence Artifact:\n{f['evidence']}\n\nRisk Context:\n{f['risk_reason']}", language="text")
        else:
            st.markdown("<div style='color: #94a3b8;'>No findings match the active query.</div>", unsafe_allow_html=True)

elif menu == "Remediation Queue":
    st.markdown("### Active Triage Plan")
    
    scan_data = load_latest_scan()
    if not scan_data or not scan_data["plan"]:
        st.warning("No triage plan generated.")
    else:
        plan = scan_data["plan"]
        summary = plan["summary"]
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"<div class='metric-container'><div class='metric-value score-critical'>{summary['by_priority']['IMMEDIATE']}</div><div class='metric-label'>Immediate (4h SLA)</div></div>", unsafe_allow_html=True)
        with c2:
            st.markdown(f"<div class='metric-container'><div class='metric-value score-warning'>{summary['by_priority']['URGENT']}</div><div class='metric-label'>Urgent (24h SLA)</div></div>", unsafe_allow_html=True)
        with c3:
            st.markdown(f"<div class='metric-container'><div class='metric-value' style='color:#3b82f6;'>{summary['by_priority']['SOON']}</div><div class='metric-label'>Standard (7d SLA)</div></div>", unsafe_allow_html=True)
        with c4:
            st.markdown(f"<div class='metric-container'><div class='metric-value' style='color:#f8fafc;'>{summary['estimated_total_time_hours']}h</div><div class='metric-label'>Est. Engineering Hours</div></div>", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        for item in plan["plan_items"]:
            pri = item['priority'].lower()
            color_map = {"immediate": "critical", "urgent": "high", "soon": "medium", "eventual": "low"}
            badge_class = color_map.get(pri, "medium")
            
            with st.expander(f"{item['service']} — {item['title']}"):
                st.markdown(f"**SLA:** <span class='badge badge-{badge_class}'>{item['priority']}</span> &nbsp; | &nbsp; **Resource:** <code>{item['resource']}</code>", unsafe_allow_html=True)
                st.markdown("#### Execution Runbook")
                for step in item['steps']:
                    st.markdown(f"- {step}")

elif menu == "Posture Trending":
    st.markdown("### Historical Analytics")
    history = load_scan_history()
    
    if len(history) < 2:
        st.markdown("<div style='color: #94a3b8;'>Insufficient historical data. Minimum 2 scans required for trend generation.</div>", unsafe_allow_html=True)
    else:
        df = pd.DataFrame([{
            "Timestamp": pd.to_datetime(h["timestamp"]),
            "Score": h["security_score"],
            "Critical": h["findings_by_severity"]["CRITICAL"],
            "High": h["findings_by_severity"]["HIGH"]
        } for h in history])
        
        st.markdown("<div class='metric-label' style='margin-bottom: 10px;'>Compliance Score Trend</div>", unsafe_allow_html=True)
        fig = px.area(df, x="Timestamp", y="Score", markers=True, color_discrete_sequence=['#10b981'])
        fig.update_layout(**PLOTLY_THEME, yaxis_range=[0, 100], height=350)
        fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#334155')
        fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#334155')
        st.plotly_chart(fig, use_container_width=True)
            
        st.markdown("<div class='metric-label' style='margin-top: 20px; margin-bottom: 10px;'>Vulnerability Volume</div>", unsafe_allow_html=True)
        fig2 = px.line(df, x="Timestamp", y=["Critical", "High"], markers=True, color_discrete_sequence=['#ef4444', '#f97316'])
        fig2.update_layout(**PLOTLY_THEME, height=350)
        fig2.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#334155')
        fig2.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#334155')
        st.plotly_chart(fig2, use_container_width=True)

elif menu == "Engine Settings":
    st.markdown("### System Configuration")
    
    st.markdown("<div class='metric-label' style='margin-bottom: 10px;'>Audit Scope</div>", unsafe_allow_html=True)
    scan_s3 = st.toggle("Include S3 Storage Objects", value=True)
    scan_iam = st.toggle("Include IAM Identity Policies", value=True)
    
    st.markdown("<br><div class='metric-label' style='margin-bottom: 10px;'>Data Lifecycle Management</div>", unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Purge Active Reports", use_container_width=True):
            import shutil
            if os.path.exists("reports"): shutil.rmtree("reports")
            st.success("Reports purged.")
            st.rerun()
            
    with c2:
        if st.button("Purge Historical Telemetry", use_container_width=True):
            import shutil
            if os.path.exists("scan_history"): shutil.rmtree("scan_history")
            st.success("History purged.")
            st.rerun()

# ========== FOOTER ==========

st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em;'>"
    "CloudSentinel Security Operations | "
    f"Updated {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    "</p>",
    unsafe_allow_html=True
)