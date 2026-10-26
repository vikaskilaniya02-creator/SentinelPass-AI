"""Read-only Streamlit dashboard:  streamlit run dashboard.py

Never shows hashes, salts, tokens or session IDs. It only reads aggregates and
sanitised event rows.
"""
import pandas as pd
import streamlit as st

from app_context import build_context
from reports.security_report import build_report

st.set_page_config(page_title="SentinelPass AI", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_ctx():
    return build_context()


ctx = get_ctx()
rep = build_report(ctx)
auth, ov, pw = rep["authentication_statistics"], rep["system_overview"], rep["password_security"]

st.title("🛡️ SentinelPass AI - Security Dashboard")
st.caption("AI-Assisted Password Security & Adaptive Authentication Platform (local demo, synthetic data)")
if st.button("Refresh"):
    st.rerun()

tab_overview, tab_security, tab_activity, tab_ai, tab_pw = st.tabs(
    ["Overview", "Security", "Login Activity", "AI Security Center", "Password Security"])

with tab_overview:
    c = st.columns(4)
    c[0].metric("Total users", ov["total_users"])
    c[1].metric("Active users", ov["active_users"])
    c[2].metric("Locked accounts", ov["locked_accounts"])
    c[3].metric("Reset requests", auth["reset_requests"])
    c = st.columns(3)
    c[0].metric("Successful logins", auth["successful_logins"])
    c[1].metric("Failed logins", auth["failed_logins"])
    c[2].metric("Suspicious logins", auth["suspicious_logins"])

with tab_security:
    st.subheader("Risk distribution")
    st.bar_chart(pd.Series(rep["risk_distribution"]))
    st.subheader("Recent security events")
    st.dataframe(pd.DataFrame(rep["recent_security_events"]), use_container_width=True)

with tab_activity:
    rows = [{"time (UTC)": r["timestamp"][:19], "user": r["username_attempted"],
             "result": "OK" if r["success"] else "FAIL", "risk": r["risk_level"],
             "score": r["risk_score"], "region": r["ip_label"], "reason": r["reason"]}
            for r in ctx.login_events.recent(50)]
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

with tab_ai:
    ai = rep["ai_analysis"]
    st.subheader(f"AI risk assessment - {ai['risk']}  (source: {ai['source']})")
    st.write(ai["explanation"])
    st.markdown("**Recommendations**")
    for r in rep["security_recommendations"]:
        st.write(f"- {r}")
    st.markdown("**Anomaly detection results (risk score >= 50)**")
    st.dataframe(pd.DataFrame(rep["detected_anomalies"]), use_container_width=True)
    ev = rep.get("detector_evaluation")
    if ev:
        st.markdown("**Detector evaluation on synthetic data**")
        st.json(ev["metrics"])
    st.info("AI explains and recommends. Deterministic code makes every security decision.")

with tab_pw:
    c = st.columns(3)
    c[0].metric("Strong passwords", f"{pw['strong_password_pct']}%")
    c[1].metric("Weak passwords", f"{pw['weak_password_pct']}%")
    c[2].metric("Reuse attempts blocked", pw["password_reuse_detections"])
    st.write("Accounts requiring password update:", pw["accounts_requiring_update"] or "none")
