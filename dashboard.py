import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = "siem.db"
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {"critical": "#B42318", "high": "#C2410C", "medium": "#A16207", "low": "#57534E"}

st.set_page_config(page_title="mini-siem", layout="wide")
st.title("mini-siem")

if not Path(DB_PATH).exists():
    st.info("No database found. Run `python ingest.py` first, then reload this page.")
    st.stop()

conn = sqlite3.connect(DB_PATH)
events = pd.read_sql_query("SELECT ts, source, ip FROM events", conn, parse_dates=["ts"])
alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY ts_start DESC", conn)

st.caption(f"Logs from {events.ts.min():%d %b %Y %H:%M} to {events.ts.max():%d %b %Y %H:%M}")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total events", f"{len(events):,}")
col2.metric("Total alerts", len(alerts))
col3.metric("Critical and high", alerts.severity.isin(["critical", "high"]).sum())
col4.metric("Alerting IPs", alerts.ip.nunique())

st.sidebar.header("Filter alerts")
severity_filter = st.sidebar.multiselect("Severity", SEVERITIES, default=SEVERITIES)
rules = sorted(alerts.rule.unique())
rule_filter = st.sidebar.multiselect("Rule", rules, default=rules)
shown = alerts[alerts.severity.isin(severity_filter) & alerts.rule.isin(rule_filter)]

st.subheader("Alerts")
table = shown[["ts_start", "ts_end", "severity", "rule", "technique", "ip", "details"]]
styled = table.style.map(lambda s: f"color: {SEVERITY_COLORS.get(s, 'inherit')}; font-weight: 600",
                         subset=["severity"])
st.dataframe(styled, hide_index=True, width="stretch")

# SSH and web volumes differ by about 30x, so a shared axis would flatten SSH to nothing.
st.subheader("Events per hour")
hourly = events.groupby([events.ts.dt.hour.rename("hour"), "source"]).size().unstack(fill_value=0)
hourly = hourly.reindex(range(24), fill_value=0)
left, right = st.columns(2)
for column, source, label in [(left, "ssh", "SSH"), (right, "web", "Web")]:
    column.caption(f"{label} events")
    column.bar_chart(hourly[source], x_label="Hour of day", y_label="Events", color="#9A3412", height=260)

st.subheader("Top alerting IPs")
shown_ranked = shown.assign(rank=shown.severity.map(SEVERITIES.index))
top_ips = (
    shown_ranked.groupby("ip")
    .agg(alerts=("id", "count"), rank=("rank", "min"), rules=("rule", lambda r: ", ".join(sorted(set(r)))))
    .sort_values(["rank", "alerts"], ascending=[True, False])
    .reset_index()
)
top_ips["worst severity"] = top_ips["rank"].map(lambda i: SEVERITIES[i])
st.dataframe(top_ips[["ip", "alerts", "worst severity", "rules"]], hide_index=True, width="stretch")

st.subheader("IP drill-down")
ip = st.selectbox("Alerting IP", top_ips.ip)
if ip:
    lines = pd.read_sql_query("SELECT raw FROM events WHERE ip = ? ORDER BY ts", conn, params=(ip,))
    st.caption(f"{len(lines)} log lines from {ip}")
    st.code("\n".join(lines.raw), language=None, height=360)
