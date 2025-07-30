import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import numpy as np

# ---- Mock Data Generation ----
np.random.seed(1)
mock_assets = [f"10.0.0.{i}" for i in range(1, 11)]
mock_tools = ["Nessus", "PingCastle", "Prowler", "ScoutSuite"]
severities = ["Critical", "High", "Medium", "Low", "Informational"]

data = []
for i in range(120):
    asset = np.random.choice(mock_assets)
    sev = np.random.choice(severities, p=[0.1, 0.2, 0.3, 0.3, 0.1])
    score = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Informational": 0}[sev] + np.random.uniform(-1,1)
    row = {
        "id": f"VULN-{1000+i}",
        "title": f"Mock Finding {i+1}",
        "severity": sev,
        "cvss_score": np.clip(score, 0, 10),
        "asset_ip": asset,
        "asset_hostname": f"host-{asset.replace('.', '-')}",
        "source_tool": np.random.choice(mock_tools),
        "date_found": (datetime.now() - timedelta(days=np.random.randint(0,30))).strftime("%Y-%m-%d"),
        "status": "open" if np.random.rand() > 0.2 else "remediated"
    }
    data.append(row)

df = pd.DataFrame(data)

# ---- Sidebar Filters ----
st.sidebar.title("Filters")
sel_sevs = st.sidebar.multiselect("Severity", severities, default=severities)
sel_tools = st.sidebar.multiselect("Tool", mock_tools, default=mock_tools)
sel_status = st.sidebar.radio("Status", ["All", "Open", "Remediated"])
date_range = st.sidebar.slider("Days Back", 1, 30, (1, 30))

# ---- Filter Data ----
df_filtered = df[
    df.severity.isin(sel_sevs) &
    df.source_tool.isin(sel_tools) &
    (
        (sel_status == "All") |
        (df.status.str.lower() == sel_status.lower())
    ) &
    (
        (pd.to_datetime(df.date_found) >= datetime.now() - timedelta(days=date_range[1])) &
        (pd.to_datetime(df.date_found) <= datetime.now() - timedelta(days=date_range[0]-1))
    )
]

# ---- Dashboard Layout ----
st.title("Client Security Assessment Dashboard")
st.markdown("**All findings presented are for demonstration (mock data).**\n")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Findings", len(df_filtered))
col2.metric("Critical", (df_filtered["severity"] == "Critical").sum())
col3.metric("High", (df_filtered["severity"] == "High").sum())
col4.metric("Assets", df_filtered["asset_ip"].nunique())
col5.metric("Avg CVSS", f'{df_filtered["cvss_score"].mean():.1f}')

# ---- Charts ----
col6, col7 = st.columns(2)
with col6:
    st.subheader("Severity Distribution")
    fig = px.pie(df_filtered, names="severity", color="severity",
                 color_discrete_map={"Critical":"crimson","High":"orangered","Medium":"orange","Low":"yellow","Informational":"green"})
    st.plotly_chart(fig)

with col7:
    st.subheader("By Source Tool")
    st.bar_chart(df_filtered["source_tool"].value_counts())

st.subheader("Top Vulnerable Assets")
asset_counts = df_filtered.groupby("asset_ip")["id"].count().sort_values(ascending=False).head(10)
st.bar_chart(asset_counts)

st.subheader("Trend: Findings Over Time")
trend = df_filtered.groupby("date_found")["id"].count()
st.line_chart(trend)

# ---- Compliance Status ----
st.markdown("### Compliance Framework Overview")
critical = (df_filtered["severity"] == "Critical").sum()
high = (df_filtered["severity"] == "High").sum()
nist = "Compliant" if critical == 0 and high <= 3 else "Partial" if critical <= 2 and high <= 5 else "Non-Compliant"
st.write(f"NIST Cybersecurity Framework Status: **{nist}**")

# ---- Interactive Table ----
st.subheader("Drilldown: Detailed Findings")
st.dataframe(df_filtered[["id","title","severity","asset_ip","source_tool","cvss_score","date_found","status"]])

# ---- Export ----
st.download_button("Export as CSV", df_filtered.to_csv(index=False), "filtered_findings.csv")

