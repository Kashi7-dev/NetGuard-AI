
import pandas as pd
import plotly.express as px
import streamlit as st
import requests

from api_client import (
    upload_pcap,
    get_analyses,
    get_analysis_detail,
)


st.set_page_config(
    page_title="NetGuard AI",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------
# Helper functions
# ---------------------------------------------

def show_overview(data):
    st.subheader("Traffic Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Packets",
        f"{data.get('total_packets', 0):,}",
    )

    col2.metric(
        "Total Bytes",
        f"{data.get('total_bytes', 0):,}",
    )

    col3.metric(
        "Unique Source IPs",
        data.get("unique_source_ips", 0),
    )

    col4.metric(
        "Security Alerts",
        len(data.get("alerts", [])),
    )


def show_traffic_charts(data):
    st.subheader("Traffic Timeline")

    timeseries = data.get("traffic_timeseries", [])

    if not timeseries:
        st.info("No traffic timeseries available.")
        return

    df = pd.DataFrame(timeseries)
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        utc=True,
    )

    fig_pps = px.line(
        df,
        x="timestamp",
        y="pps",
        title="Packets Per Second",
        markers=True,
    )

    fig_bytes = px.line(
        df,
        x="timestamp",
        y="bps",
        title="Traffic Volume (Bytes/s)",
        markers=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.plotly_chart(
            fig_pps,
            use_container_width=True,
        )

    with col2:
        st.plotly_chart(
            fig_bytes,
            use_container_width=True,
        )


def show_protocol_distribution(data):
    st.subheader("Protocol Distribution")

    protocols = data.get("protocol_distribution")

    # Phase 4 does not persist this field separately.
    # Reconstruct packet counts from stored flows.
    if protocols is None:
        protocols = {}

        for flow in data.get("flows", []):
            protocol = flow["protocol"]
            protocols[protocol] = (
                protocols.get(protocol, 0)
                + flow["packets"]
            )

    if not protocols:
        st.info("No protocol data available.")
        return

    df = pd.DataFrame([
        {"Protocol": name, "Packets": count}
        for name, count in protocols.items()
    ])

    fig = px.pie(
        df,
        names="Protocol",
        values="Packets",
        title="Network Protocol Distribution",
        hole=0.4,
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


def show_network_flows(data):
    st.subheader("Network Flows")

    flows = data.get("flows", [])

    if not flows:
        st.info("No network flows available.")
        return

    df = pd.DataFrame(flows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )


def show_security_alerts(data):
    st.subheader("Security Alerts")

    alerts = data.get("alerts", [])

    if not alerts:
        st.success(
            "No anomalies detected by the configured rules."
        )
        return

    severity_filter = st.selectbox(
        "Filter by severity",
        ["ALL", "HIGH", "MEDIUM", "LOW"],
    )

    filtered = [
        alert for alert in alerts
        if severity_filter == "ALL"
        or alert["severity"] == severity_filter
    ]

    if not filtered:
        st.info("No alerts match this filter.")
        return

    for alert in filtered:
        severity = alert["severity"]
        alert_type = alert["alert_type"]
        source_ip = alert.get("source_ip") or "N/A"

        with st.expander(
            f"[{severity}] {alert_type} — {source_ip}"
        ):
            st.write(alert["description"])
            st.write(
                "Detected at:",
                alert.get("detected_at") or "Not specified",
            )


def show_analysis(data):
    if not data:
        st.info("Upload a PCAP or select a previous analysis.")
        return

    if data.get("analysis_id") or data.get("id"):
        st.caption(
            f"Analysis ID: "
            f"{data.get('analysis_id', data.get('id'))}"
        )

    show_overview(data)

    st.divider()
    show_traffic_charts(data)

    st.divider()
    show_protocol_distribution(data)

    st.divider()
    show_network_flows(data)

    st.divider()
    show_security_alerts(data)


# ---------------------------------------------
# Main dashboard
# ---------------------------------------------

st.title("🛡️ NetGuard AI")
st.caption(
    "Network Traffic Monitoring and Anomaly Detection"
)

st.sidebar.header("Navigation")

page = st.sidebar.radio(
    "Choose a page",
    ["Upload & Analyze", "Analysis History"],
)

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None


if page == "Upload & Analyze":
    st.header("Upload PCAP")

    uploaded_file = st.file_uploader(
        "Choose a PCAP file",
        type=["pcap", "pcapng"],
        max_upload_size=10,
    )

    if uploaded_file is not None:
        st.write(
            f"Selected: {uploaded_file.name}"
        )

        if st.button(
            "Analyze Traffic",
            type="primary",
        ):
            try:
                with st.spinner(
                    "Analyzing network traffic..."
                ):
                    result = upload_pcap(uploaded_file)

                st.session_state.analysis_result = result
                st.success(
                    "Traffic analysis completed successfully."
                )

            except requests.RequestException as exc:
                st.error(f"API request failed: {exc}")

    show_analysis(
        st.session_state.analysis_result
    )


elif page == "Analysis History":
    st.header("Previous Analyses")

    try:
        analyses = get_analyses()

        if not analyses:
            st.info("No saved analyses found.")

        else:
            history_df = pd.DataFrame(analyses)

            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True,
            )

            options = {
                f"#{item['id']} — {item['filename']}": item["id"]
                for item in analyses
            }

            selected = st.selectbox(
                "Select an analysis",
                list(options.keys()),
            )

            if st.button("View Analysis"):
                analysis_id = options[selected]

                with st.spinner("Loading analysis..."):
                    detail = get_analysis_detail(analysis_id)

                st.session_state.history_detail = detail

            if "history_detail" in st.session_state:
                show_analysis(
                    st.session_state.history_detail
                )

    except requests.RequestException as exc:
        st.error(f"Unable to load analysis history: {exc}")
