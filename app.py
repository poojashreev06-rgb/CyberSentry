import streamlit as st
import pandas as pd
import re
from collections import Counter
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="CyberSentry",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 CyberSentry")
st.subheader("Security Log Analysis & Rule-Based Threat Detection")
st.write(
    "Analyse SSH security logs, identify repeated failed logins, "
    "and flag potentially suspicious activity."
)

uploaded_file = st.file_uploader(
    "Upload an SSH log file",
    type=["log", "txt"]
)

if uploaded_file is not None:
    logs = uploaded_file.getvalue().decode(
        "utf-8", errors="ignore"
    ).splitlines()

    records = []

    for line in logs:
        if "Failed password" not in line:
            continue

        timestamp_match = re.search(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            line
        )
        ip_match = re.search(
            r"from (\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if timestamp_match and ip_match:
            records.append({
                "timestamp": timestamp_match.group(1),
                "ip_address": ip_match.group(1)
            })

    failed_df = pd.DataFrame(records)

    total_logs = len(logs)
    failed_count = len(failed_df)
    invalid_users = sum("Invalid user" in line for line in logs)

    st.subheader("Dataset Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Log Entries", total_logs)
    col2.metric("Failed-Password Messages", failed_count)
    col3.metric("Invalid-User Messages", invalid_users)

    if not failed_df.empty:
        ip_counts = Counter(failed_df["ip_address"])

        total_df = pd.DataFrame(
            ip_counts.items(),
            columns=["Source IP", "Total Failed Messages"]
        )

        total_df["Total Count Rule"] = total_df[
            "Total Failed Messages"
        ] >= 10

        failed_df["time"] = pd.to_datetime(
            failed_df["timestamp"],
            format="%b %d %H:%M:%S",
            errors="coerce"
        )

        window_results = []

        for ip, group in failed_df.groupby("ip_address"):
            times = (
                group["time"]
                .dropna()
                .sort_values()
                .reset_index(drop=True)
            )

            if times.empty:
                continue

            left = 0
            best_count = 0
            best_start = None
            best_end = None

            for right in range(len(times)):
                while (
                    times.iloc[right] - times.iloc[left]
                    > pd.Timedelta(minutes=5)
                ):
                    left += 1

                count = right - left + 1

                if count > best_count:
                    best_count = count
                    best_start = times.iloc[left]
                    best_end = times.iloc[right]

            window_results.append({
                "Source IP": ip,
                "Max Messages in 5 Minutes": best_count,
                "Window Start": best_start,
                "Window End": best_end
            })

        window_df = pd.DataFrame(window_results)

        results = total_df.merge(
            window_df, on="Source IP", how="left"
        )

        results["Time Window Rule"] = (
            results["Max Messages in 5 Minutes"] >= 5
        )

        results["Window Start"] = pd.to_datetime(
            results["Window Start"]
        ).dt.strftime("%b %d %H:%M:%S")

        results["Window End"] = pd.to_datetime(
            results["Window End"]
        ).dt.strftime("%b %d %H:%M:%S")

        results = results.sort_values(
            "Max Messages in 5 Minutes",
            ascending=False
        )

        flagged = results[
            results["Total Count Rule"] |
            results["Time Window Rule"]
        ]

        st.subheader("Failed-Password Activity by IP")
        st.bar_chart(
            results.set_index("Source IP")[
                "Total Failed Messages"
            ]
        )

        st.subheader("Potentially Suspicious IP Addresses")
        st.caption(
            "Flags are based on configurable rules and do not "
            "prove malicious activity."
        )
        st.dataframe(flagged, use_container_width=True)

        st.subheader("All Analysed IP Addresses")
        st.dataframe(results, use_container_width=True)

        csv_data = results.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Analysis Results (CSV)",
            data=csv_data,
            file_name="cybersentry_results.csv",
            mime="text/csv"
        )

    else:
        st.warning(
            "No failed-password records with extractable IP addresses "
            "were found in this file."
        )

else:
    st.info("Upload your OpenSSH log file to begin analysis.")
