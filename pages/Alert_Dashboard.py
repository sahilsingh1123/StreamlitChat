import streamlit as st
import requests
from backend.datastore import Datastore
import pandas as pd
import streamlit_shadcn_ui as ui
from demo_model import start
from constant import *


def set_seleted_data(data):
    st.session_state["data"] = data


def build_alert_headers(table_data):
    header_cols = st.columns(len(table_data.columns) + 1)  # +1 for the button column
    for i, header in enumerate(table_data.columns):
        header_cols[i].markdown(f"**{header}**")
    header_cols[-1].markdown(
        f"**{ACTION}**"
    )  # Placeholder for the button column header

    # Insert a visual separator (line) after the headers
    st.markdown(
        "<hr style='margin-top:0.25rem; margin-bottom:0.25rem;'/>",
        unsafe_allow_html=True,
    )


def get_widgets(data):
    total_alerts = len(data)
    incident = 0
    status_counts = data[STATUS].value_counts()
    assessment_counts = data[ASSESSMENT].value_counts()
    incident = str(assessment_counts.get(TRUE_POSITIVE, 0))
    completed_count = str(status_counts.get(COMPLETE, 0))
    pending = str(status_counts.get(PENDING, 0))
    review = str(status_counts.get(REVIEW, 0))

    cols = st.columns(4)
    values = [total_alerts, incident, pending, review]
    with cols[0]:
        ui.metric_card(title=TOTAL_ALERTS, content=values[0])
    with cols[1]:
        ui.metric_card(title=INCIDENT, content=values[1])
    with cols[2]:
        ui.metric_card(title=PENDING, content=values[2])
    with cols[3]:
        ui.metric_card(title=REVIEW, content=values[3])


def create_alert_table(main_data, datastoreObj):
    # Display the DataFrame with an extra column for buttons
    filter_column = datastoreObj.get_alert_columns_name
    table_data = main_data[filter_column]
    get_widgets(table_data)
    build_alert_headers(table_data)

    for _, row in table_data.iterrows():
        cols = st.columns(len(row) + 1)  # +1 for the button column
        key = ""
        for i, value in enumerate(row):
            if not key:
                key = value
            cols[i].write(value)
        do_action = cols[-1].button("Details", key=key)
        if do_action:
            filterData = {CASEID: key}
            set_seleted_data(filterData)
            st.switch_page("pages/Investigation_Details.py")


def get_alert_type(row):
    alertType = "Alert"
    alertData = row[ALERT]
    if "email_header" in alertData:
        alertType = "Phishing"
    return alertType


##################-----------------start

with st.sidebar:
    st.title(HACKATHON_TITLE)
st.title(ALERT_DASHBOARD)

datastoreObj = Datastore()
try:
    main_data = datastoreObj.get_dataset()
except Exception as e:
    main_data = datastoreObj.get_empty_dataset()

create_alert_table(main_data, datastoreObj)

# now check for pending assessment data from dataset
pending_asse_df = main_data[main_data[STATUS] == PENDING]
try:
    in_progress = st.session_state[IN_PROGRESS]
except Exception as e:
    st.session_state[IN_PROGRESS] = False

for id, row in pending_asse_df.iterrows():
    # make sure to update the pending status to investigating
    alertType = get_alert_type(row)
    print(f"- alert tpe {alertType}")
    # if alertType == "Phishing":
    if not st.session_state[IN_PROGRESS]:
        print("indei prog")
        st.session_state[IN_PROGRESS] = True
        print(f"inside if condition - {alertType}")
        start(row, alertType)
print("done with alert page")
