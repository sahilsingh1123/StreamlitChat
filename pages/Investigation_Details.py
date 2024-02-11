import streamlit as st
from openai import OpenAI
import time
import streamlit_nested_layout  # pylint: disable=unused-import
import pandas as pd
from backend.datastore import Datastore
from constant import *

from dotenv import load_dotenv
import os

import cohere


load_dotenv()
COHERE_API_KEY = os.getenv("COHERE_API_KEY")
CHAT_CONNECTOR_ID = os.getenv("CHAT_CONNECTOR_ID")


def get_cohere_client():
    return cohere.Client(api_key=COHERE_API_KEY)


def get_chatbot_response(user_input, client):
    chat_resp = client.chat(
        message=user_input,
        model="command",
        temperature=0.3,
        connectors=[{"id": CHAT_CONNECTOR_ID}],
    )

    return chat_resp.text


def chatbox_func_2():
    st.title("💬 Night's Watch")
    st.caption("🚀 Chatbot Powered by Cohere")
    if "messages" not in st.session_state:
        st.session_state["messages"] = [
            {"role": "assistant", "content": "How can I help you?"}
        ]

    for msg in st.session_state.messages:
        st.chat_message(msg["role"]).write(msg["content"])
    client = get_cohere_client()

    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        st.chat_message("user").write(prompt)
        msg = get_chatbot_response(prompt, client)
        st.session_state.messages.append({"role": "assistant", "content": msg})
        st.chat_message("assistant").write(msg)


def generate_analysis_report_alert(dataset):
    alert_data = dataset[ALERT].iloc[0]
    threat_description = alert_data["threat_description"]
    threat_ip = alert_data["threat_match_value"]
    assessment_details = dataset[ASSESSMENT].iloc[0]

    my_list = [
        f"**Threat Description:** {threat_description}",
        f"**Threat IP:** {threat_ip}",
        f"**Case Assessment:** {assessment_details}",
    ]

    # Create 2 rows
    for i in range(
        0, len(my_list), 2
    ):  # Step by 2 since we're filling 2 columns at a time
        # In each row, create 2 columns
        col1, col2 = st.columns(2)

        # Fill the first column
        with col1:
            st.write(my_list[i])

        # Fill the second column (check if the index exists to avoid index errors)
        if i + 1 < len(my_list):
            with col2:
                st.write(my_list[i + 1])


def generate_analysis_report_phishing(dataset):
    alert_data = dataset[ALERT].iloc[0]
    threat_description = alert_data["email_header"]
    threat_ip = alert_data["ip_address"]
    assessment_details = dataset[ASSESSMENT].iloc[0]
    my_list = [
        f"**Email Header:** {threat_description}",
        f"**Threat IP:** {threat_ip}",
        f"**Case Assessment:** {assessment_details}",
    ]
    # my_list = [f"**{item}**" for item in original_list]

    # Create 2 rows
    for i in range(
        0, len(my_list), 2
    ):  # Step by 2 since we're filling 2 columns at a time
        # In each row, create 2 columns
        col1, col2 = st.columns(2)

        # Fill the first column
        with col1:
            st.write(my_list[i])

        # Fill the second column (check if the index exists to avoid index errors)
        if i + 1 < len(my_list):
            with col2:
                st.write(my_list[i + 1])


def get_header_remediation_button(dataset, alertType):
    header, remediationButton = st.columns([0.75, 0.25])

    # Place the header in the first column
    with header:
        # st.header("Case Analysis")
        if alertType == ALERT:
            generate_analysis_report_alert(dataset)
        elif alertType == PHISHING:
            generate_analysis_report_phishing(dataset)

    # Place the button in the second column
    with remediationButton:
        m = st.markdown(
            """
            <style>
            div.stButton > button:first-child {
                background-color: #0099ff;
                color:#ffffff;
            }
            </style>""",
            unsafe_allow_html=True,
        )

        if st.button(label="Run Remediation"):
            # progress_bar = st.progress(0)
            time.sleep(10)
            st.success(
                "Task Complete. Please check all details in activity tab or JIRA"
            )


def alertDetailsTab(alertDetails):
    st.json(alertDetails)


def remediationTab(assessmentDetails):
    st.markdown(assessmentDetails)


def activityTab(activityDetails):
    st.dataframe(activityDetails, hide_index=True, use_container_width=True)


def prepare_alert_details(dataset):
    return dataset["Alert"].iloc[0]


def prepare_assessment_details(dataset):
    evaluation_steps = dataset["EvaluationSteps"].iloc[0]
    evaluation_enriched = dataset["EvaluationEnriched"].iloc[0]
    evaluation_summary = dataset["EvaluationSummary"].iloc[0]
    remediation_steps = dataset["RemediationDetails"].iloc[0]
    if isinstance(remediation_steps, list):
        remediation_steps = ",\n".join(remediation_steps)

    assessmentDetails = f"""
        **Evaluation Summary:**
        \n{evaluation_summary}
        \n--------------
        \n{evaluation_steps}
        \n--------------
        \n**Evaluation Results:**
        \n{evaluation_enriched}
        \n-----------------------
        \n**Remediation Steps:**
        \n{remediation_steps}
        """
    return assessmentDetails


def prepare_activity_details(dataset):
    activity_details = dataset["ActivityDetails"].iloc[0]
    ac_df = pd.DataFrame(activity_details, columns=["Logs"])
    return ac_df


def fetch_dataset(case_id):
    ds = Datastore()
    df = ds.get_dataset()
    dataset = df[df["CaseId"] == case_id]
    return dataset


def get_alert_type(dataset):
    alertType = "Alert"
    alertData = dataset[ALERT].iloc[0]
    if "email_header" in alertData:
        alertType = "Phishing"
    return alertType


##########-------------------- start
with st.sidebar:
    st.title("Cohere Hackathon")
if st.button("Back to Alerts"):
    st.switch_page("pages/Alert_Dashboard.py")

try:
    caseId = st.session_state["data"][CASEID]
    dataset = fetch_dataset(caseId)
    alertType = get_alert_type(dataset)
    alertDetails = prepare_alert_details(dataset)
    assessmentDetails = prepare_assessment_details(dataset)
    activityDetails = prepare_activity_details(dataset)
    do_load_analysis = True
except Exception as e:
    caseId = None
    do_load_analysis = False


st.title(f"Investigation: {caseId}")
st.markdown(
    "<hr style='margin-top:0.25rem; margin-bottom:0.25rem;'/>", unsafe_allow_html=True
)
# Use columns to create main content area and chatbox
main_content, chatbox = st.columns([2, 1])  # Adjust the ratio based on your preference

# Main content area
if do_load_analysis:
    with main_content:
        get_header_remediation_button(dataset, alertType)
        alert, remediation, activity = st.tabs(
            ["Alert Details", "Automated Evaluation", "Activity"]
        )
        with alert:
            alertDetailsTab(alertDetails)
        with remediation:
            remediationTab(assessmentDetails)
        with activity:
            activityTab(activityDetails)


# Chatbox area
with chatbox:
    # st.header("Chatbox")
    chatbox_func_2()
