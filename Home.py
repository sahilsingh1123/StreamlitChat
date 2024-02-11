import streamlit as st
import requests
from constant import *

st.set_page_config(layout="wide")
with st.sidebar:
    st.title(HACKATHON_TITLE)
st.title("Welcome")
st.header(ALERT_PAGE_FROM_HOME_MESSAGE)
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
if st.button("Alert Dashboard"):
    st.switch_page("pages/Alert_Dashboard.py")
