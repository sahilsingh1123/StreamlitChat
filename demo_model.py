from langchain_community.retrievers import CohereRagRetriever
from langchain_community.embeddings import CohereEmbeddings
from langchain_community.chat_models import ChatCohere
from langchain_community.document_loaders import TextLoader
from backend.perform_investigation_steps import PerformInvestigation
from langchain_community.vectorstores import Weaviate, Chroma
from langchain_community.llms import Cohere
from dotenv import load_dotenv
from langchain_community.chat_models import ChatCohere
import cohere
from datetime import datetime
from pathlib import Path
import json, re, os

from backend.remediation_model import RemediationModel

import weaviate

from langchain_community.utilities.requests import JsonRequestsWrapper
from langchain_community.utilities.requests import GenericRequestsWrapper
from langchain_community.tools.requests.tool import RequestsGetTool
from langchain.agents import load_tools, AgentType
from langchain.agents import initialize_agent
from langchain_community.llms import Cohere

from langchain.prompts import PromptTemplate
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains import LLMChain

from constant import *

from backend.datastore import Datastore

load_dotenv()
COHERE_API_KEY = os.getenv("COHERE_API_KEY")
ABUSEDB_API_KEY = os.getenv("ABUSEDB_API_KEY")
CONFLUENCE_CONNECTOR_ID = os.getenv("CONFLUENCE_CONNECTOR_ID")
NGROK_URL = os.getenv("NGROK_URL")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MXTOOL_API_KEY = os.getenv("MXTOOL_API_KEY")
WEAVIATE_URL = os.getenv("WEAVIATE_URL")
WEAVIATE_API_KEY = os.getenv("WEAVIATE_API_KEY")
FINE_TUNED_MODEL_ID_PHISHING = os.getenv("FINE_TUNED_MODEL_ID_PHISHING")
FINE_TUNED_MODEL_ID_ALERT = os.getenv("FINE_TUNED_MODEL_ID_ALERT")


def get_cohere_obj():
    return Cohere(model="command", temperature=0, cohere_api_key=COHERE_API_KEY)


def get_agent():
    api_key = "44c3bc088c249e97814ec0da3153a66f2f5a36a6a970f4fbf47a0c5c2c478d12a01fa6ad51e44d49"

    # Headers including the API key
    url = "https://api.abuseipdb.com/api/v2/check"

    querystring = {"ipAddress": "118.25.6.39", "maxAgeInDays": "90"}

    headers = {"Accept": "application/json", "Key": api_key}
    generic_requests_wrapper = GenericRequestsWrapper(headers=headers)

    # Initialize the TextRequestsWrapper with the headers
    json_requests_wrapper = JsonRequestsWrapper(headers=headers)

    # Initialize the RequestsGetTool with the customized TextRequestsWrapper
    requests_get_tool = RequestsGetTool(requests_wrapper=generic_requests_wrapper)
    tools = [requests_get_tool]
    llm = get_cohere_obj()
    agent = initialize_agent(
        tools,
        llm,
        agent="zero-shot-react-description",
        verbose=True,
        handle_parsing_errors=True,
    )
    return agent


def setup_vector_store(doc):
    client = weaviate.Client(
        url=WEAVIATE_URL, auth_client_secret=weaviate.auth.AuthApiKey(WEAVIATE_API_KEY)
    )

    raw_documents = TextLoader(doc).load()
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    documents = text_splitter.split_documents(raw_documents)
    cohere_embeddings = CohereEmbeddings(cohere_api_key=COHERE_API_KEY)
    db = Weaviate.from_documents(
        documents, cohere_embeddings, client=client, by_text=False
    )
    return db


def setup_vector_store_chroma(doc):
    raw_documents = TextLoader(doc).load()
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    documents = text_splitter.split_documents(raw_documents)
    cohere_embeddings = CohereEmbeddings(cohere_api_key=COHERE_API_KEY)
    db = Chroma.from_documents(documents, cohere_embeddings)

    return db


def setup_vector_store_weaviate(index_name):
    client = weaviate.Client(
        url=WEAVIATE_URL
    )  # , auth_client_secret=weaviate.auth.AuthApiKey(WEAVIATE_API_KEY))
    cohere_embeddings = CohereEmbeddings(cohere_api_key=COHERE_API_KEY)
    return Weaviate(
        client=client,
        embedding=cohere_embeddings,
        index_name=index_name,
        text_key="text",
        by_text=False,
    )


def get_relevant_documents(db, user_query):
    # final_user_query = "find all processes related to {}".format(user_query)
    # final_user_query = user_query
    input_docs = db.as_retriever().get_relevant_documents(user_query)
    print(f"_sahil input doc - {input_docs}")
    cohere_chat_model = ChatCohere(cohere_api_key=COHERE_API_KEY, model="command")
    rag = CohereRagRetriever(llm=cohere_chat_model)
    docs = rag.get_relevant_documents(
        user_query,
        source_documents=input_docs,
    )
    answers = []
    citations = []
    # Print the documents
    for doc in docs[:-1]:
        print(doc.metadata)
        print("\n\n" + doc.page_content)
        print("\n\n" + "-" * 30 + "\n\n")
        answers.append(doc.page_content)
        citations.append(doc.metadata)

    return answers[0], citations


def generate_summary(classification, evaluation_result):
    client = cohere.Client(COHERE_API_KEY)

    response = client.generate(
        model="command",
        prompt="Given the classification of an ip abuse alert as {0} with the following reasons {1} Provide a short 3 sentence summary of why its {0}".format(
            classification, evaluation_result
        ),
        max_tokens=300,
        temperature=0,
        k=0,
        stop_sequences=[],
        return_likelihoods="NONE",
    )

    return response.generations[0].text


def update_dataset(
    case_id,
    status,
    evaluation_steps,
    evaluation_summary,
    evaluation_enriched,
    remediation_steps,
    classification,
    activity_details,
):
    ds = Datastore()
    df = ds.get_dataset()
    # Update multiple columns for rows matching the condition
    df.loc[
        df["CaseId"] == case_id,
        [
            "Status",
            "Assessment",
            "EvaluationSteps",
            "EvaluationSummary",
            "EvaluationEnriched",
            "RemediationDetails",
            "ActivityDetails",
        ],
    ] = [
        status,
        classification,
        evaluation_steps,
        evaluation_summary,
        evaluation_enriched,
        remediation_steps,
        activity_details,
    ]
    ds.save_dataset(df)


def fetch_remediation_steps(alert_json, investigation_steps, alert_type, modelId):
    remModel = RemediationModel(cohere.Client(COHERE_API_KEY), modelId)
    if alert_type == ALERT:
        remData = remModel.inference_for_threat_usecase(alert_json, investigation_steps)
    else:
        remData = remModel.inference_for_phishing_usecase(
            alert_json, investigation_steps
        )
    return parse_rem_data(remData)


def parse_rem_data(remData):
    if "```" in remData:
        remData = remData.replace("```", "")
        remData = remData.replace("json", "")

    json_match = re.search(r"json\n(\{.*?\})\n", remData, re.DOTALL)
    data = None
    try:
        data = json.loads(remData)
    except Exception as e:
        if json_match:
            json_string = json_match.group(1)  # Extract the JSON string
            data = json.loads(json_string)  # Parse the JSON string

    return data


def reformat_string(input_string):
    # Split the input string into parts based on ': ' and ', ' separators
    parts = input_string.split(": ")
    header = parts[0] + ":\n"  # Add newline character after the header
    details = parts[1].split(", ")

    # Define a dictionary to hold the key-value pairs from the details
    detail_dict = {}
    for detail in details:
        key, value = detail.split(" - ")
        detail_dict[key.strip()] = value.strip()

    # Specify the order and capitalization of the keys for the final string
    final_order = [
        "Current Firewall Status",
        "Malicious",
        "ORG Name",
        "Threat Confidence",
    ]
    final_details = []
    for key in final_order:
        if key in detail_dict:
            # Special case for capitalization
            if key == "Current Firewall Status":
                value = detail_dict[
                    key
                ].capitalize()  # Capitalize the status (e.g., "Blocked")
            else:
                value = detail_dict[key]
            final_details.append(f"{key} - {value}")

    # Join the final parts together to form the final string
    final_string = header + ", ".join(final_details)

    return final_string


def perform_investigations(alert_json, investigation_steps, alert_type):
    llm = get_cohere_obj()
    perInvestigation = PerformInvestigation(llm)
    enrichedInvestigation = perInvestigation.process_alert_json_and_run_workflow(
        alert_json, investigation_steps
    )
    # print(f"alertData - {alert_json} \n\n investiinga - {investigation_steps} \n enriched- {enrichedInvestigation}")
    if alert_type == ALERT:
        return reformat_string(enrichedInvestigation)
    else:
        return enrichedInvestigation


def handle_alert_data(data, logging):
    caseid = data["CaseId"]
    alertData = data["Alert"]
    print(f"_sahil pringting caseid - {caseid}")
    sop_d = "backend/data/sop.txt"

    threat_ip_address = data["Alert"]["threat_match_value"]
    alert_category = "Threat Activity Detected"
    alert_enrich_data = {
        "ip_address": threat_ip_address,
        "alert_category": alert_category,
    }
    alert_enrich_data = json.dumps(alert_enrich_data)
    # index_name = "Sopindex"

    logging.append(f"{datetime.now()}:   Connecting to weaviate vector store")
    # db = setup_vector_store_weaviate(index_name)
    db = setup_vector_store_chroma(sop_d)
    logging.append(f"{datetime.now()}:   Connected to weaviate vector store")
    user_query = f"Give the steps to investigate a {alert_category.lower()}."
    logging.append(f"{datetime.now()}:   Fetching RAG data")
    docs, citations = get_relevant_documents(db, user_query=user_query)
    # doc_string = "\n".join(docs)

    # generate evaluation steps
    logging.append(f"{datetime.now()}:   Finished fetching RAG data")
    logging.append(f"{datetime.now()}:   Generating Evaluation Steps")
    enriched_eval_doc = perform_investigations(alert_enrich_data, docs, "Alert")
    logging.append(f"{datetime.now()}:   Finished generating Evaluation Steps")

    logging.append(f"{datetime.now()}:   Generating Assessment for Incident")
    logging.append(f"{datetime.now()}:   Generating Remediation actions for Incident")
    remData = fetch_remediation_steps(
        alertData, enriched_eval_doc, "Alert", FINE_TUNED_MODEL_ID_ALERT
    )
    for key in remData.keys():
        if "threat" in key.lower():
            resolution = remData[key]
        else:
            remSteps = remData[key]
    logging.append(f"{datetime.now()}:   Finished generating Assessment for Incident")
    logging.append(
        f"{datetime.now()}:   Finished generating Remediation actions for Incident"
    )

    # generate summary
    logging.append(f"{datetime.now()}:   Generating Evaluation Summary")
    eval_summary = generate_summary(enriched_eval_doc, resolution)
    logging.append(f"{datetime.now()}:   Completed Evaluation Summary generation")
    print(logging)

    # update all data
    status = REVIEW
    classification = resolution
    evaluation_steps = docs
    evaluation_enriched = enriched_eval_doc
    evaluation_summary = eval_summary
    remediation_steps = remSteps
    print(logging)
    update_dataset(
        caseid,
        status,
        evaluation_steps,
        evaluation_summary,
        evaluation_enriched,
        remediation_steps,
        classification,
        logging,
    )


def handle_phishing_data(data, logging):
    caseid = data["CaseId"]
    alertData = data["Alert"]
    print(f"_sahil pringting caseid - {caseid}")

    threat_ip_address = data["Alert"]["ip_address"]
    from_value = data["Alert"]["from"]
    domain = from_value.split("@")[1]
    alert_category = "Phishing Activity Detected"
    alert_enrich_data = {
        "ip_address": threat_ip_address,
        "alert_category": alert_category,
        "domain": domain,
    }
    alert_enrich_data = json.dumps(alert_enrich_data)
    index_name = "Sopindex"

    # alert_data = get_splunk_alert_data()
    logging.append(f"{datetime.now()}:   Connecting to weaviate vector store")
    db = setup_vector_store_weaviate(index_name)
    logging.append(f"{datetime.now()}:   Connected to weaviate vector store")
    user_query = f"Give the steps to investigate a {alert_category.lower()}."
    logging.append(f"{datetime.now()}:   Fetching RAG data")
    docs, citations = get_relevant_documents(db, user_query=user_query)
    print(f"_sahil docs - {docs}")
    # doc_string = "\n".join(docs)

    # generate evaluation steps
    logging.append(f"{datetime.now()}:   Finished fetching RAG data")
    logging.append(f"{datetime.now()}:   Generating Evaluation Steps")
    enriched_eval_doc = perform_investigations(alert_enrich_data, docs, "Phishing")
    logging.append(f"{datetime.now()}:   Finished generating Evaluation Steps")

    logging.append(f"{datetime.now()}:   Generating Assessment for Incident")
    logging.append(f"{datetime.now()}:   Generating Remediation actions for Incident")
    remData = fetch_remediation_steps(
        alertData, enriched_eval_doc, "Phishing", FINE_TUNED_MODEL_ID_PHISHING
    )
    for key in remData.keys():
        if "classification" in key.lower():
            resolution = remData[key]
            if resolution == "Legitimate":
                resolution = "Benign"
            if resolution == "Phishing":
                resolution = "True Positive"
        else:
            remSteps = remData[key]

    logging.append(f"{datetime.now()}:   Finished generating Assessment for Incident")
    logging.append(
        f"{datetime.now()}:   Finished generating Remediation actions for Incident"
    )

    # generate summary
    logging.append(f"{datetime.now()}:   Generating Evaluation Summary")
    eval_summary = generate_summary(enriched_eval_doc, resolution)
    logging.append(f"{datetime.now()}:   Completed Evaluation Summary generation")
    print(logging)

    # update all data
    status = REVIEW
    classification = resolution
    evaluation_steps = docs
    evaluation_enriched = enriched_eval_doc
    evaluation_summary = eval_summary
    remediation_steps = remSteps
    print(logging)
    update_dataset(
        caseid,
        status,
        evaluation_steps,
        evaluation_summary,
        evaluation_enriched,
        remediation_steps,
        classification,
        logging,
    )


def start(data, data_type):
    # ENTRY POINT
    logging = []

    if data_type == ALERT:
        handle_alert_data(data, logging)
    if data_type == PHISHING:
        handle_phishing_data(data, logging)
