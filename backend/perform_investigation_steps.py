from langchain.tools import BaseTool
import requests
import random
from typing import Union, Dict
import os
import re
import json
from dotenv import load_dotenv
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langchain.agents import initialize_agent

load_dotenv()
ABUSEDB_API_KEY = os.getenv("ABUSEDB_API_KEY")
CONFLUENCE_CONNECTOR_ID = os.getenv("CONFLUENCE_CONNECTOR_ID")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MXTOOL_API_KEY = os.getenv("MXTOOL_API_KEY")


class VirusTotalDetailsFetcher(BaseTool):
    name = "VirusTotal Details Fetcher"
    description = "Use this tool to get relevant details for a given IP address from VirusTotal, including malicious status."

    def _run(self, ip_address: str) -> Union[Dict[str, Union[int, str]], None]:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"Accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()  # Check for HTTP errors
            data = response.json()
            malicious = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", None)
            )
            firewall_status = random.choice(["ALLOWED", "BLOCKED"])

            return {
                "ip_address": ip_address,
                "malicious_score": malicious,
                "firewall_status": firewall_status,
            }
        except Exception as e:
            print(f"Failed to fetch details for IP {ip_address} from VirusTotal: {e}")
            return None

    def _arun(self, ip_address: str):
        raise NotImplementedError("This tool does not support async operations.")


class MXLookupTool(BaseTool):
    name = "MX Lookup Tool"
    description = (
        "Use this tool to get MX record details for a given domain from MXToolBox."
    )

    def _run(self, domain: str) -> Union[Dict[str, str], None]:
        endpoint = f"https://api.mxtoolbox.com/api/v1/Lookup/mx?argument={domain}"
        headers = {"Authorization": MXTOOL_API_KEY}
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()  # Check for HTTP errors
            data = response.json()
            # Initialize response values
            dmarc_record = "Not Found"
            dns_record = "Not Found"
            mx_record = "Found" if data.get("Information") else "Not Found"

            # Check 'Passed' key for DMARC and DNS records
            for item in data.get("Passed", []):
                if "DMARC Record Published" in item.get("Name", ""):
                    dmarc_record = "Found"
                if "DNS Record Published" in item.get("Name", ""):
                    dns_record = "Found"

            return {
                "DMARC Record": dmarc_record,
                "DNS Record": dns_record,
                "MX Record": mx_record,
            }
        except Exception as e:
            print(f"Failed to fetch MX records for domain {domain} from MXToolBox: {e}")
            return None

    def _arun(self, domain: str):
        raise NotImplementedError("This tool does not support async operations.")


class AbuseDBTool(BaseTool):
    name = "AbuseIPDB Details Fetcher"
    description = "Use this tool to get relevant details for a given IP address from AbuseDB, including threat confidence level and organization information."

    def _run(self, ip_address: str) -> Union[Dict[str, Union[int, str]], None]:
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": ABUSEDB_API_KEY}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90}
        try:
            response = requests.get(endpoint, headers=headers, params=params)
            # for http erros
            response.raise_for_status()
            data = response.json()
            threat_confidence = data.get("data", {}).get("abuseConfidenceScore", None)
            organization_name = data.get("data", {}).get("isp", "Not Found")
            return {
                "ip_address": ip_address,
                "threat_confidence_level": threat_confidence,
                "organization_name": organization_name,
            }
        except Exception as e:
            print(f"Failed to fetch threat confidence level for IP {ip_address}: {e}")
            return None

    def _arun(self, ip_address: str, max_age_in_days: int = 90):
        raise NotImplementedError("This tool does not support async")


class PerformInvestigation:

    def __init__(self, llm):
        self.llm = llm
        conversational_memory = ConversationBufferWindowMemory(
            memory_key="chat_history", k=0, return_messages=True
        )

        tools = [VirusTotalDetailsFetcher(), AbuseDBTool(), MXLookupTool()]

        # initialize agent with tools
        self.agent = initialize_agent(
            agent="chat-conversational-react-description",
            tools=tools,
            llm=llm,
            verbose=True,
            max_iterations=3,
            early_stopping_method="generate",
            memory=conversational_memory,
        )

    def split_investigation_steps(self, investigation_steps):
        steps = re.split(r"\n\d+\.\s", investigation_steps.strip())
        print(f"_sahil steps - {steps}")

        # The first split includes text before the first marker which we don't need
        # so we skip the first element (which is before "1.") if it doesn't contain actual step content
        if steps and steps[0].startswith("Below are"):
            steps = steps[1:]

        return steps

    def process_alert_json_and_run_workflow(self, alert_json, investigation_steps):
        """Process an alert JSON object to extract relevant information and run the appropriate workflow."""
        alert_data = json.loads(alert_json)
        ip_address = alert_data.get("ip_address", "")
        alert_category = alert_data.get("alert_category", "")
        domain = alert_data.get("domain", None)

        if domain:
            return self.run_workflow_phishing(domain, ip_address, investigation_steps)
        else:
            return self.run_workflow_threat_detection(ip_address, investigation_steps)

    def run_workflow_threat_detection(self, ip_address, investigation_steps):
        steps = self.split_investigation_steps(investigation_steps)
        ip_reputation_prompt = steps[0].format(ip_address=ip_address)
        confidence_level_prompt = steps[1].format(ip_address=ip_address)

        prompts = [ip_reputation_prompt, confidence_level_prompt]

        responses = []
        for prompt in prompts:
            print(f"Running prompt: {prompt}")
            response = self.agent.run(prompt)
            # response = f"Response : {response}"
            responses.append(response)

        investigation_summary = f'Investigation Steps Performed with their Results: \n{", ".join(responses)}'
        return investigation_summary

    def run_workflow_phishing(self, domain, ip_address, investigation_steps):
        steps = self.split_investigation_steps(investigation_steps)
        # Format the steps with the actual domain and IP address
        dmarc_dns_mx_prompt = steps[0].format(domain=domain)
        malicious_score_prompt = steps[1].format(ip_address=ip_address)

        # prompts array dynamically based on the investigation steps
        prompts = [dmarc_dns_mx_prompt, malicious_score_prompt]

        responses = []
        for prompt in prompts:
            print(f"Running prompt: {prompt}")
            response = self.agent.run(prompt)
            # response = f"Response : {response}"
            responses.append(response)

        investigation_summary = "\n".join(responses)
        return investigation_summary
