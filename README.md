# Cohere Hackathon

Welcome to the repository for the Cohere Hackathon project focused on Alert Detection and Remediation using Large Language Models (LLM), specifically leveraging the Retrieval-Augmented Generation (RAG) approach. This project aims to enhance cybersecurity measures by automatically detecting and responding to various threats through the integration of advanced AI models and cybersecurity APIs.

## Project Overview

This project integrates several technologies and platforms to create a sophisticated alert detection and remediation system. By utilizing Cohere's powerful language models, along with various cybersecurity APIs such as AbuseDB, VirusTotal, and MXToolBox, the system is capable of identifying potential threats and providing immediate solutions to mitigate risks.

## Getting Started

To run this project locally, you'll need to set up a few things first. Follow the instructions below to get started.

### Prerequisites

Ensure you have the following installed:
- Python 3.10 or higher
- pip for installing Python packages
- pip install -r requirements.txt

### Configuration
1. Create a .env file in the root directory of the project.
2. Add the following variables to the .env file, replacing "API_KEY" and "connector-id" with your actual API keys and connector IDs obtained from the respective services:

- COHERE_API_KEY="API_KEY"
- ABUSEDB_API_KEY="API_KEY"
- CONFLUENCE_CONNECTOR_ID="connector-id for confluence connector"
- VIRUSTOTAL_API_KEY="API_KEY"
- MXTOOL_API_KEY="API_KEY"
- WEAVIATE_URL="https://timepass-random.weaviate.network"
- WEAVIATE_API_KEY="API_KEY"
- CHAT_CONNECTOR_ID="connector-id for night's watch chat"
- FINE_TUNED_MODEL_ID_ALERT="MODEL-ID FOR FINETUNE"
- FINE_TUNED_MODEL_ID_PHISHING="MODEL-ID FOR FINETUNE"`