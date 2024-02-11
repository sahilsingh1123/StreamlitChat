"""
contains all LLM model logics
"""

from langchain_community.retrievers import CohereRagRetriever
from langchain_community.embeddings import CohereEmbeddings
from langchain_community.chat_models import ChatCohere
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import Chroma
from langchain_community.llms import Cohere
from langchain_community.chat_models import ChatCohere

from langchain.prompts import PromptTemplate
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains import LLMChain

import cohere


class RagData:
    def __init__(self) -> None:
        pass

    def get_rag_data(self):
        return "rag_data"


class LLMModelBase:
    def __init__(self) -> None:
        pass

    def retrieve_rag_doc(self):
        pass

    def get_model_obj(self):
        pass

    def get_prompt_template(self):
        pass

    def get_user_query(self):
        pass

    def run_llm_model(self):
        pass


class CohereLLM(LLMModelBase):
    def __init__(self) -> None:
        self.user_query = ""
        self.api_key = "123"
        self.fine_tune_model = "command"

    def retrieve_rag_doc(self):
        input_docs = "rag_data"
        return input_docs

    def get_model_obj(self):
        cohere_chat_model = ChatCohere(
            cohere_api_key=self.api_key, model=self.fine_tune_model
        )
        return CohereRagRetriever(llm=cohere_chat_model)

    def get_prompt_template(self):
        return "prompt_template"

    def run_llm_model(self):
        return super().run_llm_model()
