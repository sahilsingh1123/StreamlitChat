"""
Start point for backend server side execution
"""

from datastore import Datastore
from constant import alert_type


class SOCAutomate:
    def __init__(self) -> None:
        pass

    def start(self):
        # initialise dataset
        # fetch alert/phishing data
        #   - if alert, langchain add more details
        # call LLM model
        pass

    def initialize_dataset(self):
        # load or create a pandas dataframe
        datastore = Datastore()
        dataframe = datastore.get_pd_dataframe()
        return dataframe

    def fetch_data_gen(self, data_type=alert_type):
        # fetch data for alert/phishing
        if data_type == alert_type:
            return self.fetch_alert_data(), data_type
        else:
            return self.fetch_phishing_data(), data_type

    def fetch_alert_data(self):
        # will fetch data from splunk alert
        # if alert data, run Langchain model to
        # gather more details with the returned data
        pass

    def fetch_phishing_data(self):
        # will fetch data from mock API
        pass
