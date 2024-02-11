"""
Langchain related codes
"""


class AlertSOP:
    def __init__(self) -> None:
        pass

    def get_ratings(self):
        # call langchain model with query data
        # and fetch V.T ip address and T.R score
        data = {"VT": "www.virustotal.com", "TR": "34"}
        return data


class RunRemediation:
    def __init__(self) -> None:
        self.remediation_steps = ""
        self.jira_ticket = ""
        pass

    def run(self):
        # call langchain model, and ask to run the
        # steps and return the success/failure status
        status = "Success"
        return status
