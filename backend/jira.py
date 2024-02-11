"""
Code related with all jira respective actions
"""


class JiraBase:
    def __init__(self) -> None:
        pass

    def create_jira_ticket(self):
        return "success"

    def update_jira_description(self):
        return True

    def update_jira_comment(self):
        return True

    def delete_jira_ticket(self):
        pass
