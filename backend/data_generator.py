"""
For handling execution for splunk related queries
"""

from typing import Any, List
from faker import Faker
import random


class FakeEmailGen:

    def __init__(self) -> None:
        self.fake = Faker()

    def generate_phishing_email(self):
        email_headers = [
            "Urgent: Verify Your Account Now!",
            "Action Required: Unusual Sign-in Activity",
            "Security Notice: Account Compromised",
            "Warning: Your Account Has Been Breached",
            "Alert: Unauthorized Access Detected",
        ]
        email_body = (
            self.fake.text(max_nb_chars=200)
            + "\n\nPlease click the link below to secure your account.\nhttp://phishing-link.com"
        )
        return {
            "alert_title": "Potential Phishing Email",
            "from_email_address": self.fake.free_email(),
            "to_email_address": self.fake.free_email(),
            "email_header": random.choice(email_headers),
            "email_body": email_body,
        }

    def generate_legitimate_email(self):
        email_subjects = [
            "Meeting Reminder",
            "Project Update",
            "Invoice Attached",
            "Weekly Newsletter",
            "Happy Birthday!",
        ]
        email_body = self.fake.text(max_nb_chars=200)
        return {
            "alert_title": "Potential Phishing Email",
            "from_email_address": self.fake.company_email(),
            "to_email_address": self.fake.free_email(),
            "email_header": random.choice(email_subjects),
            "email_body": email_body,
        }


class SplunkAlerts:

    def __init__(self) -> None:
        pass

    def fetch_data(self) -> List:
        alerts = []
        sample_alert = {
            "ticket_id": "1",
            "threat_group": "iblocklist_spyware",
            "threat_description": "Addresses that are commonly associated with known spyware sites",
            "threat_collection_key": "iblocklist_spyware|216.239.34.21",
        }
        alerts.append(sample_alert)
        return alerts


class PhishingData:
    def __init__(self) -> None:
        pass

    def fetch_data(self):
        phishings = []
        sample_phishing = FakeEmailGen().generate_phishing_email()
        phishings.append(sample_phishing)
        return phishings
