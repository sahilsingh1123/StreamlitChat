class RemediationModel:
    threat_json_prompt = "{}\n Extract information(Threat, Recommended Follow-up Steps) and convert them into JSON format from the following statement. keep 'Recommened Follow-up Steps' value as it is in json. Only needs JSON object in output."
    # phishing_json_prompt = "{}\n Extract key details(Classification, Reason) and convert them into JSON format from the following statement. Classification possible values are 'Phishing' and 'Legitimate'. Only provide JSON object in output."
    phishing_json_prompt = "{}\n Extract key details(Classification, Reason) and convert them into JSON format from the following statement. In JSON 'Reason' and 'Classification' must be there .Classification possible values are 'Phishing' and 'Legitimate'.Only provide valid JSON object in output."

    def __init__(self, cohere, modelID):
        self.co = cohere
        self.model_id = modelID

    def inference_for_threat_usecase(self, alert_json, investigation_steps):
        prompt = self.create_threat_inference_prompt(alert_json, investigation_steps)

        response = self.co.generate(
            model=self.model_id,  # Model ID
            prompt=prompt,
            max_tokens=500,
            temperature=0,
            k=0,
            stop_sequences=[],
            return_likelihoods="NONE",
        )
        response = "{}".format(response.generations[0].text)

        response = self.co.generate(
            model=self.model_id,  # Model ID
            prompt=self.threat_json_prompt.format(response),
            max_tokens=500,
            temperature=0,
            k=0,
            stop_sequences=[],
            return_likelihoods="NONE",
        )
        json_format = "{}".format(response.generations[0].text)
        return json_format

    def inference_for_phishing_usecase(self, alert_json, investigation_steps):
        prompt = self.create_phishing_inference_prompt(alert_json, investigation_steps)
        response = self.co.generate(
            model=self.model_id,  # Model ID
            prompt=prompt,
            max_tokens=500,
            temperature=0.1,
            k=0,
            stop_sequences=[],
            return_likelihoods="NONE",
        )
        response = "{}".format(response.generations[0].text)

        response = self.co.generate(
            model=self.model_id,  # Model ID
            prompt=self.phishing_json_prompt.format(response),
            max_tokens=500,
            temperature=0,
            k=0,
            stop_sequences=[],
            return_likelihoods="NONE",
        )
        json_format = "{}".format(response.generations[0].text)

        return json_format

    def create_threat_inference_prompt(self, alert_json, Investigation_steps):
        skip_cols = ["Ticket ID", "threat_source_digest", "threat_source_type"]
        prompt = "Threat fields:\n"
        for key, value in alert_json.items():
            if key in skip_cols:
                continue
            prompt += f"{key}:{value}, "
        prompt += "."
        prompt += f"\n{Investigation_steps}"
        return prompt

    def create_phishing_inference_prompt(self, alert_json, investigation_steps):
        prompt = (
            f"Analyze the following email and determine if it is phishing or not:\n\n"
            f"from: {alert_json['from']}\n"
            f"to: {alert_json['to']}\n"
            f"Subject: {alert_json['email_header']}\n"
            f"Body: {alert_json['email_body']}\n"
            "Investigation Steps Performed with their Results:\n"
        )
        prompt += f"\n{investigation_steps}"
        return prompt
