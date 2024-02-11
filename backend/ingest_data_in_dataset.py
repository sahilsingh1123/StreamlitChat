import json
from datastore import Datastore


def get_json_data():
    json_file_path = "data/live_asset_data.json"
    with open(json_file_path, "r", encoding="utf-8") as file:
        json_data = json.load(file)
        return json_data


json_data = get_json_data()
rows = []
ds = Datastore()
dataset = ds.get_dataset()
row = ds.get_dataset_row_dict_structure()
for j_data in json_data:
    # j_data = json.dumps(j_data)
    caseId = j_data["Ticket ID"]
    alertDesc = j_data.get("threat_description", j_data.get("email_header"))
    row["CaseId"] = caseId
    row["AlertDescription"] = alertDesc
    row["Alert"] = j_data
    row["Status"] = "Pending"
    ds.update_dataset(row)
final_dataset = ds.get_dataset()
ds.save_dataset()

# if __name__ == "__main__":
#     ds = Datastore()
#     data = ds.get_dataset()
#     print(len(data))
#     print(data.tail(10))
