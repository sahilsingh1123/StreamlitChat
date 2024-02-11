from pathlib import Path
import pandas as pd
from constant import *


class Datastore:
    def __init__(self) -> None:
        self.data_store_file_name = DATASTORE_FILENAME
        self.file_dir = DATASTORE_DIR
        self.storage_location = self.file_dir + self.data_store_file_name
        self.dataset = None
        script_dir = Path(__file__).parent
        self.data_file_path = script_dir / self.storage_location

    def get_dataset(self):
        if self.dataset is None:
            self.get_pd_dataframe()
        return self.dataset

    def set_dataset(self, dataset):
        self.dataset = dataset

    def get_pd_dataframe(self):
        # create an empty dataframe or load
        # the existing one
        if self.data_file_path.is_file():
            dataframe = pd.read_pickle(self.data_file_path)
            print(len(dataframe))
        else:
            # create empty dataframe with columns
            dataframe = self.get_empty_dataset()
        self.set_dataset(dataframe)

    def get_empty_dataset(self):
        columns = self.get_all_columns_name
        return pd.DataFrame(columns=columns)

    def save_dataset(self, dataframe=None):
        if dataframe is None:
            dataframe = self.get_dataset()
        dataframe.to_pickle(self.data_file_path)

    def set_status_pending(self):
        df = self.get_dataset()
        df.loc[df[STATUS] == REVIEW, STATUS] = PENDING
        self.save_dataset(df)

    def update_dataset(self, row, dataset=None):
        if not dataset:
            dataset = self.get_dataset()
        new_row_df = pd.DataFrame([row])
        updated_dataset = pd.concat([dataset, new_row_df], ignore_index=True)
        self.set_dataset(updated_dataset)

    def get_dataset_row_dict_structure(self):
        return {key: None for key in self.get_all_columns_name}

    @property
    def get_alert_columns_name(self):
        columns = [
            CASEID,
            ALERT_DESCRIPTION,
            ASSESSMENT,
            STATUS,
        ]
        return columns

    @property
    def get_all_columns_name(self):
        columns = [
            CASEID,
            ALERT,
            ALERT_DESCRIPTION,
            ASSESSMENT,
            STATUS,
            EVALUATION_STEPS,
            EVALUATION_SUMMARY,
            EVALUATION_ENRICHED,
            ASSESSMENT_DETAILS,
            REMEDIATION_DETAILS,
            ACTIVITY_DETAILS,
        ]
        return columns
