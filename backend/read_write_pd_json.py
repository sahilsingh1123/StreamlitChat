from datastore import Datastore
import pandas as pd

ds = Datastore()
df = ds.get_dataset()
# df.to_json('temp_data.json', orient='records')

df2 = pd.read_json("prefilled_data.json", orient="records")
ds.save_dataset(df2)
