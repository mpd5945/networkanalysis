import pandas as pd

data_set = pd.read_csv(r"file_path")

# Uncomment below to get rid of NaN rows from data
# data_set.dropna(inplace=True)

print(data_set)
