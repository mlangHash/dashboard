from pathlib import Path
from parsers import prepare_all
import json

dataset = prepare_all(Path("files"))
# print(dataset)
with open("dataset.json", "w") as file:
    json.dump(dataset, file, indent=4)
print("Tables found:", list(dataset.keys()))
print()

for table_name, records in dataset.items():
    print("=== " + table_name + " ===")
    print("Total records:", len(records))
    if records:
        print("Fields:", list(records[0].keys()))
        print("First record:", records[0])
    print()
