from parsers.NVD_parser import load_records
from collections import defaultdict

filepath = "files/classified_patches1.json"

records = load_records(filepath)
print(type(records))
layer_sublayer = defaultdict(list)
for rec in records:
    layer = rec.get("layer", "")
    sublayer = rec.get("sublayer", "")
    layer_sublayer[layer].append(sublayer)

print(layer_sublayer)